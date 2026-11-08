//! NetherNet data framing (guide §6.1).
//!
//! Every SCTP message sent on either data channel starts with a 1-byte header:
//!
//! * `0`     – complete message, or the *last* fragment of a fragmented message;
//! * `N > 0` – a fragment followed by `N` more fragments (countdown).
//!
//! Fragmentation is only allowed on the `ReliableDataChannel`. On the
//! `UnreliableDataChannel` the header is always `0`.

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

/// Size of the NetherNet header that prefixes every SCTP message.
pub const HEADER_LEN: usize = 1;

/// The header is a single byte, so a message is at most 256 fragments long
/// (first header = 255, last header = 0).
pub const MAX_FRAGMENTS: usize = u8::MAX as usize + 1;

/// Largest payload that can be sent with a given SCTP max message size.
pub fn max_payload_len(max_message_size: usize) -> usize {
    max_message_size.saturating_sub(HEADER_LEN) * MAX_FRAGMENTS
}

/// Splits `payload` into NetherNet fragments that each fit in `max_message_size`
/// bytes (header included). Used on the reliable channel.
///
/// A payload that fits in one SCTP message produces a single `[0x00, payload..]` frame.
pub fn fragment(payload: &[u8], max_message_size: usize) -> Result<Vec<Bytes>> {
    if max_message_size <= HEADER_LEN {
        return Err(Error::Config(format!(
            "max message size must be greater than {HEADER_LEN} byte(s), got {max_message_size}"
        )));
    }
    let chunk_len = max_message_size - HEADER_LEN;
    let count = payload.len().div_ceil(chunk_len).max(1);
    if count > MAX_FRAGMENTS {
        return Err(Error::MessageTooLarge {
            size: payload.len(),
            limit: max_payload_len(max_message_size),
        });
    }

    let mut frames = Vec::with_capacity(count);
    if payload.is_empty() {
        frames.push(Bytes::from_static(&[0]));
        return Ok(frames);
    }
    for (index, chunk) in payload.chunks(chunk_len).enumerate() {
        let remaining = (count - 1 - index) as u8;
        let mut frame = BytesMut::with_capacity(HEADER_LEN + chunk.len());
        frame.put_u8(remaining);
        frame.put_slice(chunk);
        frames.push(frame.freeze());
    }
    Ok(frames)
}

/// Builds a single unfragmented frame (`[0x00, payload..]`). Used on the
/// unreliable channel, where messages that do not fit are dropped by the sender.
pub fn frame_single(payload: &[u8], max_message_size: usize) -> Result<Bytes> {
    let size = payload.len() + HEADER_LEN;
    if size > max_message_size {
        return Err(Error::MessageTooLarge {
            size: payload.len(),
            limit: max_message_size.saturating_sub(HEADER_LEN),
        });
    }
    let mut frame = BytesMut::with_capacity(size);
    frame.put_u8(0);
    frame.put_slice(payload);
    Ok(frame.freeze())
}

/// Parses a frame received on the unreliable channel, returning its payload.
///
/// The header must be `0`; anything else is a protocol violation and the
/// message must be dropped.
pub fn parse_single(frame: &[u8]) -> Result<&[u8]> {
    match frame.split_first() {
        None => Err(Error::Framing("empty message (missing header byte)".into())),
        Some((0, payload)) => Ok(payload),
        Some((header, _)) => Err(Error::Framing(format!(
            "fragmented message (header {header}) on a channel that does not support fragmentation"
        ))),
    }
}

/// Reassembles fragmented messages received on the reliable channel.
#[derive(Debug)]
pub struct Reassembler {
    buffer: BytesMut,
    /// Header value expected for the next fragment, `None` when idle.
    expected: Option<u8>,
    max_message_len: usize,
}

impl Reassembler {
    /// Creates a reassembler that refuses messages larger than `max_message_len`
    /// bytes once reassembled (protection against memory exhaustion).
    pub fn new(max_message_len: usize) -> Self {
        Self {
            buffer: BytesMut::new(),
            expected: None,
            max_message_len,
        }
    }

    /// Returns `true` when a fragmented message is partially received.
    pub fn is_partial(&self) -> bool {
        self.expected.is_some()
    }

    /// Discards any partially received message.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.expected = None;
    }

    /// Feeds one SCTP message. Returns `Some(payload)` once a full message is available.
    ///
    /// On error the reassembler is reset; the caller should treat the error as a
    /// protocol violation (the reliable channel is ordered, so a broken countdown
    /// can only come from a misbehaving peer).
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Bytes>> {
        let Some((&header, data)) = frame.split_first() else {
            self.reset();
            return Err(Error::Framing("empty message (missing header byte)".into()));
        };

        if let Some(expected) = self.expected
            && header != expected
        {
            self.reset();
            return Err(Error::Framing(format!(
                "unexpected fragment header {header}, expected {expected}"
            )));
        }

        let new_len = self.buffer.len() + data.len();
        if new_len > self.max_message_len {
            self.reset();
            return Err(Error::MessageTooLarge {
                size: new_len,
                limit: self.max_message_len,
            });
        }

        if header == 0 && self.expected.is_none() {
            // Fast path: unfragmented message, no copy into the buffer.
            return Ok(Some(Bytes::copy_from_slice(data)));
        }

        self.buffer.extend_from_slice(data);
        if header == 0 {
            self.expected = None;
            Ok(Some(self.buffer.split().freeze()))
        } else {
            self.expected = Some(header - 1);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_message_is_not_fragmented() {
        let frames = fragment(b"hello", 100).unwrap();
        assert_eq!(frames, vec![Bytes::from_static(b"\x00hello")]);
    }

    #[test]
    fn empty_message_is_a_lone_header() {
        let frames = fragment(b"", 100).unwrap();
        assert_eq!(frames, vec![Bytes::from_static(b"\x00")]);
        let mut r = Reassembler::new(1024);
        assert_eq!(r.push(&frames[0]).unwrap().unwrap(), Bytes::new());
    }

    #[test]
    fn fragments_count_down() {
        // chunk size = 4 - 1 = 3 bytes -> "abcdefgh" = 3 fragments
        let frames = fragment(b"abcdefgh", 4).unwrap();
        assert_eq!(
            frames,
            vec![
                Bytes::from_static(b"\x02abc"),
                Bytes::from_static(b"\x01def"),
                Bytes::from_static(b"\x00gh"),
            ]
        );
    }

    #[test]
    fn exact_multiple_of_chunk_size() {
        let frames = fragment(b"abcdef", 4).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0][0], 1);
        assert_eq!(frames[1][0], 0);
    }

    #[test]
    fn roundtrip_large_message() {
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let frames = fragment(&payload, 1200).unwrap();
        assert!(frames.len() > 1);
        let mut r = Reassembler::new(1 << 20);
        let mut out = None;
        for (i, f) in frames.iter().enumerate() {
            let res = r.push(f).unwrap();
            if i + 1 < frames.len() {
                assert!(res.is_none());
                assert!(r.is_partial());
            } else {
                out = res;
            }
        }
        assert_eq!(out.unwrap(), payload);
        assert!(!r.is_partial());
    }

    #[test]
    fn too_many_fragments_is_rejected() {
        let payload = vec![0u8; 2 * MAX_FRAGMENTS + 1];
        let err = fragment(&payload, 3).unwrap_err();
        assert!(matches!(err, Error::MessageTooLarge { .. }));
        // Exactly 256 fragments is fine.
        let payload = vec![0u8; 2 * MAX_FRAGMENTS];
        let frames = fragment(&payload, 3).unwrap();
        assert_eq!(frames.len(), MAX_FRAGMENTS);
        assert_eq!(frames[0][0], 255);
    }

    #[test]
    fn broken_countdown_is_rejected() {
        let mut r = Reassembler::new(1024);
        assert!(r.push(b"\x02abc").unwrap().is_none());
        assert!(r.push(b"\x00def").is_err());
        assert!(!r.is_partial());
        // The reassembler recovers for the next message.
        assert_eq!(
            r.push(b"\x00ok").unwrap().unwrap(),
            Bytes::from_static(b"ok")
        );
    }

    #[test]
    fn reassembly_size_limit() {
        let mut r = Reassembler::new(5);
        assert!(r.push(b"\x01abc").unwrap().is_none());
        assert!(matches!(
            r.push(b"\x00def"),
            Err(Error::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn empty_frame_is_rejected() {
        let mut r = Reassembler::new(5);
        assert!(r.push(b"").is_err());
        assert!(parse_single(b"").is_err());
    }

    #[test]
    fn unreliable_frames() {
        assert_eq!(
            frame_single(b"mv", 10).unwrap(),
            Bytes::from_static(b"\x00mv")
        );
        assert!(frame_single(&[0u8; 10], 10).is_err());
        assert_eq!(parse_single(b"\x00mv").unwrap(), b"mv");
        assert!(parse_single(b"\x01mv").is_err());
    }
}
