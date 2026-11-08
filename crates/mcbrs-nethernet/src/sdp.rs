//! Minimal, line-based SDP helpers used by NetherNet signaling.
//!
//! The WebRTC stack does the real SDP negotiation; these helpers only deal with
//! the parts NetherNet adds on top of it: the `a=identity` attribute (§5) and the
//! `a=fingerprint` lines it signs, plus `a=max-message-size` for fragmentation.

use serde::{Deserialize, Serialize};

const FINGERPRINT: &str = "a=fingerprint:";
const IDENTITY: &str = "a=identity:";
const MAX_MESSAGE_SIZE: &str = "a=max-message-size:";

/// Default SCTP max message size when the remote does not advertise one (RFC 8841 §6.1).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 65_536;

/// A DTLS certificate fingerprint (`a=fingerprint:<algorithm> <digest>`).
///
/// Field order matters: it is the lexicographic order required by the
/// canonical JSON used for the detached JWS payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Hash algorithm, e.g. `sha-256`.
    pub algorithm: String,
    /// Colon separated hexadecimal digest.
    pub digest: String,
}

fn lines(sdp: &str) -> impl Iterator<Item = &str> {
    sdp.lines().map(|l| l.trim_end_matches('\r'))
}

fn line_ending(sdp: &str) -> &'static str {
    if sdp.contains("\r\n") { "\r\n" } else { "\n" }
}

/// Returns every `a=fingerprint` attribute of the SDP, in order of appearance
/// (session level and media level).
pub fn fingerprints(sdp: &str) -> Vec<Fingerprint> {
    lines(sdp)
        .filter_map(|l| l.strip_prefix(FINGERPRINT))
        .filter_map(|value| {
            let mut parts = value.split_whitespace();
            let algorithm = parts.next()?;
            let digest = parts.next()?;
            Some(Fingerprint {
                algorithm: algorithm.to_owned(),
                digest: digest.to_owned(),
            })
        })
        .collect()
}

/// Returns the value of the first `a=identity` attribute, if any.
pub fn identity(sdp: &str) -> Option<&str> {
    lines(sdp)
        .find_map(|l| l.strip_prefix(IDENTITY))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Removes every `a=identity` line. WebRTC stacks reject unknown attributes, so
/// this must be applied before `setRemoteDescription()`.
pub fn strip_identity(sdp: &str) -> String {
    let eol = line_ending(sdp);
    let mut out = String::with_capacity(sdp.len());
    for line in lines(sdp).filter(|l| !l.starts_with(IDENTITY)) {
        out.push_str(line);
        out.push_str(eol);
    }
    out
}

/// Inserts a session-level `a=identity:<value>` line, after the session-level
/// `a=fingerprint` lines and before the first `m=` line (any existing
/// `a=identity` line is replaced).
pub fn insert_identity(sdp: &str, value: &str) -> String {
    let eol = line_ending(sdp);
    let stripped = strip_identity(sdp);
    let all: Vec<&str> = lines(&stripped).collect();
    let first_media = all
        .iter()
        .position(|l| l.starts_with("m="))
        .unwrap_or(all.len());
    let insert_at = all[..first_media]
        .iter()
        .rposition(|l| l.starts_with(FINGERPRINT))
        .map(|i| i + 1)
        .unwrap_or(first_media);

    let mut out = String::with_capacity(stripped.len() + value.len() + 16);
    for (i, line) in all.iter().enumerate() {
        if i == insert_at {
            out.push_str(IDENTITY);
            out.push_str(value);
            out.push_str(eol);
        }
        out.push_str(line);
        out.push_str(eol);
    }
    if insert_at == all.len() {
        out.push_str(IDENTITY);
        out.push_str(value);
        out.push_str(eol);
    }
    out
}

/// Returns the `a=max-message-size` advertised by the SDP, if any.
/// `0` means "unlimited" per RFC 8841 and is returned as `usize::MAX`.
pub fn max_message_size(sdp: &str) -> Option<usize> {
    lines(sdp)
        .find_map(|l| l.strip_prefix(MAX_MESSAGE_SIZE))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .map(|v| if v == 0 { usize::MAX } else { v })
}

/// Basic sanity check performed on offers before handing them to WebRTC.
pub fn validate_offer(sdp: &str) -> Result<(), String> {
    let mut l = lines(sdp);
    if l.next() != Some("v=0") {
        return Err("SDP must start with `v=0`".into());
    }
    if !lines(sdp).any(|l| l.starts_with("m=application") && l.contains("webrtc-datachannel")) {
        return Err("SDP has no `m=application ... webrtc-datachannel` section".into());
    }
    if fingerprints(sdp).is_empty() {
        return Err("SDP has no `a=fingerprint` attribute".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\n\
o=- 123456789 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=fingerprint:sha-256 AA:BB:CC\r\n\
a=identity:eyJpZHAiOnt9fQ==\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=fingerprint:sha-256 DD:EE:FF\r\n\
a=max-message-size:262144\r\n\
a=candidate:1 1 udp 2130706431 192.168.1.100 12345 typ host\r\n";

    #[test]
    fn reads_fingerprints() {
        assert_eq!(
            fingerprints(OFFER),
            vec![
                Fingerprint {
                    algorithm: "sha-256".into(),
                    digest: "AA:BB:CC".into()
                },
                Fingerprint {
                    algorithm: "sha-256".into(),
                    digest: "DD:EE:FF".into()
                },
            ]
        );
    }

    #[test]
    fn reads_and_strips_identity() {
        assert_eq!(identity(OFFER), Some("eyJpZHAiOnt9fQ=="));
        let stripped = strip_identity(OFFER);
        assert!(!stripped.contains("a=identity"));
        assert_eq!(identity(&stripped), None);
        assert!(stripped.ends_with("typ host\r\n"));
        assert_eq!(
            stripped.len(),
            OFFER.len() - "a=identity:eyJpZHAiOnt9fQ==\r\n".len()
        );
    }

    #[test]
    fn inserts_identity_after_session_fingerprint() {
        let stripped = strip_identity(OFFER);
        let with = insert_identity(&stripped, "XYZ");
        assert_eq!(with, OFFER.replace("eyJpZHAiOnt9fQ==", "XYZ"));
    }

    #[test]
    fn inserts_identity_before_media_without_session_fingerprint() {
        let sdp = "v=0\ns=-\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 AA\n";
        let with = insert_identity(sdp, "ID");
        assert_eq!(
            with,
            "v=0\ns=-\na=identity:ID\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 AA\n"
        );
    }

    #[test]
    fn max_message_size_is_parsed() {
        assert_eq!(max_message_size(OFFER), Some(262_144));
        assert_eq!(max_message_size("a=max-message-size:0"), Some(usize::MAX));
        assert_eq!(max_message_size("v=0"), None);
    }

    #[test]
    fn validates_offers() {
        assert!(validate_offer(OFFER).is_ok());
        assert!(validate_offer("hello").is_err());
        assert!(validate_offer("v=0\r\nm=audio 9 RTP/AVP 0\r\n").is_err());
    }
}
