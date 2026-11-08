//! Error type shared by the whole crate.

use std::fmt;

/// Convenient result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Every error the NetherNet layer can produce.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The SDP document is malformed or misses a required attribute.
    #[error("invalid SDP: {0}")]
    Sdp(String),

    /// An `a=identity` assertion (client or server) failed to parse or verify.
    #[error("identity assertion rejected: {0}")]
    Identity(String),

    /// A player was rejected by the server policy (allowlist, ban, full server, ...).
    #[error("connection refused: {0}")]
    Unauthorized(String),

    /// A key could not be generated, parsed or serialized.
    #[error("key error: {0}")]
    Key(String),

    /// The peer violated the NetherNet data framing protocol (§6.1).
    #[error("framing error: {0}")]
    Framing(String),

    /// A message is too large to be sent or reassembled.
    #[error("message too large: {size} bytes (limit {limit} bytes)")]
    MessageTooLarge {
        /// Size of the offending message.
        size: usize,
        /// Maximum accepted size.
        limit: usize,
    },

    /// The configuration is inconsistent.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// An operation did not complete in time.
    #[error("timed out while {0}")]
    Timeout(&'static str),

    /// The connection is closed.
    #[error("connection closed")]
    Closed,

    /// Error coming from the WebRTC stack.
    #[error("WebRTC error: {0}")]
    WebRtc(#[from] webrtc::error::Error),

    /// I/O error (sockets, key files, ...).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub(crate) fn identity(msg: impl fmt::Display) -> Self {
        Self::Identity(msg.to_string())
    }

    pub(crate) fn sdp(msg: impl fmt::Display) -> Self {
        Self::Sdp(msg.to_string())
    }
}
