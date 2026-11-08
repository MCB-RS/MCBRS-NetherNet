//! # mcbrs-nethernet
//!
//! NetherNet transport layer for **MCBRS**, a Minecraft Bedrock server
//! framework written in Rust.
//!
//! NetherNet is Minecraft's peer-to-peer transport built on WebRTC data
//! channels. This crate implements the *server* side of the
//! "NetherNet HTTP Signaling" protocol:
//!
//! | Guide section | Module |
//! |---|---|
//! | §4 HTTP signaling (`GET /v1/join`, `POST /v1/join/{networkId}`) | [`signaling`] |
//! | §5.1 client assertion validation | [`identity::client`] |
//! | §5.2 server assertion (operator key, TOFU) | [`identity::server`] |
//! | §6 PeerConnection configuration, §7 connection flow | [`host`] |
//! | §6.1 data framing / fragmentation | [`framing`] |
//! | SDP helpers (`a=identity`, `a=fingerprint`) | [`sdp`] |
//!
//! The game protocol itself (packets, worlds, entities, ...) is out of scope:
//! a [`NetherNetConnection`] simply delivers and accepts raw payloads on the
//! reliable / unreliable channels.
//!
//! ## Quick start
//!
//! ```no_run
//! use mcbrs_nethernet::{NetherNetConfig, NetherNetListener, ServerIdentity, ServerInfo};
//!
//! #[tokio::main]
//! async fn main() -> mcbrs_nethernet::Result<()> {
//!     let identity = ServerIdentity::load_or_generate("nethernet_server_key.pem")?;
//!     let listener = NetherNetListener::bind(
//!         "0.0.0.0:8080",
//!         NetherNetConfig::default(),
//!         identity,
//!         ServerInfo::default(),
//!     )
//!     .await?;
//!
//!     while let Some(conn) = listener.accept().await {
//!         tokio::spawn(async move {
//!             while let Some(msg) = conn.recv().await {
//!                 println!("{} sent {} bytes", conn.network_id(), msg.payload.len());
//!             }
//!         });
//!     }
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]

pub mod config;
pub mod conn;
pub mod error;
pub mod framing;
pub mod host;
pub mod identity;
pub mod sdp;
pub mod signaling;

pub use config::{Authorizer, ClientAuth, JoinRequest, NetherNetConfig, ServerInfo};
pub use conn::{Channel, Message, NetherNetConnection, RELIABLE_LABEL, UNRELIABLE_LABEL};
pub use error::{Error, Result};
pub use host::{Incoming, NetherNetHost, NetherNetListener};
pub use identity::client::{ClientIdentity, InsecureTokenDecoder, JwkSetVerifier, TokenVerifier};
pub use identity::server::ServerIdentity;
pub use identity::{IdentityAssertion, VerifiedServerIdentity, verify_server_answer};
pub use signaling::{OfferRequest, SignalingError, SignalingHandler};
