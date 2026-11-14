//! # mcbrs-nethernet
//!
//! **MCBRS-NetherNet**: Minecraft Bedrock's NetherNet transport, written in Rust.
//!
//! NetherNet is Minecraft's peer-to-peer transport built on WebRTC data
//! channels. This crate implements both sides of the "NetherNet HTTP
//! Signaling" protocol: the host ([`NetherNetListener`], [`NetherNetHost`])
//! and the client ([`NetherNetClient`]).
//!
//! | Guide section | Module |
//! |---|---|
//! | §4 HTTP signaling (`GET /v1/join`, `POST /v1/join/{networkId}`), trusted proxies | [`signaling`] |
//! | §5.1 client assertion: validation (host) and signing (client) | [`identity::client`], [`identity::sign_sdp`] |
//! | §5.2 server assertion (operator key) and TOFU | [`identity::server`], [`client`] |
//! | §6 PeerConnection configuration, §7 connection flow, STUN / TURN | [`host`], [`client`] |
//! | §6.1 data framing / fragmentation | [`framing`] |
//! | SDP helpers (`a=identity`, `a=fingerprint`, candidates) | [`sdp`] |
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

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod config;
pub mod conn;
pub mod error;
pub mod framing;
pub mod host;
pub mod identity;
mod peer;
pub mod sdp;
pub mod signaling;

pub use client::{
    AcceptAnyServer, ClientCredentials, NetherNetClient, NetherNetClientConfig, ServerTrust,
    TrustOnFirstUse, TrustRequest,
};
pub use config::{Authorizer, ClientAuth, IceServer, JoinRequest, NetherNetConfig, ServerInfo};
pub use conn::{Channel, Message, NetherNetConnection, RELIABLE_LABEL, UNRELIABLE_LABEL};
pub use error::{Error, Result};
pub use host::{Incoming, NetherNetHost, NetherNetListener};
pub use identity::client::{ClientIdentity, InsecureTokenDecoder, JwkSetVerifier, TokenVerifier};
pub use identity::server::ServerIdentity;
pub use identity::{IdentityAssertion, VerifiedServerIdentity, verify_server_answer};
pub use signaling::{OfferRequest, SignalingError, SignalingHandler};
