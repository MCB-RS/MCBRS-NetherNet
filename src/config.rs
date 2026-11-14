//! Configuration types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::identity::client::{ClientIdentity, TokenVerifier};

/// Bedrock protocol number used by [`ServerInfo::default`].
pub const DEFAULT_PROTOCOL: u32 = 2225;

/// Largest SCTP message this host advertises and can send (same value as the
/// Minecraft client's `a=max-message-size`).
pub const MAX_SCTP_MESSAGE_SIZE: usize = 262_144;

/// A STUN or TURN server used while gathering ICE candidates (guide §2, §7).
///
/// The Minecraft client configures none, and the guide recommends against
/// them for HTTP signaling: with full ICE every server must answer before the
/// SDP can be sent, which adds latency. They are still useful on a host behind
/// a NAT (STUN discovers its `srflx` candidate) or when a relay is required
/// (TURN `relay` candidates).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IceServer {
    /// URLs of the server: `stun:host[:port]`, `turn:host[:port][?transport=udp|tcp]`
    /// or `turns:host[:port]`.
    pub urls: Vec<String>,
    /// TURN username (required for `turn:` / `turns:` URLs).
    pub username: Option<String>,
    /// TURN credential (required for `turn:` / `turns:` URLs).
    pub credential: Option<String>,
}

impl IceServer {
    /// A STUN server, e.g. `IceServer::stun("stun:stun.example.com:3478")`.
    pub fn stun(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
            ..Self::default()
        }
    }

    /// A TURN server with its long-term credentials.
    pub fn turn(
        url: impl Into<String>,
        username: impl Into<String>,
        credential: impl Into<String>,
    ) -> Self {
        Self {
            urls: vec![url.into()],
            username: Some(username.into()),
            credential: Some(credential.into()),
        }
    }

    fn has_stun_url(&self) -> bool {
        self.urls
            .iter()
            .any(|u| u.to_ascii_lowercase().starts_with("stun:"))
    }

    /// Checks the URL schemes and that TURN servers carry credentials.
    pub fn validate(&self) -> crate::Result<()> {
        use crate::Error::Config;
        if self.urls.is_empty() {
            return Err(Config("an ICE server needs at least one URL".into()));
        }
        for url in &self.urls {
            let lower = url.to_ascii_lowercase();
            let is_turn = lower.starts_with("turn:") || lower.starts_with("turns:");
            if !is_turn && !lower.starts_with("stun:") {
                return Err(Config(format!(
                    "ICE server URL `{url}` must start with stun:, turn: or turns:"
                )));
            }
            if lower.contains('\n') || lower.contains('\r') {
                return Err(Config("ICE server URL contains a line break".into()));
            }
            if is_turn && (self.username.is_none() || self.credential.is_none()) {
                return Err(Config(format!(
                    "TURN server `{url}` requires a username and a credential"
                )));
            }
        }
        Ok(())
    }
}

/// Body of `GET /v1/join` (guide §4, "Capability Check and Server Info").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    /// Human-readable server name.
    pub name: String,
    /// Bedrock protocol version supported by the server.
    pub protocol: u32,
    /// Bedrock game version string (e.g. `"1.26.50"`).
    pub version: String,
    /// Name of the loaded level (world).
    pub level: String,
    /// Current player count.
    pub players: u32,
    /// Maximum number of players.
    pub max_players: u32,
    /// Default game mode (0 = Survival, 1 = Creative, 2 = Adventure).
    pub game_type: u8,
}

impl Default for ServerInfo {
    /// Placeholder values; the application is expected to overwrite them with
    /// the protocol and version it really implements. The protocol default is
    /// the one announced by a real Minecraft client in its first packet
    /// (`RequestNetworkSettings`, November 2026); the version string is the
    /// guide's example.
    fn default() -> Self {
        Self {
            name: "NetherNet Server".into(),
            protocol: DEFAULT_PROTOCOL,
            version: "1.26.50".into(),
            level: "Bedrock level".into(),
            players: 0,
            max_players: 10,
            game_type: 0,
        }
    }
}

/// What to do with the client `a=identity` assertion of incoming offers (§5.1).
#[derive(Clone, Default)]
pub enum ClientAuth {
    /// Do not validate anything (open / offline servers, local testing).
    #[default]
    Disabled,
    /// Validate the assertion when present, accept offers without one.
    Optional(Arc<dyn TokenVerifier>),
    /// Reject offers without a valid assertion.
    Required(Arc<dyn TokenVerifier>),
}

impl fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Disabled => "Disabled",
            Self::Optional(_) => "Optional(..)",
            Self::Required(_) => "Required(..)",
        })
    }
}

/// A join attempt, handed to the [`Authorizer`] before any WebRTC resource is allocated.
#[derive(Debug, Clone)]
pub struct JoinRequest {
    /// The client's NetworkID (opaque string from the URL path).
    pub network_id: String,
    /// Address of the HTTP client that performed the signaling request.
    pub signaling_addr: Option<SocketAddr>,
    /// The validated player identity, when client authentication is enabled.
    pub identity: Option<ClientIdentity>,
}

/// Server policy hook: allowlists, bans, player limits, ...
#[async_trait::async_trait]
pub trait Authorizer: Send + Sync + 'static {
    /// Returns `Err(reason)` to refuse the player (HTTP 403).
    async fn authorize(&self, request: &JoinRequest) -> Result<(), String>;
}

/// Configuration of a NetherNet host.
#[derive(Clone)]
pub struct NetherNetConfig {
    /// Client identity validation policy.
    pub client_auth: ClientAuth,
    /// Optional policy hook called for every join attempt.
    pub authorizer: Option<Arc<dyn Authorizer>>,
    /// Local UDP addresses used for WebRTC (one socket set per connection).
    /// `0.0.0.0:0` = every interface, ephemeral port.
    pub udp_bind_addrs: Vec<SocketAddr>,
    /// Public IPs to advertise as server-reflexive (`srflx`) candidates when the
    /// host is behind a 1:1 NAT (guide §7, step 11 note). Cannot be combined
    /// with STUN servers in [`Self::ice_servers`].
    pub public_ips: Vec<IpAddr>,
    /// STUN / TURN servers used to gather candidates (empty by default, like
    /// the Minecraft client).
    pub ice_servers: Vec<IceServer>,
    /// Reverse proxies (e.g. an HTTPS terminator) allowed to report the real
    /// client address through `Forwarded`, `X-Forwarded-For` or `X-Real-IP`.
    /// These headers are ignored for every other peer, so a direct client
    /// cannot spoof its address.
    pub trusted_proxies: Vec<IpAddr>,
    /// When the offer only contains non-routable candidates (client behind a
    /// NAT) and the signaling request came from a routable address, add a
    /// candidate built from that address and the port of the client's `host`
    /// candidate. Helps hole punching when the client's NAT preserves ports.
    pub infer_client_candidates: bool,
    /// Advertise loopback candidates (only useful for local testing).
    pub include_loopback_candidates: bool,
    /// Upper bound for one SCTP message we send (header included). The value
    /// actually used is `min(this, remote a=max-message-size)`.
    pub max_outgoing_message_size: usize,
    /// Maximum size of a reassembled incoming message.
    pub max_incoming_message_size: usize,
    /// Maximum number of received bytes buffered per connection and not yet
    /// read with [`crate::NetherNetConnection::recv`]. When the budget is
    /// exhausted, the reliable channel applies back-pressure (the peer is slowed
    /// down by SCTP flow control) and unreliable messages are dropped.
    pub max_buffered_incoming_bytes: usize,
    /// Per-channel limit of bytes handed to `send()` but not yet acknowledged by
    /// the peer. Once reached, `send()` waits; this bounds the memory a slow or
    /// hostile client can make the server hold.
    pub send_buffer_limit: usize,
    /// Maximum time spent gathering ICE candidates before answering.
    pub ice_gathering_timeout: Duration,
    /// Maximum time between the answer and the data channels being open.
    pub connect_timeout: Duration,
    /// Maximum number of connections being negotiated at the same time
    /// (excess offers get HTTP 503).
    pub max_pending_connections: usize,
    /// Number of established connections waiting for `accept()`.
    pub accept_backlog: usize,
}

impl Default for NetherNetConfig {
    fn default() -> Self {
        Self {
            client_auth: ClientAuth::Disabled,
            authorizer: None,
            udp_bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)],
            public_ips: Vec::new(),
            ice_servers: Vec::new(),
            trusted_proxies: Vec::new(),
            infer_client_candidates: false,
            include_loopback_candidates: false,
            max_outgoing_message_size: 65_536,
            max_incoming_message_size: 16 * 1024 * 1024,
            max_buffered_incoming_bytes: 32 * 1024 * 1024,
            send_buffer_limit: 4 * 1024 * 1024,
            ice_gathering_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(30),
            max_pending_connections: 64,
            accept_backlog: 128,
        }
    }
}

impl fmt::Debug for NetherNetConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetherNetConfig")
            .field("client_auth", &self.client_auth)
            .field("authorizer", &self.authorizer.as_ref().map(|_| ".."))
            .field("udp_bind_addrs", &self.udp_bind_addrs)
            .field("public_ips", &self.public_ips)
            .field("ice_servers", &self.ice_servers.len())
            .field("trusted_proxies", &self.trusted_proxies)
            .field("infer_client_candidates", &self.infer_client_candidates)
            .field(
                "include_loopback_candidates",
                &self.include_loopback_candidates,
            )
            .field("max_outgoing_message_size", &self.max_outgoing_message_size)
            .field("max_incoming_message_size", &self.max_incoming_message_size)
            .field(
                "max_buffered_incoming_bytes",
                &self.max_buffered_incoming_bytes,
            )
            .field("send_buffer_limit", &self.send_buffer_limit)
            .field("ice_gathering_timeout", &self.ice_gathering_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("max_pending_connections", &self.max_pending_connections)
            .field("accept_backlog", &self.accept_backlog)
            .finish()
    }
}

impl NetherNetConfig {
    pub(crate) fn validate(&self) -> crate::Result<()> {
        use crate::Error::Config;
        if self.udp_bind_addrs.is_empty() {
            return Err(Config("udp_bind_addrs must not be empty".into()));
        }
        for server in &self.ice_servers {
            server.validate()?;
        }
        if !self.public_ips.is_empty() && self.ice_servers.iter().any(IceServer::has_stun_url) {
            return Err(Config(
                "public_ips (static srflx candidates) cannot be combined with STUN servers".into(),
            ));
        }
        if !(2..=MAX_SCTP_MESSAGE_SIZE).contains(&self.max_outgoing_message_size) {
            return Err(Config(format!(
                "max_outgoing_message_size must be within 2..={MAX_SCTP_MESSAGE_SIZE}"
            )));
        }
        if self.max_incoming_message_size == 0 {
            return Err(Config("max_incoming_message_size must be non-zero".into()));
        }
        // The budget is enforced with a semaphore whose permits are counted in u32.
        let budget_max = (u32::MAX as usize).min(tokio::sync::Semaphore::MAX_PERMITS);
        if self.max_buffered_incoming_bytes == 0 || self.max_buffered_incoming_bytes > budget_max {
            return Err(Config(format!(
                "max_buffered_incoming_bytes must be within 1..={budget_max}"
            )));
        }
        if self.send_buffer_limit == 0 {
            return Err(Config(
                "send_buffer_limit must be non-zero (use usize::MAX for unbounded)".into(),
            ));
        }
        if self.ice_gathering_timeout.is_zero() || self.connect_timeout.is_zero() {
            return Err(Config(
                "ice_gathering_timeout and connect_timeout must be non-zero".into(),
            ));
        }
        if self.max_pending_connections == 0 || self.accept_backlog == 0 {
            return Err(Config(
                "max_pending_connections and accept_backlog must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_info_json_matches_guide() {
        // The guide's example body.
        let json = serde_json::to_value(ServerInfo {
            name: "Dedicated Server".into(),
            protocol: 2177,
            max_players: 10,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "name": "Dedicated Server",
                "protocol": 2177,
                "version": "1.26.50",
                "level": "Bedrock level",
                "players": 0,
                "maxPlayers": 10,
                "gameType": 0
            })
        );
    }

    #[test]
    fn default_config_is_valid() {
        NetherNetConfig::default().validate().unwrap();
    }

    #[test]
    fn invalid_configs_are_rejected() {
        let bad = [
            NetherNetConfig {
                max_outgoing_message_size: MAX_SCTP_MESSAGE_SIZE + 1,
                ..Default::default()
            },
            NetherNetConfig {
                max_incoming_message_size: 0,
                ..Default::default()
            },
            NetherNetConfig {
                max_buffered_incoming_bytes: 0,
                ..Default::default()
            },
            NetherNetConfig {
                send_buffer_limit: 0,
                ..Default::default()
            },
            NetherNetConfig {
                connect_timeout: Duration::ZERO,
                ..Default::default()
            },
        ];
        for config in bad {
            assert!(config.validate().is_err(), "{config:?}");
        }
    }

    #[test]
    fn ice_server_validation() {
        assert!(
            IceServer::stun("stun:stun.example.com:3478")
                .validate()
                .is_ok()
        );
        assert!(
            IceServer::turn("turns:turn.example.com", "u", "p")
                .validate()
                .is_ok()
        );
        assert!(IceServer::stun("turn:turn.example.com").validate().is_err());
        assert!(IceServer::stun("http://example.com").validate().is_err());
        assert!(IceServer::default().validate().is_err());

        let conflict = NetherNetConfig {
            public_ips: vec!["203.0.113.5".parse().unwrap()],
            ice_servers: vec![IceServer::stun("stun:stun.example.com")],
            ..Default::default()
        };
        assert!(conflict.validate().is_err());
        let turn_only = NetherNetConfig {
            public_ips: vec!["203.0.113.5".parse().unwrap()],
            ice_servers: vec![IceServer::turn("turn:turn.example.com", "u", "p")],
            ..Default::default()
        };
        assert!(turn_only.validate().is_ok());
    }
}
