//! Configuration types.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::identity::client::{ClientIdentity, TokenVerifier};

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
    /// Values taken from the guide's example; the application is expected to
    /// overwrite them with the real protocol/version it implements.
    fn default() -> Self {
        Self {
            name: "NetherNet Server".into(),
            protocol: 2177,
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
    /// host is behind a 1:1 NAT (guide §7, step 11 note).
    pub public_ips: Vec<IpAddr>,
    /// Advertise loopback candidates (only useful for local testing).
    pub include_loopback_candidates: bool,
    /// Upper bound for one SCTP message we send (header included). The value
    /// actually used is `min(this, remote a=max-message-size)`.
    pub max_outgoing_message_size: usize,
    /// Maximum size of a reassembled incoming message.
    pub max_incoming_message_size: usize,
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
            include_loopback_candidates: false,
            max_outgoing_message_size: 65_536,
            max_incoming_message_size: 16 * 1024 * 1024,
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
            .field(
                "include_loopback_candidates",
                &self.include_loopback_candidates,
            )
            .field("max_outgoing_message_size", &self.max_outgoing_message_size)
            .field("max_incoming_message_size", &self.max_incoming_message_size)
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
        if self.max_outgoing_message_size < 2 {
            return Err(Config(
                "max_outgoing_message_size must be at least 2".into(),
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
        let json = serde_json::to_value(ServerInfo {
            name: "Dedicated Server".into(),
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
}
