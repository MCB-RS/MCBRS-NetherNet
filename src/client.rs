//! NetherNet client: the connecting side of the HTTP signaling flow.
//!
//! [`NetherNetClient`] follows the client flow of the guide:
//!
//! 1. `GET /v1/join` – capability check and server info (§4);
//! 2. a PeerConnection with the client configuration (§6): UDP only,
//!    `max-bundle`, full ICE, the `ReliableDataChannel` (ordered, reliable) and
//!    `UnreliableDataChannel` (unordered, `maxRetransmits = 0`) channels;
//! 3. after ICE gathering, an optional `a=identity` assertion (§5.1):
//!    a `GameServerToken` plus the `a=fingerprint` lines signed with the key
//!    matching its `cpk` claim;
//! 4. `POST /v1/join/{networkId}`, verification of the server assertion of the
//!    answer (§5.2) and of the trust anchor (TLS for HTTPS, a [`ServerTrust`]
//!    policy such as [`TrustOnFirstUse`] for plaintext HTTP);
//! 5. the cleaned answer is applied and the connection is returned once the
//!    data channels are open (§7).

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use reqwest::{StatusCode, Url, header};
use webrtc::data_channel::RTCDataChannelInit;
use webrtc::peer_connection::{PeerConnection, RTCSessionDescription};

use crate::config::{IceServer, MAX_SCTP_MESSAGE_SIZE, ServerInfo};
use crate::conn::{
    ChannelOrigin, NetherNetConnection, RELIABLE_LABEL, Shared, UNRELIABLE_LABEL, pump_data_channel,
};
use crate::error::{Error, Result};
use crate::identity::jose::SigningKey;
use crate::identity::{VerifiedServerIdentity, sign_sdp, verify_server_answer};
use crate::peer::{NewPeer, PeerSettings, new_peer};
use crate::sdp;
use crate::signaling::validate_network_id;

/// Maximum accepted size of an SDP answer.
const MAX_ANSWER_SIZE: usize = 256 * 1024;
/// Maximum accepted size of a `GET /v1/join` body.
const MAX_SERVER_INFO_SIZE: usize = 64 * 1024;
/// Per-connection queue length of received messages not yet read.
const MESSAGE_QUEUE_LEN: usize = 1024;

/// The player identity sent in the offer (§5.1).
#[derive(Clone)]
pub struct ClientCredentials {
    /// `idp.domain`: the auth service that issued the token.
    pub domain: String,
    /// The `GameServerToken` JWT issued by the Minecraft auth service.
    pub token: String,
    /// The private key matching the token's `cpk` claim; it signs the DTLS
    /// fingerprints of every offer.
    pub key: SigningKey,
}

impl ClientCredentials {
    /// Bundles a token and the key matching its `cpk` claim.
    pub fn new(domain: impl Into<String>, token: impl Into<String>, key: SigningKey) -> Self {
        Self {
            domain: domain.into(),
            token: token.into(),
            key,
        }
    }
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("domain", &self.domain)
            .field("token", &"<redacted>")
            .field("key", &self.key)
            .finish()
    }
}

/// What a [`ServerTrust`] policy is asked to decide about.
#[derive(Debug)]
pub struct TrustRequest<'a> {
    /// The signaling URL the client connected to.
    pub server_url: &'a str,
    /// `true` when signaling was reached over HTTPS: TLS already authenticated
    /// the server, and the guide says not to prompt the player (§5.2).
    pub https: bool,
    /// The structurally verified server identity (operator key `cpk`, claims).
    /// `iss` and `idp.domain` are untrusted display text.
    pub identity: &'a VerifiedServerIdentity,
}

/// Trust anchor check performed after the server assertion was verified
/// (§5.2, "What the Client Does With It", step 7).
pub trait ServerTrust: Send + Sync + 'static {
    /// Returns `Err(reason)` to abort the connection.
    fn check(&self, request: &TrustRequest<'_>) -> std::result::Result<(), String>;
}

/// Accepts every server whose assertion is structurally valid. Suitable for
/// HTTPS signaling (TLS is the trust anchor) and for tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyServer;

impl ServerTrust for AcceptAnyServer {
    fn check(&self, _request: &TrustRequest<'_>) -> std::result::Result<(), String> {
        Ok(())
    }
}

type Prompt = dyn Fn(&TrustRequest<'_>) -> bool + Send + Sync;

/// Trust On First Use, as done by the Minecraft client for plaintext HTTP
/// signaling (§5.2): HTTPS servers are accepted without prompting; over HTTP
/// a known operator key is accepted silently, and an unknown one is passed to
/// `prompt` (show the key fingerprint to the player); on acceptance the key
/// is pinned.
///
/// The pins are the RFC 7638 thumbprints of `cpk`
/// ([`VerifiedServerIdentity::key_fingerprint`]); persist them with
/// [`Self::pins`] / [`Self::with_pins`].
pub struct TrustOnFirstUse {
    pins: Mutex<HashSet<String>>,
    prompt: Box<Prompt>,
}

impl TrustOnFirstUse {
    /// Creates an empty pin store; `prompt` decides about unknown keys.
    pub fn new(prompt: impl Fn(&TrustRequest<'_>) -> bool + Send + Sync + 'static) -> Self {
        Self {
            pins: Mutex::new(HashSet::new()),
            prompt: Box::new(prompt),
        }
    }

    /// Adds previously stored pins.
    pub fn with_pins(self, pins: impl IntoIterator<Item = String>) -> Self {
        self.lock().extend(pins);
        self
    }

    /// The pinned key fingerprints.
    pub fn pins(&self) -> Vec<String> {
        self.lock().iter().cloned().collect()
    }

    /// Returns `true` if `fingerprint` is pinned.
    pub fn is_pinned(&self, fingerprint: &str) -> bool {
        self.lock().contains(fingerprint)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.pins.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for TrustOnFirstUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustOnFirstUse")
            .field("pins", &self.lock().len())
            .finish_non_exhaustive()
    }
}

impl ServerTrust for TrustOnFirstUse {
    fn check(&self, request: &TrustRequest<'_>) -> std::result::Result<(), String> {
        if request.https {
            return Ok(());
        }
        let fingerprint = request.identity.key_fingerprint();
        if self.is_pinned(&fingerprint) {
            return Ok(());
        }
        // The prompt may block (UI); never call it with the lock held.
        if (self.prompt)(request) {
            self.lock().insert(fingerprint);
            Ok(())
        } else {
            Err(format!("operator key {fingerprint} was not accepted"))
        }
    }
}

/// Configuration of a [`NetherNetClient`].
#[derive(Clone)]
pub struct NetherNetClientConfig {
    /// Player identity added to offers; `None` sends no `a=identity` (only
    /// accepted by servers that do not require authentication).
    pub credentials: Option<ClientCredentials>,
    /// Trust anchor policy for the server identity (default [`AcceptAnyServer`]).
    pub server_trust: Arc<dyn ServerTrust>,
    /// STUN / TURN servers (none by default, like the Minecraft client).
    pub ice_servers: Vec<IceServer>,
    /// Local UDP addresses used for WebRTC (`0.0.0.0:0` by default).
    pub udp_bind_addrs: Vec<SocketAddr>,
    /// Advertise loopback candidates (only useful for local testing).
    pub include_loopback_candidates: bool,
    /// Upper bound for one SCTP message sent (header included); the value used
    /// is `min(this, server a=max-message-size)`.
    pub max_outgoing_message_size: usize,
    /// Maximum size of a reassembled incoming message.
    pub max_incoming_message_size: usize,
    /// Received bytes buffered and not yet read with `recv()`.
    pub max_buffered_incoming_bytes: usize,
    /// Per-channel limit of sent but unacknowledged bytes.
    pub send_buffer_limit: usize,
    /// Timeout of each HTTP request.
    pub http_timeout: Duration,
    /// Maximum time spent gathering ICE candidates before sending the offer.
    pub ice_gathering_timeout: Duration,
    /// Maximum time between the answer and the data channels being open.
    pub connect_timeout: Duration,
}

impl Default for NetherNetClientConfig {
    fn default() -> Self {
        Self {
            credentials: None,
            server_trust: Arc::new(AcceptAnyServer),
            ice_servers: Vec::new(),
            udp_bind_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)],
            include_loopback_candidates: false,
            max_outgoing_message_size: 65_536,
            max_incoming_message_size: 16 * 1024 * 1024,
            max_buffered_incoming_bytes: 32 * 1024 * 1024,
            send_buffer_limit: 4 * 1024 * 1024,
            http_timeout: Duration::from_secs(10),
            ice_gathering_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(30),
        }
    }
}

impl fmt::Debug for NetherNetClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetherNetClientConfig")
            .field("credentials", &self.credentials)
            .field("ice_servers", &self.ice_servers.len())
            .field("udp_bind_addrs", &self.udp_bind_addrs)
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
            .field("http_timeout", &self.http_timeout)
            .field("ice_gathering_timeout", &self.ice_gathering_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl NetherNetClientConfig {
    fn validate(&self) -> Result<()> {
        use Error::Config;
        if self.udp_bind_addrs.is_empty() {
            return Err(Config("udp_bind_addrs must not be empty".into()));
        }
        for server in &self.ice_servers {
            server.validate()?;
        }
        if !(2..=MAX_SCTP_MESSAGE_SIZE).contains(&self.max_outgoing_message_size) {
            return Err(Config(format!(
                "max_outgoing_message_size must be within 2..={MAX_SCTP_MESSAGE_SIZE}"
            )));
        }
        let budget_max = (u32::MAX as usize).min(tokio::sync::Semaphore::MAX_PERMITS);
        if self.max_incoming_message_size == 0
            || self.max_buffered_incoming_bytes == 0
            || self.max_buffered_incoming_bytes > budget_max
            || self.send_buffer_limit == 0
        {
            return Err(Config(
                "message sizes, buffer budget and send buffer limit must be non-zero (budget <= u32::MAX)"
                    .into(),
            ));
        }
        if self.http_timeout.is_zero()
            || self.ice_gathering_timeout.is_zero()
            || self.connect_timeout.is_zero()
        {
            return Err(Config("timeouts must be non-zero".into()));
        }
        Ok(())
    }
}

/// Closes a peer connection when dropped, unless disarmed: if the `connect`
/// future is cancelled half-way, the connection must not leak.
struct CloseOnDrop(Option<Arc<dyn PeerConnection>>);

impl CloseOnDrop {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if let Some(pc) = self.0.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                let _ = pc.close().await;
            });
        }
    }
}

/// Connects to NetherNet servers through HTTP signaling.
///
/// ```no_run
/// # async fn run() -> mcbrs_nethernet::Result<()> {
/// use mcbrs_nethernet::{NetherNetClient, NetherNetClientConfig};
///
/// let client = NetherNetClient::new(NetherNetClientConfig::default())?;
/// let info = client.server_info("https://play.example.com").await?;
/// println!("{} ({} / {})", info.name, info.players, info.max_players);
///
/// let (conn, server) = client.connect("https://play.example.com", "1234567890").await?;
/// println!("connected, operator key {}", server.key_fingerprint());
/// conn.send(b"hello").await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
pub struct NetherNetClient {
    config: NetherNetClientConfig,
    http: reqwest::Client,
}

impl NetherNetClient {
    /// Creates a client.
    pub fn new(config: NetherNetClientConfig) -> Result<Self> {
        config.validate()?;
        let http = reqwest::Client::builder()
            .timeout(config.http_timeout)
            // The signaling endpoint is the URL we were given: never follow a
            // redirect with the offer (or the player identity) to another host.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("mcbrs-nethernet/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { config, http })
    }

    /// The client configuration.
    pub fn config(&self) -> &NetherNetClientConfig {
        &self.config
    }

    /// `GET {server_url}/v1/join`: checks that the server supports NetherNet
    /// and returns its metadata (§4). A non-2xx status means "not supported".
    pub async fn server_info(&self, server_url: &str) -> Result<ServerInfo> {
        let url = endpoint(server_url, &["v1", "join"])?;
        let response = self.http.get(url).send().await?;
        let body = read_success_body(response, MAX_SERVER_INFO_SIZE).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// Connects to `server_url` as `network_id` (the client's opaque NetworkID,
    /// §9) and returns the connection plus the verified server identity.
    pub async fn connect(
        &self,
        server_url: &str,
        network_id: &str,
    ) -> Result<(NetherNetConnection, VerifiedServerIdentity)> {
        validate_network_id(network_id).map_err(Error::Config)?;
        let url = endpoint(server_url, &["v1", "join", network_id])?;
        let https = url.scheme() == "https";

        let (shared, msg_rx) = Shared::new(
            network_id.to_owned(),
            self.config.max_incoming_message_size,
            self.config.max_buffered_incoming_bytes,
            MESSAGE_QUEUE_LEN,
        );
        let settings = PeerSettings {
            udp_bind_addrs: &self.config.udp_bind_addrs,
            ice_servers: &self.config.ice_servers,
            public_ips: &[],
            include_loopback_candidates: self.config.include_loopback_candidates,
            send_buffer_limit: self.config.send_buffer_limit,
        };
        let mut peer = new_peer(&settings, shared.clone()).await?;
        let guard = CloseOnDrop(Some(peer.pc.clone()));

        match self
            .negotiate(&mut peer, &shared, url, server_url, https)
            .await
        {
            Ok((max_message_size, server)) => {
                guard.disarm();
                let pc = peer.pc;
                let conn =
                    NetherNetConnection::new(shared, pc, msg_rx, max_message_size, None, None);
                Ok((conn, server))
            }
            Err(e) => {
                shared.close();
                drop(guard); // closes the peer connection
                Err(e)
            }
        }
    }

    async fn negotiate(
        &self,
        peer: &mut NewPeer,
        shared: &Arc<Shared>,
        url: Url,
        server_url: &str,
        https: bool,
    ) -> Result<(usize, VerifiedServerIdentity)> {
        // §6: the client opens both channels before creating the offer.
        let reliable = peer.pc.create_data_channel(RELIABLE_LABEL, None).await?;
        let unreliable = peer
            .pc
            .create_data_channel(
                UNRELIABLE_LABEL,
                Some(RTCDataChannelInit {
                    ordered: false,
                    max_retransmits: Some(0),
                    ..Default::default()
                }),
            )
            .await?;
        for dc in [reliable, unreliable] {
            tokio::spawn(pump_data_channel(shared.clone(), dc, ChannelOrigin::Local));
        }

        // §2 / §7: full ICE – the offer is sent once every candidate is known.
        let offer = peer.pc.create_offer(None).await?;
        peer.pc.set_local_description(offer).await?;
        let mut offer = peer
            .local_description(self.config.ice_gathering_timeout)
            .await?;
        if let Some(credentials) = &self.config.credentials {
            offer = sign_sdp(
                &offer,
                &credentials.domain,
                credentials.token.clone(),
                &credentials.key,
            )?;
        }

        // §4: exactly one request per attempt, no retry.
        let response = self
            .http
            .post(url)
            .header(header::CONTENT_TYPE, "application/sdp")
            .body(offer)
            .send()
            .await?;
        let body = read_success_body(response, MAX_ANSWER_SIZE).await?;
        let answer = String::from_utf8(body).map_err(|_| Error::sdp("answer is not UTF-8"))?;
        sdp::validate_answer(&answer).map_err(Error::Sdp)?;

        // §5.2: a missing or malformed server assertion aborts the connection.
        let server = verify_server_answer(&answer)?;
        let request = TrustRequest {
            server_url,
            https,
            identity: &server,
        };
        self.config
            .server_trust
            .check(&request)
            .map_err(Error::UntrustedServer)?;

        peer.pc
            .set_remote_description(RTCSessionDescription::answer(sdp::strip_identity(&answer))?)
            .await?;
        let opened =
            tokio::time::timeout(self.config.connect_timeout, shared.wait_reliable_open()).await;
        match opened {
            Ok(true) => {}
            Ok(false) => return Err(Error::Closed),
            Err(_) => return Err(Error::Timeout("opening the data channels")),
        }

        let remote_max = sdp::max_message_size(&answer).unwrap_or(sdp::DEFAULT_MAX_MESSAGE_SIZE);
        Ok((
            remote_max.min(self.config.max_outgoing_message_size),
            server,
        ))
    }
}

/// Builds `{base}/{segments..}`, percent-encoding each segment.
fn endpoint(base: &str, segments: &[&str]) -> Result<Url> {
    let mut url =
        Url::parse(base).map_err(|e| Error::Config(format!("invalid server URL `{base}`: {e}")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(Error::Config(format!(
            "server URL `{base}` must use http:// or https://"
        )));
    }
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|()| Error::Config(format!("server URL `{base}` cannot have a path")))?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

/// Reads a 2xx response body (bounded); other statuses become
/// [`Error::SignalingRejected`].
async fn read_success_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let status = response.status();
    let limit = if status.is_success() { limit } else { 1024 };
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > limit {
            if status.is_success() {
                return Err(Error::Http(format!(
                    "response body larger than {limit} bytes"
                )));
            }
            body.extend_from_slice(&chunk[..limit - body.len()]);
            break;
        }
        body.extend_from_slice(&chunk);
    }
    if status.is_success() {
        return Ok(body);
    }
    Err(rejected(status, &body))
}

fn rejected(status: StatusCode, body: &[u8]) -> Error {
    let message = String::from_utf8_lossy(body)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    Error::SignalingRejected {
        status: status.as_u16(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_building() {
        let url = endpoint("http://127.0.0.1:8080", &["v1", "join", "42"]).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:8080/v1/join/42");
        let url = endpoint("https://example.com/prefix/?x=1#f", &["v1", "join"]).unwrap();
        assert_eq!(url.as_str(), "https://example.com/prefix/v1/join");
        // NetworkIDs are opaque: path separators are percent-encoded.
        let url = endpoint("http://h", &["v1", "join", "a/b?c"]).unwrap();
        assert_eq!(url.as_str(), "http://h/v1/join/a%2Fb%3Fc");
        assert!(endpoint("ftp://h", &[]).is_err());
        assert!(endpoint("not a url", &[]).is_err());
    }

    fn identity() -> VerifiedServerIdentity {
        VerifiedServerIdentity {
            domain: "example".into(),
            claims: serde_json::json!({}),
            public_key: SigningKey::generate().verifying_key(),
        }
    }

    #[test]
    fn tofu_pins_accepted_keys() {
        let prompts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = prompts.clone();
        let tofu = TrustOnFirstUse::new(move |_| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            true
        });
        let id = identity();
        let req = TrustRequest {
            server_url: "http://h",
            https: false,
            identity: &id,
        };
        tofu.check(&req).unwrap();
        tofu.check(&req).unwrap();
        assert_eq!(prompts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(tofu.is_pinned(&id.key_fingerprint()));
    }

    #[test]
    fn tofu_rejection_and_https_bypass() {
        let tofu = TrustOnFirstUse::new(|_| false);
        let id = identity();
        let http = TrustRequest {
            server_url: "http://h",
            https: false,
            identity: &id,
        };
        assert!(tofu.check(&http).is_err());
        let https = TrustRequest {
            server_url: "https://h",
            https: true,
            identity: &id,
        };
        assert!(tofu.check(&https).is_ok(), "TLS is the trust anchor");
        assert!(tofu.pins().is_empty());

        let pinned = TrustOnFirstUse::new(|_| false).with_pins([id.key_fingerprint()]);
        assert!(pinned.check(&http).is_ok());
    }

    #[test]
    fn config_validation() {
        assert!(NetherNetClient::new(NetherNetClientConfig::default()).is_ok());
        let bad = NetherNetClientConfig {
            ice_servers: vec![IceServer::stun("http://nope")],
            ..Default::default()
        };
        assert!(NetherNetClient::new(bad).is_err());
        let bad = NetherNetClientConfig {
            http_timeout: Duration::ZERO,
            ..Default::default()
        };
        assert!(NetherNetClient::new(bad).is_err());
    }

    #[test]
    fn credentials_debug_hides_token() {
        let c = ClientCredentials::new("d", "secret.jwt.token", SigningKey::generate());
        assert!(!format!("{c:?}").contains("secret"));
    }
}
