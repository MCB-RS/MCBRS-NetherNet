//! The WebRTC answering side ("Partner Host", guide §3 and §7) and the
//! all-in-one [`NetherNetListener`] (HTTP signaling + host).

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, PoisonError, RwLock};

use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use webrtc::peer_connection::{PeerConnection, RTCSessionDescription};

use crate::config::{ClientAuth, JoinRequest, NetherNetConfig, ServerInfo};
use crate::conn::{ConnReceiver, NetherNetConnection, Shared};
use crate::error::Result;
use crate::identity::client::{ClientIdentity, verify_client_offer};
use crate::identity::server::ServerIdentity;
use crate::peer::{PeerSettings, new_peer};
use crate::sdp;
use crate::signaling::{self, OfferRequest, SignalingError, SignalingHandler, validate_network_id};

/// Per-connection queue length of received messages not yet read by the
/// application (the byte budget is `max_buffered_incoming_bytes`).
const MESSAGE_QUEUE_LEN: usize = 1024;
/// Receives connections established by a [`NetherNetHost`].
#[derive(Debug)]
pub struct Incoming(mpsc::Receiver<NetherNetConnection>);

impl Incoming {
    /// Waits for the next established connection. `None` once the host is gone.
    pub async fn accept(&mut self) -> Option<NetherNetConnection> {
        self.0.recv().await
    }
}

/// The WebRTC host: turns SDP offers into signed answers and yields
/// [`NetherNetConnection`]s once the data channels are open.
///
/// It implements [`SignalingHandler`], so it can be plugged into the HTTP
/// router of [`crate::signaling`] (or any custom signaling transport).
#[derive(Clone)]
pub struct NetherNetHost {
    inner: Arc<HostInner>,
}

struct HostInner {
    config: NetherNetConfig,
    identity: ServerIdentity,
    server_info: RwLock<ServerInfo>,
    incoming: mpsc::Sender<NetherNetConnection>,
    pending: Arc<Semaphore>,
}

impl std::fmt::Debug for NetherNetHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetherNetHost")
            .field("config", &self.inner.config)
            .field("key_fingerprint", &self.inner.identity.key_fingerprint())
            .finish_non_exhaustive()
    }
}

impl NetherNetHost {
    /// Creates a host and the stream of connections it will produce.
    pub fn new(
        config: NetherNetConfig,
        identity: ServerIdentity,
        server_info: ServerInfo,
    ) -> Result<(Self, Incoming)> {
        config.validate()?;
        let (tx, rx) = mpsc::channel(config.accept_backlog);
        let pending = Arc::new(Semaphore::new(config.max_pending_connections));
        let host = Self {
            inner: Arc::new(HostInner {
                config,
                identity,
                server_info: RwLock::new(server_info),
                incoming: tx,
                pending,
            }),
        };
        Ok((host, Incoming(rx)))
    }

    /// Current server metadata (served on `GET /v1/join`).
    pub fn server_info(&self) -> ServerInfo {
        // A panic inside `update_server_info` must not take `GET /v1/join` down
        // forever: recover the data from a poisoned lock.
        self.inner
            .server_info
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replaces the server metadata.
    pub fn set_server_info(&self, info: ServerInfo) {
        *self
            .inner
            .server_info
            .write()
            .unwrap_or_else(PoisonError::into_inner) = info;
    }

    /// Updates the server metadata in place (e.g. the player count).
    pub fn update_server_info(&self, update: impl FnOnce(&mut ServerInfo)) {
        update(
            &mut self
                .inner
                .server_info
                .write()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// The operator identity used to sign answers.
    pub fn identity(&self) -> &ServerIdentity {
        &self.inner.identity
    }

    /// Processes one offer: validates the client, negotiates WebRTC and returns
    /// the signed answer. The connection is delivered to [`Incoming`] later,
    /// once its data channels are open.
    pub async fn accept_offer(&self, request: OfferRequest) -> Result<String, SignalingError> {
        // Run the negotiation in its own task: if the HTTP client hangs up, the
        // request future is dropped, and a PeerConnection created by a dropped
        // future would never be closed (its driver task and UDP sockets leak).
        // A detached task always reaches the code paths that close it.
        match tokio::spawn(self.inner.clone().accept_offer(request)).await {
            Ok(result) => result,
            Err(e) => Err(SignalingError::Internal(format!("offer task failed: {e}"))),
        }
    }
}

#[async_trait::async_trait]
impl SignalingHandler for NetherNetHost {
    async fn server_info(&self) -> ServerInfo {
        NetherNetHost::server_info(self)
    }

    async fn handle_offer(&self, request: OfferRequest) -> Result<String, SignalingError> {
        self.accept_offer(request).await
    }

    fn trusted_proxies(&self) -> &[IpAddr] {
        &self.inner.config.trusted_proxies
    }
}

impl HostInner {
    async fn accept_offer(
        self: Arc<Self>,
        request: OfferRequest,
    ) -> Result<String, SignalingError> {
        let OfferRequest {
            network_id,
            sdp: offer,
            signaling_addr,
        } = request;

        validate_network_id(&network_id).map_err(SignalingError::BadRequest)?;
        sdp::validate_offer(&offer).map_err(SignalingError::BadRequest)?;

        // §5.1 – validate the client assertion before allocating anything.
        let identity = self.authenticate(&offer)?;

        if let Some(authorizer) = &self.config.authorizer {
            let join = JoinRequest {
                network_id: network_id.clone(),
                signaling_addr,
                identity: identity.clone(),
            };
            authorizer
                .authorize(&join)
                .await
                .map_err(SignalingError::Forbidden)?;
        }

        let permit = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| SignalingError::Unavailable("too many pending connections".into()))?;

        // §5.1 step 7 – WebRTC stacks reject unknown attributes.
        let mut offer = sdp::strip_identity(&offer);
        if self.config.infer_client_candidates
            && let Some(addr) = signaling_addr
            && let Some(with_inferred) = sdp::infer_client_candidates(&offer, addr.ip())
        {
            tracing::debug!(%network_id, ip = %addr.ip(), "added inferred client candidate");
            offer = with_inferred;
        }
        let remote_max = sdp::max_message_size(&offer).unwrap_or(sdp::DEFAULT_MAX_MESSAGE_SIZE);
        let max_message_size = remote_max.min(self.config.max_outgoing_message_size);

        let (shared, msg_rx) = Shared::new(
            network_id.clone(),
            self.config.max_incoming_message_size,
            self.config.max_buffered_incoming_bytes,
            MESSAGE_QUEUE_LEN,
        );
        let (pc, answer) = self.negotiate(shared.clone(), offer).await.map_err(|e| {
            shared.close();
            tracing::warn!(%network_id, "WebRTC negotiation failed: {e}");
            SignalingError::from(e)
        })?;

        // §5.2 – the answer must always carry the server assertion.
        let signed = match self.identity.sign_answer(&answer) {
            Ok(s) => s,
            Err(e) => {
                shared.close();
                let _ = pc.close().await;
                return Err(e.into());
            }
        };

        let pending = PendingConnection {
            shared,
            pc,
            msg_rx,
            max_message_size,
            identity,
            signaling_addr,
            permit,
        };
        tokio::spawn(self.clone().finish(pending));
        tracing::info!(%network_id, ?signaling_addr, "answered NetherNet offer");
        Ok(signed)
    }

    fn authenticate(&self, offer: &str) -> Result<Option<ClientIdentity>, SignalingError> {
        let (verifier, required) = match &self.config.client_auth {
            ClientAuth::Disabled => return Ok(None),
            ClientAuth::Optional(v) => (v, false),
            ClientAuth::Required(v) => (v, true),
        };
        match verify_client_offer(offer, verifier.as_ref()) {
            Ok(Some(identity)) => Ok(Some(identity)),
            Ok(None) if required => Err(SignalingError::Forbidden(
                "offer has no a=identity assertion".into(),
            )),
            Ok(None) => Ok(None),
            Err(e) => Err(SignalingError::Forbidden(e.to_string())),
        }
    }

    /// Creates the answering peer connection and gathers all ICE candidates
    /// (full ICE: trickle is disabled, §2).
    async fn negotiate(
        &self,
        shared: Arc<Shared>,
        offer: String,
    ) -> Result<(Arc<dyn PeerConnection>, String)> {
        let settings = PeerSettings {
            udp_bind_addrs: &self.config.udp_bind_addrs,
            ice_servers: &self.config.ice_servers,
            public_ips: &self.config.public_ips,
            include_loopback_candidates: self.config.include_loopback_candidates,
            send_buffer_limit: self.config.send_buffer_limit,
        };
        let mut peer = new_peer(&settings, shared).await?;
        let result = async {
            peer.pc
                .set_remote_description(RTCSessionDescription::offer(offer)?)
                .await?;
            let answer = peer.pc.create_answer(None).await?;
            peer.pc.set_local_description(answer).await?;
            peer.local_description(self.config.ice_gathering_timeout)
                .await
        }
        .await;

        match result {
            Ok(answer) => Ok((peer.pc, answer)),
            Err(e) => {
                let _ = peer.pc.close().await;
                Err(e)
            }
        }
    }

    /// Waits for the data channels and hands the connection to `accept()`.
    async fn finish(self: Arc<Self>, pending: PendingConnection) {
        let PendingConnection {
            shared,
            pc,
            msg_rx,
            max_message_size,
            identity,
            signaling_addr,
            permit,
        } = pending;

        let opened =
            tokio::time::timeout(self.config.connect_timeout, shared.wait_reliable_open()).await;
        if !matches!(opened, Ok(true)) {
            tracing::info!(network_id = %shared.network_id, "connection failed before the data channels opened");
            shared.close();
            let _ = pc.close().await;
            return;
        }
        drop(permit);

        let conn = NetherNetConnection::new(
            shared.clone(),
            pc,
            msg_rx,
            max_message_size,
            identity,
            signaling_addr,
        );
        tracing::info!(network_id = %shared.network_id, "NetherNet connection established");
        if let Err(e) = self.incoming.try_send(conn) {
            tracing::warn!(network_id = %shared.network_id, "accept backlog full or listener closed, dropping connection");
            drop(e); // dropping the connection closes it
        }
    }
}

struct PendingConnection {
    shared: Arc<Shared>,
    pc: Arc<dyn PeerConnection>,
    msg_rx: ConnReceiver,
    max_message_size: usize,
    identity: Option<ClientIdentity>,
    signaling_addr: Option<SocketAddr>,
    permit: OwnedSemaphorePermit,
}

/// All-in-one NetherNet server: HTTP signaling endpoint + WebRTC host.
///
/// ```no_run
/// # async fn run() -> mcbrs_nethernet::Result<()> {
/// use mcbrs_nethernet::{NetherNetConfig, NetherNetListener, ServerIdentity, ServerInfo};
///
/// let identity = ServerIdentity::load_or_generate("nethernet_server_key.pem")?;
/// let listener = NetherNetListener::bind(
///     "0.0.0.0:8080",
///     NetherNetConfig::default(),
///     identity,
///     ServerInfo::default(),
/// )
/// .await?;
///
/// while let Some(conn) = listener.accept().await {
///     tokio::spawn(async move {
///         while let Some(message) = conn.recv().await {
///             let _ = conn.send(&message.payload).await; // echo
///         }
///     });
/// }
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct NetherNetListener {
    host: NetherNetHost,
    incoming: Mutex<Incoming>,
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
}

impl NetherNetListener {
    /// Binds the HTTP signaling server on `addr` and starts accepting offers.
    pub async fn bind(
        addr: impl ToSocketAddrs,
        config: NetherNetConfig,
        identity: ServerIdentity,
        server_info: ServerInfo,
    ) -> Result<Self> {
        let (host, incoming) = NetherNetHost::new(config, identity, server_info)?;
        let tcp = TcpListener::bind(addr).await?;
        let local_addr = tcp.local_addr()?;
        let (shutdown, mut shutdown_rx) = watch::channel(false);

        let handler: Arc<dyn SignalingHandler> = Arc::new(host.clone());
        tokio::spawn(async move {
            let stop = async move {
                let _ = shutdown_rx.wait_for(|s| *s).await;
            };
            if let Err(e) = signaling::serve(tcp, handler, stop).await {
                tracing::error!("NetherNet signaling server stopped: {e}");
            }
        });
        tracing::info!(%local_addr, "NetherNet signaling listening");

        Ok(Self {
            host,
            incoming: Mutex::new(incoming),
            local_addr,
            shutdown,
        })
    }

    /// Address of the HTTP signaling server.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The underlying host (server info, identity, ...).
    pub fn host(&self) -> &NetherNetHost {
        &self.host
    }

    /// Waits for the next established connection.
    pub async fn accept(&self) -> Option<NetherNetConnection> {
        let mut incoming = self.incoming.lock().await;
        let mut stop = self.shutdown.subscribe();
        tokio::select! {
            conn = incoming.accept() => conn,
            _ = stop.wait_for(|stopped| *stopped) => None,
        }
    }

    /// Stops the HTTP signaling server; pending `accept()` calls return `None`.
    /// Established connections are not affected.
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
    }
}

impl Drop for NetherNetListener {
    fn drop(&mut self) {
        self.shutdown();
    }
}
