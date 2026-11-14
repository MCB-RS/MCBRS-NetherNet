//! An established NetherNet connection (two SCTP data channels over one
//! WebRTC peer connection), with NetherNet framing applied transparently.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use bytes::Bytes;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::PeerConnection;

use crate::error::{Error, Result};
use crate::framing::{self, Reassembler};
use crate::identity::client::ClientIdentity;

/// Label of the ordered, reliable data channel.
pub const RELIABLE_LABEL: &str = "ReliableDataChannel";
/// Label of the unordered, unreliable data channel.
pub const UNRELIABLE_LABEL: &str = "UnreliableDataChannel";

/// The data channel a message travelled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// `ReliableDataChannel`: ordered, reliable, supports fragmentation.
    Reliable,
    /// `UnreliableDataChannel`: unordered, `maxRetransmits = 0`, no fragmentation.
    Unreliable,
}

impl Channel {
    /// The data channel label used by the Minecraft client.
    pub fn label(self) -> &'static str {
        match self {
            Self::Reliable => RELIABLE_LABEL,
            Self::Unreliable => UNRELIABLE_LABEL,
        }
    }

    /// Maps a data channel label to a [`Channel`].
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            RELIABLE_LABEL => Some(Self::Reliable),
            UNRELIABLE_LABEL => Some(Self::Unreliable),
            _ => None,
        }
    }
}

/// A complete application message (NetherNet header stripped, fragments reassembled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Channel the message was received on.
    pub channel: Channel,
    /// Application payload (a Bedrock game packet batch).
    pub payload: Bytes,
}

/// A received message waiting in the connection queue, together with the
/// share of the incoming byte budget it holds until `recv()` hands it out.
struct Queued {
    message: Message,
    _budget: OwnedSemaphorePermit,
}

type ChannelSlot = StdMutex<Option<Arc<dyn DataChannel>>>;

/// State shared between the connection handle, the peer-connection event
/// handler and the data channel pumps.
pub(crate) struct Shared {
    pub(crate) network_id: String,
    closed: watch::Sender<bool>,
    reliable_open: watch::Sender<bool>,
    reliable: ChannelSlot,
    unreliable: ChannelSlot,
    msg_tx: mpsc::Sender<Queued>,
    max_incoming_message_size: usize,
    /// Bytes of received-but-unread messages, see `max_buffered_incoming_bytes`.
    budget: Arc<Semaphore>,
    budget_size: usize,
}

impl Shared {
    pub(crate) fn new(
        network_id: String,
        max_incoming_message_size: usize,
        max_buffered_incoming_bytes: usize,
        queue_len: usize,
    ) -> (Arc<Self>, ConnReceiver) {
        let (msg_tx, msg_rx) = mpsc::channel(queue_len);
        let shared = Arc::new(Self {
            network_id,
            closed: watch::channel(false).0,
            reliable_open: watch::channel(false).0,
            reliable: StdMutex::new(None),
            unreliable: StdMutex::new(None),
            msg_tx,
            max_incoming_message_size,
            budget: Arc::new(Semaphore::new(max_buffered_incoming_bytes)),
            budget_size: max_buffered_incoming_bytes,
        });
        (shared, ConnReceiver(msg_rx))
    }

    pub(crate) fn close(&self) {
        self.closed.send_replace(true);
    }

    pub(crate) fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// Resolves once the connection is closed.
    pub(crate) async fn closed(&self) {
        let mut rx = self.closed.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }

    /// Resolves to `true` once the reliable channel is open, `false` if the
    /// connection closed first.
    pub(crate) async fn wait_reliable_open(&self) -> bool {
        let mut open = self.reliable_open.subscribe();
        tokio::select! {
            res = open.wait_for(|o| *o) => res.is_ok() && !self.is_closed(),
            () = self.closed() => false,
        }
    }

    fn slot(&self, channel: Channel) -> &ChannelSlot {
        match channel {
            Channel::Reliable => &self.reliable,
            Channel::Unreliable => &self.unreliable,
        }
    }

    fn channel(&self, channel: Channel) -> Option<Arc<dyn DataChannel>> {
        // No user code runs under this lock, but never turn a poisoned lock into
        // a panic on the network path.
        self.slot(channel)
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Registers `dc` for `channel`. Returns `false` if a channel with the same
    /// label is already registered (a client may not open duplicates).
    fn claim_channel(&self, channel: Channel, dc: &Arc<dyn DataChannel>) -> bool {
        let mut slot = self
            .slot(channel)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if slot.is_some() {
            return false;
        }
        *slot = Some(dc.clone());
        true
    }

    fn release_channel(&self, channel: Channel) {
        *self
            .slot(channel)
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Budget cost of a payload (a message larger than the whole budget still
    /// gets through, alone).
    fn cost(&self, len: usize) -> u32 {
        // `budget_size <= u32::MAX` is enforced by `NetherNetConfig::validate`.
        u32::try_from(len.min(self.budget_size)).unwrap_or(u32::MAX)
    }
}

/// Receiving half of a connection's message queue.
pub(crate) struct ConnReceiver(mpsc::Receiver<Queued>);

/// Checks that the reliable channel really has the reliable, ordered semantics
/// the reassembler relies on.
async fn has_reliable_semantics(dc: &Arc<dyn DataChannel>) -> bool {
    matches!(dc.ordered().await, Ok(true))
        && matches!(dc.max_retransmits().await, Ok(None))
        && matches!(dc.max_packet_life_time().await, Ok(None))
}

/// Who created a data channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelOrigin {
    /// Opened by the remote peer (host side): already open when announced.
    Remote,
    /// Created locally (client side): must wait for its `OnOpen` event.
    Local,
}

/// Waits until a locally created channel is open. Returns `false` if it
/// closed first.
async fn wait_local_open(dc: &Arc<dyn DataChannel>) -> bool {
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => return true,
            Some(DataChannelEvent::OnClose) | None => return false,
            Some(_) => {}
        }
    }
}

/// Reads events of one data channel, applies NetherNet framing and forwards
/// complete messages to the connection.
pub(crate) async fn pump_data_channel(
    shared: Arc<Shared>,
    dc: Arc<dyn DataChannel>,
    origin: ChannelOrigin,
) {
    let network_id = shared.network_id.as_str();
    let label = dc.label().await.unwrap_or_default();
    let Some(channel) = Channel::from_label(&label) else {
        tracing::warn!(%network_id, label = %label.escape_debug(), "closing unexpected data channel");
        let _ = dc.close().await;
        return;
    };
    if origin == ChannelOrigin::Local {
        let opened = tokio::select! {
            opened = wait_local_open(&dc) => opened,
            () = shared.closed() => false,
        };
        if !opened {
            if channel == Channel::Reliable {
                shared.close();
            }
            return;
        }
    } else if channel == Channel::Reliable && !has_reliable_semantics(&dc).await {
        tracing::warn!(%network_id, "closing ReliableDataChannel opened as unordered/unreliable");
        let _ = dc.close().await;
        return;
    }
    if !shared.claim_channel(channel, &dc) {
        tracing::warn!(%network_id, %label, "closing duplicate data channel");
        let _ = dc.close().await;
        return;
    }
    tracing::debug!(%network_id, %label, "data channel open");
    if channel == Channel::Reliable {
        shared.reliable_open.send_replace(true);
    }

    let mut closed = shared.closed.subscribe();
    let mut reassembler = Reassembler::new(shared.max_incoming_message_size);
    loop {
        let event = tokio::select! {
            event = dc.poll() => event,
            _ = closed.wait_for(|c| *c) => break,
        };
        let msg = match event {
            Some(DataChannelEvent::OnMessage(msg)) => msg,
            Some(DataChannelEvent::OnClose) | None => {
                tracing::debug!(%network_id, %label, "data channel closed");
                shared.release_channel(channel);
                if channel == Channel::Reliable {
                    shared.close();
                }
                break;
            }
            Some(_) => continue,
        };

        match channel {
            Channel::Reliable => {
                let payload = match reassembler.push_owned(msg.data) {
                    Ok(Some(payload)) => payload,
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::warn!(%network_id, "closing connection: {e}");
                        shared.close();
                        break;
                    }
                };
                // Reliable data must not be lost: wait for budget and queue room.
                // While we wait, webrtc-rs stops draining SCTP, so the peer is
                // throttled by flow control instead of growing our memory.
                let cost = shared.cost(payload.len());
                let budget = tokio::select! {
                    permit = shared.budget.clone().acquire_many_owned(cost) => match permit {
                        Ok(permit) => permit,
                        Err(_) => break,
                    },
                    _ = closed.wait_for(|c| *c) => break,
                };
                let queued = Queued {
                    message: Message { channel, payload },
                    _budget: budget,
                };
                tokio::select! {
                    res = shared.msg_tx.send(queued) => if res.is_err() { break },
                    _ = closed.wait_for(|c| *c) => break,
                }
            }
            Channel::Unreliable => {
                let payload = match framing::parse_single_owned(msg.data) {
                    Ok(payload) => payload,
                    Err(e) => {
                        tracing::debug!(%network_id, "dropping unreliable message: {e}");
                        continue;
                    }
                };
                // Loss is acceptable here: never block (that would stall the
                // reliable channel too), drop when the application lags behind.
                let Ok(budget) = shared
                    .budget
                    .clone()
                    .try_acquire_many_owned(shared.cost(payload.len()))
                else {
                    tracing::trace!(%network_id, "incoming budget exhausted, dropping unreliable message");
                    continue;
                };
                let queued = Queued {
                    message: Message { channel, payload },
                    _budget: budget,
                };
                if let Err(mpsc::error::TrySendError::Closed(_)) = shared.msg_tx.try_send(queued) {
                    break;
                }
            }
        }
    }
}

/// An established NetherNet connection with a Minecraft client.
///
/// Dropping the handle closes the underlying WebRTC peer connection.
pub struct NetherNetConnection {
    shared: Arc<Shared>,
    pc: Arc<dyn PeerConnection>,
    rx: Mutex<ConnReceiver>,
    send_lock: Mutex<()>,
    max_message_size: usize,
    identity: Option<ClientIdentity>,
    signaling_addr: Option<SocketAddr>,
}

impl std::fmt::Debug for NetherNetConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetherNetConnection")
            .field("network_id", &self.shared.network_id)
            .field("signaling_addr", &self.signaling_addr)
            .field("authenticated", &self.identity.is_some())
            .field("closed", &self.shared.is_closed())
            .finish_non_exhaustive()
    }
}

impl NetherNetConnection {
    pub(crate) fn new(
        shared: Arc<Shared>,
        pc: Arc<dyn PeerConnection>,
        rx: ConnReceiver,
        max_message_size: usize,
        identity: Option<ClientIdentity>,
        signaling_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            shared,
            pc,
            rx: Mutex::new(rx),
            send_lock: Mutex::new(()),
            max_message_size,
            identity,
            signaling_addr,
        }
    }

    /// The client's NetworkID.
    pub fn network_id(&self) -> &str {
        &self.shared.network_id
    }

    /// The validated player identity (when client authentication is enabled).
    pub fn identity(&self) -> Option<&ClientIdentity> {
        self.identity.as_ref()
    }

    /// Address of the HTTP client that performed the signaling request.
    pub fn signaling_addr(&self) -> Option<SocketAddr> {
        self.signaling_addr
    }

    /// SCTP message size (header included) used to fragment outgoing messages.
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Returns `true` once the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }

    /// Receives the next complete message from either channel.
    /// Returns `None` once the connection is closed and drained.
    pub async fn recv(&self) -> Option<Message> {
        let mut rx = self.rx.lock().await;
        let queued = tokio::select! {
            biased;
            queued = rx.0.recv() => queued,
            () = self.shared.closed() => rx.0.try_recv().ok(),
        };
        // Dropping the permit gives the bytes back to the incoming budget.
        queued.map(|q| q.message)
    }

    /// Sends a message on the reliable channel, fragmenting it if needed.
    ///
    /// Waits while the channel's send buffer is full (see
    /// [`crate::NetherNetConfig::send_buffer_limit`]); returns
    /// [`Error::Closed`] if the connection closes meanwhile.
    pub async fn send(&self, payload: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        let frames = framing::fragment_mut(payload, self.max_message_size)?;
        let dc = self
            .shared
            .channel(Channel::Reliable)
            .ok_or(Error::Closed)?;
        // Fragments of two messages must never interleave.
        let _guard = self.send_lock.lock().await;
        let send_all = async {
            for frame in frames {
                dc.send(frame).await?;
            }
            Ok(())
        };
        tokio::select! {
            res = send_all => res,
            () = self.shared.closed() => Err(Error::Closed),
        }
    }

    /// Sends a message on the unreliable channel (may be lost or reordered).
    ///
    /// Messages larger than one SCTP message cannot be fragmented on this
    /// channel and are refused with [`Error::MessageTooLarge`]. If the client
    /// did not open the unreliable channel, the reliable one is used instead.
    pub async fn send_unreliable(&self, payload: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        match self.shared.channel(Channel::Unreliable) {
            Some(dc) => {
                let frame = framing::frame_single_mut(payload, self.max_message_size)?;
                tokio::select! {
                    res = dc.send(frame) => res.map_err(Error::from),
                    () = self.shared.closed() => Err(Error::Closed),
                }
            }
            None => self.send(payload).await,
        }
    }

    /// Sends a message on the given channel.
    pub async fn send_on(&self, channel: Channel, payload: &[u8]) -> Result<()> {
        match channel {
            Channel::Reliable => self.send(payload).await,
            Channel::Unreliable => self.send_unreliable(payload).await,
        }
    }

    /// Closes the connection.
    pub async fn close(&self) {
        self.shared.close();
        if let Err(e) = self.pc.close().await {
            tracing::debug!(network_id = %self.shared.network_id, "error while closing peer connection: {e}");
        }
    }
}

impl Drop for NetherNetConnection {
    fn drop(&mut self) {
        self.shared.close();
        // `PeerConnection::close` is async; outside a runtime the driver task is
        // already gone with it, so there is nothing left to release.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let pc = self.pc.clone();
            handle.spawn(async move {
                let _ = pc.close().await;
            });
        }
    }
}
