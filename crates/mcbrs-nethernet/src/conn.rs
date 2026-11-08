//! An established NetherNet connection (two SCTP data channels over one
//! WebRTC peer connection), with NetherNet framing applied transparently.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use bytes::{Bytes, BytesMut};
use tokio::sync::{Mutex, mpsc, watch};
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

/// State shared between the connection handle, the peer-connection event
/// handler and the data channel pumps.
pub(crate) struct Shared {
    pub(crate) network_id: String,
    closed: watch::Sender<bool>,
    reliable_open: watch::Sender<bool>,
    reliable: StdMutex<Option<Arc<dyn DataChannel>>>,
    unreliable: StdMutex<Option<Arc<dyn DataChannel>>>,
    msg_tx: mpsc::Sender<Message>,
    max_incoming_message_size: usize,
}

impl Shared {
    pub(crate) fn new(
        network_id: String,
        max_incoming_message_size: usize,
        buffer: usize,
    ) -> (Arc<Self>, mpsc::Receiver<Message>) {
        let (msg_tx, msg_rx) = mpsc::channel(buffer);
        let shared = Arc::new(Self {
            network_id,
            closed: watch::channel(false).0,
            reliable_open: watch::channel(false).0,
            reliable: StdMutex::new(None),
            unreliable: StdMutex::new(None),
            msg_tx,
            max_incoming_message_size,
        });
        (shared, msg_rx)
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
            _ = self.closed() => false,
        }
    }

    fn slot(&self, channel: Channel) -> &StdMutex<Option<Arc<dyn DataChannel>>> {
        match channel {
            Channel::Reliable => &self.reliable,
            Channel::Unreliable => &self.unreliable,
        }
    }

    fn channel(&self, channel: Channel) -> Option<Arc<dyn DataChannel>> {
        self.slot(channel).lock().expect("poisoned").clone()
    }

    fn set_channel(&self, channel: Channel, dc: Option<Arc<dyn DataChannel>>) {
        *self.slot(channel).lock().expect("poisoned") = dc;
    }
}

/// Reads events of one data channel, applies NetherNet framing and forwards
/// complete messages to the connection.
pub(crate) async fn pump_data_channel(shared: Arc<Shared>, dc: Arc<dyn DataChannel>) {
    let label = dc.label().await.unwrap_or_default();
    let Some(channel) = Channel::from_label(&label) else {
        tracing::warn!(network_id = %shared.network_id, %label, "closing unexpected data channel");
        let _ = dc.close().await;
        return;
    };
    tracing::debug!(network_id = %shared.network_id, %label, "data channel open");
    shared.set_channel(channel, Some(dc.clone()));
    if channel == Channel::Reliable {
        shared.reliable_open.send_replace(true);
    }

    let mut reassembler = Reassembler::new(shared.max_incoming_message_size);
    loop {
        let event = tokio::select! {
            event = dc.poll() => event,
            _ = shared.closed() => break,
        };
        match event {
            Some(DataChannelEvent::OnMessage(msg)) => {
                let payload = match channel {
                    Channel::Reliable => match reassembler.push(&msg.data) {
                        Ok(Some(payload)) => payload,
                        Ok(None) => continue,
                        Err(e) => {
                            tracing::warn!(network_id = %shared.network_id, "closing connection: {e}");
                            shared.close();
                            break;
                        }
                    },
                    Channel::Unreliable => match framing::parse_single(&msg.data) {
                        Ok(payload) => Bytes::copy_from_slice(payload),
                        Err(e) => {
                            tracing::debug!(network_id = %shared.network_id, "dropping unreliable message: {e}");
                            continue;
                        }
                    },
                };
                let message = Message { channel, payload };
                tokio::select! {
                    res = shared.msg_tx.send(message) => if res.is_err() { break },
                    _ = shared.closed() => break,
                }
            }
            Some(DataChannelEvent::OnClose) | None => {
                tracing::debug!(network_id = %shared.network_id, %label, "data channel closed");
                shared.set_channel(channel, None);
                if channel == Channel::Reliable {
                    shared.close();
                }
                break;
            }
            Some(_) => {}
        }
    }
}

/// An established NetherNet connection with a Minecraft client.
///
/// Dropping the handle closes the underlying WebRTC peer connection.
pub struct NetherNetConnection {
    shared: Arc<Shared>,
    pc: Arc<dyn PeerConnection>,
    rx: Mutex<mpsc::Receiver<Message>>,
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
        rx: mpsc::Receiver<Message>,
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
        tokio::select! {
            biased;
            message = rx.recv() => message,
            _ = self.shared.closed() => rx.try_recv().ok(),
        }
    }

    /// Sends a message on the reliable channel, fragmenting it if needed.
    pub async fn send(&self, payload: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        let frames = framing::fragment(payload, self.max_message_size)?;
        let dc = self
            .shared
            .channel(Channel::Reliable)
            .ok_or(Error::Closed)?;
        // Fragments of two messages must never interleave.
        let _guard = self.send_lock.lock().await;
        for frame in frames {
            dc.send(BytesMut::from(frame)).await?;
        }
        Ok(())
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
                let frame = framing::frame_single(payload, self.max_message_size)?;
                dc.send(BytesMut::from(frame)).await?;
                Ok(())
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
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let pc = self.pc.clone();
            handle.spawn(async move {
                let _ = pc.close().await;
            });
        }
    }
}
