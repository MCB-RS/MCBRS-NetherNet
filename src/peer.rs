//! PeerConnection construction shared by the host and the client (guide §6):
//! UDP only, `max-bundle`, full ICE (no trickle), optional STUN / TURN.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rtc::ice::network_type::NetworkType;
use rtc::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
use tokio::sync::mpsc;
use webrtc::data_channel::DataChannel;
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCBundlePolicy,
    RTCConfigurationBuilder, RTCIceCandidateType, RTCIceGatheringState, RTCIceServer,
    RTCPeerConnectionState, SettingEngineBuilder,
};

use crate::config::{IceServer, MAX_SCTP_MESSAGE_SIZE};
use crate::conn::{ChannelOrigin, Shared, pump_data_channel};
use crate::error::{Error, Result};

/// Transport settings of a peer connection.
pub(crate) struct PeerSettings<'a> {
    pub(crate) udp_bind_addrs: &'a [SocketAddr],
    pub(crate) ice_servers: &'a [IceServer],
    pub(crate) public_ips: &'a [IpAddr],
    pub(crate) include_loopback_candidates: bool,
    pub(crate) send_buffer_limit: usize,
}

/// A freshly built peer connection plus the signal of ICE gathering completion.
pub(crate) struct NewPeer {
    pub(crate) pc: Arc<dyn PeerConnection>,
    gathered: mpsc::Receiver<()>,
}

impl NewPeer {
    /// Waits for ICE gathering to complete (full ICE: the SDP is only sent once
    /// every candidate is known) and returns the local description.
    ///
    /// On timeout the candidates gathered so far are used.
    pub(crate) async fn local_description(&mut self, timeout: Duration) -> Result<String> {
        if tokio::time::timeout(timeout, self.gathered.recv())
            .await
            .is_err()
        {
            tracing::warn!("ICE gathering timed out, using the candidates found so far");
        }
        self.pc
            .local_description()
            .await
            .map(|d| d.sdp)
            .ok_or_else(|| Error::sdp("no local description after ICE gathering"))
    }
}

fn to_rtc_ice_server(server: &IceServer) -> RTCIceServer {
    RTCIceServer {
        urls: server.urls.clone(),
        username: server.username.clone().unwrap_or_default(),
        credential: server.credential.clone().unwrap_or_default(),
    }
}

/// Builds a peer connection whose data channels feed `shared`.
pub(crate) async fn new_peer(settings: &PeerSettings<'_>, shared: Arc<Shared>) -> Result<NewPeer> {
    let mut engine = SettingEngineBuilder::new()
        // §6: no TCP candidates, UDP only.
        .with_network_types(vec![NetworkType::Udp4, NetworkType::Udp6])
        .with_include_loopback_candidate(settings.include_loopback_candidates)
        .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(
            u32::try_from(MAX_SCTP_MESSAGE_SIZE).unwrap_or(u32::MAX),
        ));
    if !settings.public_ips.is_empty() {
        engine = engine.with_nat_1to1_ips(
            settings
                .public_ips
                .iter()
                .map(ToString::to_string)
                .collect(),
            RTCIceCandidateType::Srflx,
        );
    }
    let configuration = RTCConfigurationBuilder::new()
        .with_bundle_policy(RTCBundlePolicy::MaxBundle)
        .with_ice_servers(settings.ice_servers.iter().map(to_rtc_ice_server).collect())
        .build();

    let (gathered_tx, gathered) = mpsc::channel(1);
    let handler = Arc::new(PeerHandler {
        shared,
        gathered: gathered_tx,
    });
    let pc = PeerConnectionBuilder::new()
        .with_configuration(configuration)
        .with_setting_engine(engine.build())
        .with_handler(handler)
        .with_udp_addrs(settings.udp_bind_addrs.to_vec())
        .with_data_channel_send_buffer_limit(settings.send_buffer_limit)
        .build()
        .await?;
    Ok(NewPeer {
        pc: Arc::new(pc),
        gathered,
    })
}

/// Peer connection events: ICE gathering, connection state, remote channels.
struct PeerHandler {
    shared: Arc<Shared>,
    gathered: mpsc::Sender<()>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for PeerHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gathered.try_send(());
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        tracing::debug!(network_id = %self.shared.network_id, %state, "peer connection state");
        if matches!(
            state,
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
        ) {
            self.shared.close();
        }
    }

    async fn on_data_channel(&self, data_channel: Arc<dyn DataChannel>) {
        // Never block the WebRTC driver: pump each channel in its own task.
        tokio::spawn(pump_data_channel(
            self.shared.clone(),
            data_channel,
            ChannelOrigin::Remote,
        ));
    }
}
