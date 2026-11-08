//! End-to-end test: a fake "Minecraft client" built with webrtc-rs performs the
//! exact flow of the NetherNet guide against a real `NetherNetListener`:
//!
//! 1. `GET /v1/join` (capability check + server info)
//! 2. full-ICE offer with two data channels and a signed `a=identity`
//! 3. `POST /v1/join/{networkId}` → signed answer, verified like the client does
//! 4. data channels open, framed + fragmented messages flow both ways.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use mcbrs_nethernet::framing::{self, Reassembler};
use mcbrs_nethernet::identity::jose::{self, SigningKey};
use mcbrs_nethernet::identity::{IDP_PROTOCOL, IdentityAssertion, canonical};
use mcbrs_nethernet::{
    Channel, ClientAuth, JwkSetVerifier, NetherNetConfig, NetherNetListener, ServerIdentity,
    ServerInfo, sdp, verify_server_answer,
};
use rtc::ice::network_type::NetworkType;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCBundlePolicy,
    RTCConfigurationBuilder, RTCIceGatheringState, RTCSessionDescription, SettingEngineBuilder,
};

const TIMEOUT: Duration = Duration::from_secs(20);

struct ClientHandler {
    gathered: tokio::sync::mpsc::Sender<()>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for ClientHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gathered.try_send(());
        }
    }
}

struct FakeClient {
    pc: Arc<dyn PeerConnection>,
    reliable: Arc<dyn DataChannel>,
    unreliable: Arc<dyn DataChannel>,
    offer: String,
}

/// Creates the client PeerConnection exactly as described in guide §6.
async fn fake_client() -> FakeClient {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let settings = SettingEngineBuilder::new()
        .with_network_types(vec![NetworkType::Udp4])
        .with_include_loopback_candidate(true)
        .build();
    let pc = PeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_bundle_policy(RTCBundlePolicy::MaxBundle)
                .build(),
        )
        .with_setting_engine(settings)
        .with_handler(Arc::new(ClientHandler { gathered: tx }))
        .with_udp_addrs(vec!["127.0.0.1:0".parse::<SocketAddr>().unwrap()])
        .build()
        .await
        .expect("client peer connection");
    let pc: Arc<dyn PeerConnection> = Arc::new(pc);

    let reliable = pc
        .create_data_channel("ReliableDataChannel", None)
        .await
        .unwrap();
    let unreliable = pc
        .create_data_channel(
            "UnreliableDataChannel",
            Some(RTCDataChannelInit {
                ordered: false,
                max_retransmits: Some(0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let offer = pc.create_offer(None).await.unwrap();
    pc.set_local_description(offer).await.unwrap();
    tokio::time::timeout(TIMEOUT, rx.recv())
        .await
        .expect("client ICE gathering");
    let offer = pc.local_description().await.unwrap().sdp;

    FakeClient {
        pc,
        reliable,
        unreliable,
        offer,
    }
}

/// Adds the client `a=identity` (GameServerToken + signed fingerprints, §5.1).
fn sign_offer(offer: &str, auth_service: &SigningKey, client_key: &SigningKey) -> String {
    let token = jose::sign_jwt(
        auth_service,
        &serde_json::json!({
            "xid": "2535412345678901",
            "pfid": "1234ABCD5678EF90",
            "cpk": client_key.verifying_key().to_jwk(),
            "exp": jose::unix_now() + 3600,
        }),
    );
    let payload = canonical::fingerprint_payload(&sdp::fingerprints(offer));
    let assertion = IdentityAssertion {
        domain: "auth.example.test".into(),
        protocol: IDP_PROTOCOL.into(),
        token,
        fingerprints: jose::sign_detached(client_key, payload.as_bytes()),
    };
    sdp::insert_identity(offer, &assertion.encode())
}

async fn wait_open(dc: &Arc<dyn DataChannel>) {
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => return,
            Some(_) => continue,
            None => panic!("data channel closed before opening"),
        }
    }
}

async fn next_frame(dc: &Arc<dyn DataChannel>) -> BytesMut {
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnMessage(msg)) => return msg.data,
            Some(_) => continue,
            None => panic!("data channel closed"),
        }
    }
}

async fn start_server(auth_service: &SigningKey) -> (NetherNetListener, String) {
    let verifier = JwkSetVerifier::new().with_key(None, auth_service.verifying_key());
    let config = NetherNetConfig {
        client_auth: ClientAuth::Required(Arc::new(verifier)),
        udp_bind_addrs: vec!["127.0.0.1:0".parse().unwrap()],
        include_loopback_candidates: true,
        // Small SCTP messages so that fragmentation is exercised.
        max_outgoing_message_size: 1200,
        ..Default::default()
    };
    let identity = ServerIdentity::generate()
        .with_domain("mcbrs.test")
        .with_issuer("MCBRS test server");
    let info = ServerInfo {
        name: "MCBRS Test".into(),
        ..Default::default()
    };
    let listener = NetherNetListener::bind("127.0.0.1:0", config, identity, info)
        .await
        .unwrap();
    let url = format!("http://{}", listener.local_addr());
    (listener, url)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_nethernet_flow() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("mcbrs_nethernet=debug")
        .with_test_writer()
        .try_init();

    let auth_service = SigningKey::generate();
    let (listener, url) = start_server(&auth_service).await;
    let http = reqwest::Client::new();

    // 1. Capability check.
    let resp = http.get(format!("{url}/v1/join")).send().await.unwrap();
    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "application/json"
    );
    let info: serde_json::Value = serde_json::from_slice(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(info["name"], "MCBRS Test");
    assert_eq!(info["maxPlayers"], 10);
    assert_eq!(info["gameType"], 0);

    // 2. Offer.
    let client = fake_client().await;
    assert!(client.offer.contains("a=candidate:"), "full ICE offer");
    let client_key = SigningKey::generate();
    let offer = sign_offer(&client.offer, &auth_service, &client_key);

    // 3. Signaling round-trip.
    let resp = http
        .post(format!("{url}/v1/join/9876543210123456789"))
        .header("content-type", "application/sdp")
        .body(offer)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "application/sdp"
    );
    let answer = resp.text().await.unwrap();
    assert!(answer.contains("a=candidate:"), "full ICE answer");

    // The client verifies the server assertion (§5.2) then strips it.
    let server_id = verify_server_answer(&answer).expect("valid server assertion");
    assert_eq!(server_id.domain, "mcbrs.test");
    assert_eq!(server_id.claims["iss"], "MCBRS test server");
    assert_eq!(
        server_id.key_fingerprint(),
        listener.host().identity().key_fingerprint()
    );
    let answer = sdp::strip_identity(&answer);
    client
        .pc
        .set_remote_description(RTCSessionDescription::answer(answer).unwrap())
        .await
        .unwrap();

    // 4. Data channels.
    tokio::time::timeout(TIMEOUT, wait_open(&client.reliable))
        .await
        .expect("reliable channel open");
    tokio::time::timeout(TIMEOUT, wait_open(&client.unreliable))
        .await
        .expect("unreliable channel open");
    let conn = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .expect("server accepted")
        .expect("listener open");
    assert_eq!(conn.network_id(), "9876543210123456789");
    let identity = conn.identity().expect("authenticated player");
    assert_eq!(identity.xuid().as_deref(), Some("2535412345678901"));
    assert_eq!(identity.playfab_id().as_deref(), Some("1234ABCD5678EF90"));
    assert_eq!(conn.max_message_size(), 1200);

    // Client -> server, small reliable message.
    for frame in framing::fragment(b"hello nethernet", 262_144).unwrap() {
        client.reliable.send(BytesMut::from(frame)).await.unwrap();
    }
    let msg = tokio::time::timeout(TIMEOUT, conn.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(msg.channel, Channel::Reliable);
    assert_eq!(&msg.payload[..], b"hello nethernet");

    // Client -> server, fragmented reliable message.
    let big: Vec<u8> = (0..50_000u32).map(|i| (i * 7 % 256) as u8).collect();
    let frames = framing::fragment(&big, 4096).unwrap();
    assert!(frames.len() > 1);
    for frame in frames {
        client.reliable.send(BytesMut::from(frame)).await.unwrap();
    }
    let msg = tokio::time::timeout(TIMEOUT, conn.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(msg.payload.len(), big.len());
    assert_eq!(&msg.payload[..], &big[..]);

    // Client -> server, unreliable message (loopback: no loss expected).
    client
        .unreliable
        .send(BytesMut::from(&b"\x00movement"[..]))
        .await
        .unwrap();
    let msg = tokio::time::timeout(TIMEOUT, conn.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(msg.channel, Channel::Unreliable);
    assert_eq!(&msg.payload[..], b"movement");

    // Server -> client, fragmented with the negotiated size (1200 bytes).
    let reply: Vec<u8> = (0..20_000u32).map(|i| (i % 253) as u8).collect();
    conn.send(&reply).await.unwrap();
    let mut reassembler = Reassembler::new(1 << 20);
    let mut fragments = 0;
    let received = loop {
        let frame = tokio::time::timeout(TIMEOUT, next_frame(&client.reliable))
            .await
            .unwrap();
        assert!(frame.len() <= 1200, "fragment exceeds negotiated size");
        fragments += 1;
        if let Some(full) = reassembler.push(&frame).unwrap() {
            break full;
        }
    };
    assert_eq!(fragments, 20_000usize.div_ceil(1199));
    assert_eq!(&received[..], &reply[..]);

    // Server -> client, unreliable.
    conn.send_unreliable(b"pos").await.unwrap();
    let frame = tokio::time::timeout(TIMEOUT, next_frame(&client.unreliable))
        .await
        .unwrap();
    assert_eq!(&frame[..], b"\x00pos");
    assert!(conn.send_unreliable(&[0u8; 5000]).await.is_err());

    // Closing from the client side ends the server connection.
    client.pc.close().await.unwrap();
    let end = tokio::time::timeout(TIMEOUT, async { while conn.recv().await.is_some() {} }).await;
    assert!(end.is_ok(), "server noticed the disconnection");
    assert!(conn.is_closed());
    listener.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_offers() {
    let auth_service = SigningKey::generate();
    let (_listener, url) = start_server(&auth_service).await;
    let http = reqwest::Client::new();
    let client = fake_client().await;
    let post = |body: String| {
        let http = http.clone();
        let url = format!("{url}/v1/join/42");
        async move {
            http.post(url)
                .body(body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    // No a=identity while authentication is required.
    assert_eq!(post(client.offer.clone()).await, 403);

    // Token signed by an unknown "auth service".
    let rogue = SigningKey::generate();
    assert_eq!(
        post(sign_offer(&client.offer, &rogue, &SigningKey::generate())).await,
        403
    );

    // MITM: fingerprint replaced after signing.
    let signed = sign_offer(&client.offer, &auth_service, &SigningKey::generate());
    let original = &sdp::fingerprints(&client.offer)[0].digest;
    let fake_digest = format!("{}00", "00:".repeat(31));
    let tampered = signed.replace(original.as_str(), &fake_digest);
    assert_eq!(post(tampered).await, 403);

    // Garbage body.
    assert_eq!(post("hello".into()).await, 400);

    // Unknown route.
    let status = http
        .get(format!("{url}/v2/join"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status.as_u16(), 404);

    client.pc.close().await.unwrap();
}
