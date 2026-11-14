//! End-to-end tests: a real `NetherNetListener` against `NetherNetClient`
//! (and, for malformed or hostile traffic, a raw webrtc-rs peer), following
//! the flow of the NetherNet HTTP signaling guide.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use mcbrs_nethernet::framing;
use mcbrs_nethernet::identity::jose::{self, SigningKey};
use mcbrs_nethernet::identity::sign_sdp;
use mcbrs_nethernet::{
    Authorizer, Channel, ClientAuth, ClientCredentials, Error, IceServer, JoinRequest,
    JwkSetVerifier, NetherNetClient, NetherNetClientConfig, NetherNetConfig, NetherNetListener,
    ServerIdentity, ServerInfo, TrustOnFirstUse, sdp,
};
use rtc::ice::network_type::NetworkType;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCBundlePolicy,
    RTCConfigurationBuilder, RTCIceGatheringState, RTCSessionDescription, SettingEngineBuilder,
};

const TIMEOUT: Duration = Duration::from_secs(20);
const LOOPBACK: &str = "127.0.0.1:0";

// ---------------------------------------------------------------- helpers

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("mcbrs_nethernet=debug")
        .with_test_writer()
        .try_init();
}

/// Base server configuration: loopback only, client authentication required.
fn server_config(auth_service: &SigningKey) -> NetherNetConfig {
    let verifier = JwkSetVerifier::new().with_key(None, auth_service.verifying_key());
    NetherNetConfig {
        client_auth: ClientAuth::Required(Arc::new(verifier)),
        udp_bind_addrs: vec![LOOPBACK.parse().unwrap()],
        include_loopback_candidates: true,
        // Small SCTP messages so that fragmentation is exercised.
        max_outgoing_message_size: 1200,
        ..Default::default()
    }
}

async fn start(config: NetherNetConfig) -> (NetherNetListener, String) {
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

/// A GameServerToken issued by the (test) auth service for `key`.
fn credentials(auth_service: &SigningKey, key: SigningKey) -> ClientCredentials {
    let token = jose::sign_jwt(
        auth_service,
        &serde_json::json!({
            "xid": "2535412345678901",
            "pfid": "1234ABCD5678EF90",
            "cpk": key.verifying_key().to_jwk(),
            "exp": jose::unix_now() + 3600,
        }),
    );
    ClientCredentials::new("auth.example.test", token, key)
}

fn client_config(credentials: Option<ClientCredentials>) -> NetherNetClientConfig {
    NetherNetClientConfig {
        credentials,
        udp_bind_addrs: vec![LOOPBACK.parse().unwrap()],
        include_loopback_candidates: true,
        max_outgoing_message_size: 1200,
        ..Default::default()
    }
}

/// A raw webrtc-rs peer configured like the Minecraft client (§6), used to
/// send offers that `NetherNetClient` would never produce.
struct RawClient {
    pc: Arc<dyn PeerConnection>,
    reliable: Arc<dyn DataChannel>,
    offer: String,
}

struct GatherHandler(tokio::sync::mpsc::Sender<()>);

#[async_trait::async_trait]
impl PeerConnectionEventHandler for GatherHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.0.try_send(());
        }
    }
}

async fn raw_client() -> RawClient {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let pc = PeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_bundle_policy(RTCBundlePolicy::MaxBundle)
                .build(),
        )
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_network_types(vec![NetworkType::Udp4])
                .with_include_loopback_candidate(true)
                .build(),
        )
        .with_handler(Arc::new(GatherHandler(tx)))
        .with_udp_addrs(vec![LOOPBACK.parse::<SocketAddr>().unwrap()])
        .build()
        .await
        .unwrap();
    let pc: Arc<dyn PeerConnection> = Arc::new(pc);
    let reliable = pc
        .create_data_channel("ReliableDataChannel", None)
        .await
        .unwrap();
    let _unreliable = pc
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
    tokio::time::timeout(TIMEOUT, rx.recv()).await.unwrap();
    let offer = pc.local_description().await.unwrap().sdp;
    RawClient {
        pc,
        reliable,
        offer,
    }
}

fn sign_raw(offer: &str, auth_service: &SigningKey) -> String {
    let c = credentials(auth_service, SigningKey::generate());
    sign_sdp(offer, &c.domain, c.token, &c.key).unwrap()
}

async fn wait_event(dc: &Arc<dyn DataChannel>, open: bool) {
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) if open => return,
            Some(DataChannelEvent::OnClose) | None if !open => return,
            None => panic!("data channel closed before opening"),
            Some(_) => {}
        }
    }
}

/// Records the `signaling_addr` seen by the server policy, then refuses.
#[derive(Default)]
struct RecordingAuthorizer(Mutex<Vec<Option<SocketAddr>>>);

#[async_trait::async_trait]
impl Authorizer for RecordingAuthorizer {
    async fn authorize(&self, request: &JoinRequest) -> Result<(), String> {
        self.0.lock().unwrap().push(request.signaling_addr);
        Err("recorded".into())
    }
}

/// Minimal STUN server (RFC 8489 Binding with XOR-MAPPED-ADDRESS, IPv4).
async fn spawn_stun_server() -> (SocketAddr, Arc<AtomicUsize>) {
    const MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
    let socket = tokio::net::UdpSocket::bind(LOOPBACK).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            if n < 20 || buf[0..2] != [0x00, 0x01] || buf[4..8] != MAGIC {
                continue;
            }
            counter.fetch_add(1, Ordering::SeqCst);
            let SocketAddr::V4(from_v4) = from else {
                continue;
            };
            let mut response = vec![0x01, 0x01, 0x00, 0x0C];
            response.extend_from_slice(&buf[4..20]); // magic cookie + transaction ID
            response.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
            response.extend_from_slice(&(from_v4.port() ^ 0x2112).to_be_bytes());
            response.extend_from_slice(&(u32::from(*from_v4.ip()) ^ 0x2112_A442).to_be_bytes());
            let _ = socket.send_to(&response, from).await;
        }
    });
    (addr, requests)
}

// ---------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_flow_with_nethernet_client() {
    init_tracing();
    let auth_service = SigningKey::generate();
    let (listener, url) = start(server_config(&auth_service)).await;
    let client = NetherNetClient::new(client_config(Some(credentials(
        &auth_service,
        SigningKey::generate(),
    ))))
    .unwrap();

    // 1. Capability check.
    let info = client.server_info(&url).await.unwrap();
    assert_eq!(info.name, "MCBRS Test");
    assert_eq!(info.max_players, 10);

    // 2-4. Offer, signaling, server assertion, data channels.
    let (conn, server) = tokio::time::timeout(TIMEOUT, client.connect(&url, "9876543210123456789"))
        .await
        .expect("connect in time")
        .expect("connected");
    assert_eq!(server.domain, "mcbrs.test");
    assert_eq!(server.claims["iss"], "MCBRS test server");
    assert_eq!(
        server.key_fingerprint(),
        listener.host().identity().key_fingerprint()
    );
    assert_eq!(conn.max_message_size(), 1200);

    let server_conn = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server_conn.network_id(), "9876543210123456789");
    let player = server_conn.identity().expect("authenticated player");
    assert_eq!(player.xuid().as_deref(), Some("2535412345678901"));
    assert_eq!(player.playfab_id().as_deref(), Some("1234ABCD5678EF90"));
    assert_eq!(server_conn.max_message_size(), 1200);

    // Reliable, small and fragmented, both directions.
    let big: Vec<u8> = (0..50_000u32).map(|i| (i * 7 % 256) as u8).collect();
    for payload in [&b"hello nethernet"[..], &big] {
        conn.send(payload).await.unwrap();
        let msg = tokio::time::timeout(TIMEOUT, server_conn.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.channel, Channel::Reliable);
        assert_eq!(&msg.payload[..], payload);

        server_conn.send(payload).await.unwrap();
        let msg = tokio::time::timeout(TIMEOUT, conn.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.channel, Channel::Reliable);
        assert_eq!(&msg.payload[..], payload);
    }

    // Unreliable, both directions (loopback: no loss expected).
    conn.send_unreliable(b"movement").await.unwrap();
    let msg = tokio::time::timeout(TIMEOUT, server_conn.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (msg.channel, &msg.payload[..]),
        (Channel::Unreliable, &b"movement"[..])
    );
    server_conn.send_unreliable(b"pos").await.unwrap();
    let msg = tokio::time::timeout(TIMEOUT, conn.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (msg.channel, &msg.payload[..]),
        (Channel::Unreliable, &b"pos"[..])
    );
    assert!(
        conn.send_unreliable(&[0u8; 5000]).await.is_err(),
        "no fragmentation"
    );

    // Closing the client ends the server connection.
    conn.close().await;
    let drained = tokio::time::timeout(TIMEOUT, async {
        while server_conn.recv().await.is_some() {}
    })
    .await;
    assert!(drained.is_ok(), "server noticed the disconnection");
    assert!(server_conn.is_closed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trust_on_first_use_policy() {
    let auth_service = SigningKey::generate();
    let (listener, url) = start(server_config(&auth_service)).await;
    let prompts = Arc::new(AtomicUsize::new(0));
    let accept = Arc::new(Mutex::new(false));

    let tofu = {
        let prompts = prompts.clone();
        let accept = accept.clone();
        Arc::new(TrustOnFirstUse::new(move |request| {
            assert!(!request.https);
            prompts.fetch_add(1, Ordering::SeqCst);
            *accept.lock().unwrap()
        }))
    };
    let config = NetherNetClientConfig {
        server_trust: tofu.clone(),
        ..client_config(Some(credentials(&auth_service, SigningKey::generate())))
    };
    let client = NetherNetClient::new(config).unwrap();

    // The player refuses the unknown operator key: no connection.
    let refused = client.connect(&url, "1").await.unwrap_err();
    assert!(matches!(refused, Error::UntrustedServer(_)), "{refused}");

    // Accepted on the second attempt, then pinned: no further prompt.
    *accept.lock().unwrap() = true;
    let (first, _) = client.connect(&url, "2").await.unwrap();
    *accept.lock().unwrap() = false;
    let (second, _) = client.connect(&url, "3").await.unwrap();
    assert_eq!(prompts.load(Ordering::SeqCst), 2);
    assert!(tofu.is_pinned(&listener.host().identity().key_fingerprint()));
    first.close().await;
    second.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_offers() {
    let auth_service = SigningKey::generate();
    let (_listener, url) = start(server_config(&auth_service)).await;

    // NetherNetClient without credentials against a server requiring them.
    let anonymous = NetherNetClient::new(client_config(None)).unwrap();
    match anonymous.connect(&url, "42").await {
        Err(Error::SignalingRejected { status: 403, .. }) => {}
        other => panic!("expected HTTP 403, got {other:?}"),
    }
    // Invalid NetworkID rejected locally.
    assert!(matches!(
        anonymous.connect(&url, "bad\nid").await,
        Err(Error::Config(_))
    ));

    let http = reqwest::Client::new();
    let raw = raw_client().await;
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

    // Token signed by an unknown "auth service".
    assert_eq!(
        post(sign_raw(&raw.offer, &SigningKey::generate())).await,
        403
    );

    // MITM: fingerprint replaced after signing.
    let signed = sign_raw(&raw.offer, &auth_service);
    let original = &sdp::fingerprints(&raw.offer)[0].digest;
    let fake_digest = format!("{}00", "00:".repeat(31));
    assert_eq!(
        post(signed.replace(original.as_str(), &fake_digest)).await,
        403
    );

    // a=max-message-size below the 1024-byte floor.
    let tiny = raw.offer.replace(
        &format!(
            "a=max-message-size:{}",
            sdp::max_message_size(&raw.offer).unwrap()
        ),
        "a=max-message-size:1",
    );
    assert!(tiny.contains("a=max-message-size:1\r\n"));
    assert_eq!(post(sign_raw(&tiny, &auth_service)).await, 400);

    // Garbage body and unknown route.
    assert_eq!(post("hello".into()).await, 400);
    let status = http
        .get(format!("{url}/v2/join"))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status.as_u16(), 404);

    raw.pc.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extra_data_channels_are_rejected() {
    let auth_service = SigningKey::generate();
    let (listener, url) = start(server_config(&auth_service)).await;
    let raw = raw_client().await;
    let answer = reqwest::Client::new()
        .post(format!("{url}/v1/join/777"))
        .body(sign_raw(&raw.offer, &auth_service))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    raw.pc
        .set_remote_description(
            RTCSessionDescription::answer(sdp::strip_identity(&answer)).unwrap(),
        )
        .await
        .unwrap();
    tokio::time::timeout(TIMEOUT, wait_event(&raw.reliable, true))
        .await
        .unwrap();
    let conn = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();

    // Duplicate label, unordered "reliable" channel and unknown label: all closed.
    let duplicate = raw
        .pc
        .create_data_channel("UnreliableDataChannel", None)
        .await
        .unwrap();
    let unordered = raw
        .pc
        .create_data_channel(
            "ReliableDataChannel",
            Some(RTCDataChannelInit {
                ordered: false,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let unknown = raw.pc.create_data_channel("Whatever", None).await.unwrap();
    for dc in [&duplicate, &unordered, &unknown] {
        tokio::time::timeout(TIMEOUT, wait_event(dc, false))
            .await
            .expect("server closed the extra channel");
    }

    // The original channels still work.
    for frame in framing::fragment(b"still here", 1200).unwrap() {
        raw.reliable.send(BytesMut::from(frame)).await.unwrap();
    }
    let msg = tokio::time::timeout(TIMEOUT, conn.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&msg.payload[..], b"still here");
    assert!(!conn.is_closed());
    raw.pc.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trusted_proxies_report_the_real_client_address() {
    let auth_service = SigningKey::generate();
    let raw = raw_client().await;
    let offer = sign_raw(&raw.offer, &auth_service);
    let http = reqwest::Client::new();

    for trusted in [true, false] {
        let authorizer = Arc::new(RecordingAuthorizer::default());
        let config = NetherNetConfig {
            authorizer: Some(authorizer.clone()),
            trusted_proxies: if trusted {
                vec!["127.0.0.1".parse().unwrap()]
            } else {
                Vec::new()
            },
            ..server_config(&auth_service)
        };
        let (_listener, url) = start(config).await;
        let status = http
            .post(format!("{url}/v1/join/5"))
            .header("x-forwarded-for", "6.6.6.6, 8.8.8.8")
            .body(offer.clone())
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status.as_u16(), 403, "the recording authorizer refuses");
        let seen = authorizer.0.lock().unwrap()[0].unwrap();
        if trusted {
            // Rightmost untrusted hop, as reported by the proxy.
            assert_eq!(seen, "8.8.8.8:0".parse::<SocketAddr>().unwrap());
        } else {
            // Direct peer: forwarding headers are ignored (no spoofing).
            assert_eq!(seen.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
            assert_ne!(seen.port(), 0);
        }
    }
    raw.pc.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inferred_client_candidate_keeps_the_connection_working() {
    init_tracing();
    let auth_service = SigningKey::generate();
    let config = NetherNetConfig {
        trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
        infer_client_candidates: true,
        ..server_config(&auth_service)
    };
    let (listener, url) = start(config).await;
    let raw = raw_client().await;
    // The client looks like it is behind a NAT whose public address is 8.8.8.8:
    // the server adds an `srflx` candidate for it, and ICE still succeeds over
    // the real (loopback) path.
    let answer = reqwest::Client::new()
        .post(format!("{url}/v1/join/6"))
        .header("x-real-ip", "8.8.8.8")
        .body(sign_raw(&raw.offer, &auth_service))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    raw.pc
        .set_remote_description(
            RTCSessionDescription::answer(sdp::strip_identity(&answer)).unwrap(),
        )
        .await
        .unwrap();
    tokio::time::timeout(TIMEOUT, wait_event(&raw.reliable, true))
        .await
        .unwrap();
    let conn = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(conn.signaling_addr(), Some("8.8.8.8:0".parse().unwrap()));
    raw.pc.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stun_server_from_ice_servers_is_used() {
    let auth_service = SigningKey::generate();
    let (stun_addr, stun_requests) = spawn_stun_server().await;
    let config = NetherNetConfig {
        ice_servers: vec![IceServer::stun(format!("stun:{stun_addr}"))],
        ice_gathering_timeout: Duration::from_secs(3),
        ..server_config(&auth_service)
    };
    let (listener, url) = start(config).await;
    let client = NetherNetClient::new(client_config(Some(credentials(
        &auth_service,
        SigningKey::generate(),
    ))))
    .unwrap();

    let (conn, _) = tokio::time::timeout(TIMEOUT, client.connect(&url, "7"))
        .await
        .unwrap()
        .unwrap();
    assert!(
        stun_requests.load(Ordering::SeqCst) > 0,
        "the host contacted the configured STUN server while gathering"
    );
    let server_conn = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    conn.send(b"via stun-configured host").await.unwrap();
    let msg = tokio::time::timeout(TIMEOUT, server_conn.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&msg.payload[..], b"via stun-configured host");
    conn.close().await;
}
