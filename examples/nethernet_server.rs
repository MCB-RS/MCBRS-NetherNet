//! NetherNet test server: accepts Minecraft clients over WebRTC and logs
//! everything that happens on the transport (join attempts, player identity,
//! data channel traffic). It is a transport test bench – no game protocol is
//! spoken, so a real client connects, sends its first packets, then gives up
//! waiting for a game response.
//!
//! ```text
//! cargo run --example nethernet_server -- [HTTP_ADDR] [PUBLIC_IP...]
//! cargo run --example nethernet_server -- 0.0.0.0:8080 203.0.113.50
//! ```
//!
//! Environment (all optional):
//! * `NETHERNET_KEY`             – operator key path (default `nethernet_server_key.pem`)
//! * `NETHERNET_AUTH`            – `off` (default) or `insecure`: validate the player
//!   assertion with an unverified token signature, and log the player claims
//! * `NETHERNET_ECHO`            – `1` to send every received payload back
//! * `NETHERNET_STUN`            – comma-separated `stun:` URLs
//! * `NETHERNET_TRUSTED_PROXIES` – comma-separated reverse proxy IPs
//! * `NETHERNET_INFER`           – `1` to enable client candidate inference
//! * `NETHERNET_UDP_BIND`         – comma-separated local IPs (or `ip:port`) for
//!   WebRTC, e.g. your LAN IP, to skip VPN / virtual adapters (default: all)
//! * `NETHERNET_NAME`, `NETHERNET_PROTOCOL`, `NETHERNET_VERSION`,
//!   `NETHERNET_MAX_PLAYERS`     – values served on `GET /v1/join`
//! * `RUST_LOG`                  – log filter (default `info,mcbrs_nethernet=debug`)

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;

use mcbrs_nethernet::{
    Authorizer, ClientAuth, IceServer, InsecureTokenDecoder, JoinRequest, NetherNetConfig,
    NetherNetListener, ServerIdentity, ServerInfo,
};
use tracing_subscriber::EnvFilter;

/// Logs every join attempt (before any WebRTC resource is allocated) and accepts it.
struct LoggingAuthorizer;

#[async_trait::async_trait]
impl Authorizer for LoggingAuthorizer {
    async fn authorize(&self, request: &JoinRequest) -> Result<(), String> {
        match &request.identity {
            Some(player) => {
                let claim_names: Vec<&String> = player
                    .claims
                    .as_object()
                    .map(|m| m.keys().collect())
                    .unwrap_or_default();
                tracing::info!(
                    network_id = %request.network_id,
                    from = ?request.signaling_addr,
                    auth_domain = %player.domain,
                    xuid = ?player.xuid(),
                    playfab_id = ?player.playfab_id(),
                    uuid = ?player.uuid(),
                    name = ?player.display_name(),
                    cpk_alg = player.public_key.alg(),
                    ?claim_names,
                    "join attempt (player identity verified with an UNVERIFIED token signature)"
                );
            }
            None => tracing::info!(
                network_id = %request.network_id,
                from = ?request.signaling_addr,
                "join attempt (no player identity checked)"
            ),
        }
        Ok(())
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn env_list(name: &str) -> Vec<String> {
    env(name)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn env_flag(name: &str) -> bool {
    matches!(env(name).as_deref(), Some("1" | "true" | "yes" | "on"))
}

/// Parses `NETHERNET_UDP_BIND` entries: `ip` (ephemeral port) or `ip:port`.
fn parse_bind(entry: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    entry
        .parse::<SocketAddr>()
        .or_else(|_| entry.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 0)))
}

/// The address of the interface used for outgoing traffic (no packet is sent).
fn lan_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// First bytes of a payload in hex, for packet identification.
fn hex_preview(data: &[u8]) -> String {
    let shown: Vec<String> = data.iter().take(16).map(|b| format!("{b:02x}")).collect();
    let more = if data.len() > 16 { " .." } else { "" };
    format!("{}{more}", shown.join(" "))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,mcbrs_nethernet=debug".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let http_addr = args.next().unwrap_or_else(|| "0.0.0.0:8080".into());
    let public_ips: Vec<IpAddr> = args.map(|a| a.parse()).collect::<Result<_, _>>()?;

    let key_path = env("NETHERNET_KEY").unwrap_or_else(|| "nethernet_server_key.pem".into());
    let identity = ServerIdentity::load_or_generate(&key_path)?
        .with_domain("mcbrs.local")
        .with_issuer("MCBRS NetherNet test server");

    let insecure_auth = env("NETHERNET_AUTH").as_deref() == Some("insecure");
    let client_auth = if insecure_auth {
        // Checks the whole assertion except the auth service signature of the
        // GameServerToken (its public keys are not documented).
        ClientAuth::Optional(Arc::new(InsecureTokenDecoder))
    } else {
        ClientAuth::Disabled
    };
    let echo = env_flag("NETHERNET_ECHO");
    let udp_bind: Vec<SocketAddr> = env_list("NETHERNET_UDP_BIND")
        .iter()
        .map(|e| parse_bind(e))
        .collect::<Result<_, _>>()?;
    let defaults_config = NetherNetConfig::default();
    let config = NetherNetConfig {
        udp_bind_addrs: if udp_bind.is_empty() {
            defaults_config.udp_bind_addrs
        } else {
            udp_bind
        },
        client_auth,
        authorizer: Some(Arc::new(LoggingAuthorizer)),
        public_ips: public_ips.clone(),
        ice_servers: env_list("NETHERNET_STUN")
            .into_iter()
            .map(IceServer::stun)
            .collect(),
        trusted_proxies: env_list("NETHERNET_TRUSTED_PROXIES")
            .iter()
            .map(|ip| ip.parse())
            .collect::<Result<_, _>>()?,
        infer_client_candidates: env_flag("NETHERNET_INFER"),
        ..Default::default()
    };
    let defaults = ServerInfo::default();
    let info = ServerInfo {
        name: env("NETHERNET_NAME").unwrap_or_else(|| "MCBRS NetherNet test".into()),
        protocol: env("NETHERNET_PROTOCOL").map_or(Ok(defaults.protocol), |v| v.parse())?,
        version: env("NETHERNET_VERSION").unwrap_or(defaults.version),
        max_players: env("NETHERNET_MAX_PLAYERS")
            .map_or(Ok(defaults.max_players), |v| v.parse())?,
        ..defaults
    };

    let listener =
        NetherNetListener::bind(&http_addr, config.clone(), identity, info.clone()).await?;
    let port = listener.local_addr().port();

    println!();
    println!("=== MCBRS NetherNet test server ===");
    println!("Signaling (this PC) : http://127.0.0.1:{port}");
    if let Some(ip) = lan_ip() {
        println!("Signaling (LAN)     : http://{ip}:{port}");
    }
    for ip in &public_ips {
        println!("Signaling (public)  : http://{ip}:{port}");
    }
    println!(
        "Server info         : {} | protocol {} | version {}",
        info.name, info.protocol, info.version
    );
    println!(
        "Player auth         : {}",
        if insecure_auth {
            "insecure (log claims)"
        } else {
            "off"
        }
    );
    println!("Echo payloads       : {}", if echo { "on" } else { "off" });
    println!("WebRTC UDP bind     : {:?}", config.udp_bind_addrs);
    println!("STUN servers        : {}", config.ice_servers.len());
    println!("Trusted proxies     : {:?}", config.trusted_proxies);
    println!("Candidate inference : {}", config.infer_client_candidates);
    println!("Operator key        : {key_path}");
    println!(
        "Key fingerprint     : {}",
        listener.host().identity().key_fingerprint()
    );
    println!("Press Ctrl+C to stop.");
    println!();

    loop {
        tokio::select! {
            conn = listener.accept() => {
                let Some(conn) = conn else { break };
                let host = listener.host().clone();
                host.update_server_info(|i| i.players += 1);
                tokio::spawn(async move {
                    let id = conn.network_id().to_owned();
                    tracing::info!(network_id = %id, max_message_size = conn.max_message_size(), "DATA CHANNELS OPEN - client connected");
                    let mut count = 0u64;
                    while let Some(msg) = conn.recv().await {
                        count += 1;
                        tracing::info!(
                            network_id = %id,
                            channel = ?msg.channel,
                            bytes = msg.payload.len(),
                            head = %hex_preview(&msg.payload),
                            "message #{count} received"
                        );
                        if echo && let Err(e) = conn.send_on(msg.channel, &msg.payload).await {
                            tracing::warn!("send failed: {e}");
                            break;
                        }
                    }
                    tracing::info!(network_id = %id, messages = count, "client disconnected");
                    host.update_server_info(|i| i.players = i.players.saturating_sub(1));
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    listener.shutdown();
    Ok(())
}
