//! Minimal NetherNet server: accepts Minecraft clients over WebRTC and echoes
//! every payload back. It is a transport demo – no game protocol is spoken.
//!
//! ```text
//! cargo run --example nethernet_server -- [HTTP_ADDR] [PUBLIC_IP]
//! cargo run --example nethernet_server -- 0.0.0.0:8080 203.0.113.50
//! ```
//!
//! Environment:
//! * `NETHERNET_KEY`  – path of the operator key (default `nethernet_server_key.pem`)
//! * `RUST_LOG`       – log filter (default `info`)

use std::net::IpAddr;

use mcbrs_nethernet::{NetherNetConfig, NetherNetListener, ServerIdentity, ServerInfo};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let mut args = std::env::args().skip(1);
    let http_addr = args.next().unwrap_or_else(|| "0.0.0.0:8080".into());
    let public_ips: Vec<IpAddr> = args.map(|a| a.parse()).collect::<Result<_, _>>()?;

    let key_path =
        std::env::var("NETHERNET_KEY").unwrap_or_else(|_| "nethernet_server_key.pem".into());
    let identity = ServerIdentity::load_or_generate(&key_path)?
        .with_domain("mcbrs.local")
        .with_issuer("MCBRS NetherNet demo");

    let config = NetherNetConfig {
        // Demo only: no client authentication. Use ClientAuth::Required with a
        // TokenVerifier holding the Minecraft auth service keys in production.
        public_ips,
        ..Default::default()
    };
    let info = ServerInfo {
        name: "MCBRS NetherNet demo".into(),
        ..Default::default()
    };

    let listener = NetherNetListener::bind(&http_addr, config, identity, info).await?;
    println!(
        "NetherNet signaling : http://{}/v1/join",
        listener.local_addr()
    );
    println!("Operator key        : {key_path}");
    println!(
        "Key fingerprint     : {}",
        listener.host().identity().key_fingerprint()
    );
    println!("Press Ctrl+C to stop.");

    loop {
        tokio::select! {
            conn = listener.accept() => {
                let Some(conn) = conn else { break };
                let host = listener.host().clone();
                host.update_server_info(|i| i.players += 1);
                tokio::spawn(async move {
                    tracing::info!(network_id = conn.network_id(), "client connected");
                    while let Some(msg) = conn.recv().await {
                        tracing::info!(
                            network_id = conn.network_id(),
                            channel = ?msg.channel,
                            bytes = msg.payload.len(),
                            "message received"
                        );
                        if let Err(e) = conn.send_on(msg.channel, &msg.payload).await {
                            tracing::warn!("send failed: {e}");
                            break;
                        }
                    }
                    tracing::info!(network_id = conn.network_id(), "client disconnected");
                    host.update_server_info(|i| i.players = i.players.saturating_sub(1));
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    listener.shutdown();
    Ok(())
}
