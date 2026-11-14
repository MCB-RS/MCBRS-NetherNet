//! NetherNet test client: checks a server end to end (server info, signaling,
//! server assertion, data channels, a round of messages).
//!
//! ```text
//! cargo run --example nethernet_client -- http://127.0.0.1:8080 [--fake-identity]
//! ```
//!
//! `--fake-identity` adds a player assertion signed by a throwaway "auth
//! service" key: only servers that do not verify the token signature (for
//! example `nethernet_server` with `NETHERNET_AUTH=insecure`) accept it.

use std::time::Duration;

use mcbrs_nethernet::identity::jose::{self, SigningKey};
use mcbrs_nethernet::{ClientCredentials, NetherNetClient, NetherNetClientConfig, TrustOnFirstUse};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:8080".into());
    let fake_identity = args.any(|a| a == "--fake-identity");

    let credentials = fake_identity.then(|| {
        let auth_service = SigningKey::generate();
        let key = SigningKey::generate();
        let token = jose::sign_jwt(
            &auth_service,
            &serde_json::json!({
                "xid": "2535400000000001",
                "pfid": "TESTPLAYFAB0001",
                "displayName": "MCBRS-TestClient",
                "cpk": key.verifying_key().to_jwk(),
                "exp": jose::unix_now() + 600,
            }),
        );
        ClientCredentials::new("fake.auth.mcbrs.local", token, key)
    });
    let trust = TrustOnFirstUse::new(|request| {
        println!(
            "TOFU: accepting operator key {} (iss = {})",
            request.identity.key_fingerprint(),
            request.identity.claims["iss"]
        );
        true
    });
    let client = NetherNetClient::new(NetherNetClientConfig {
        credentials,
        server_trust: Arc::new(trust),
        ..Default::default()
    })?;

    let info = client.server_info(&url).await?;
    println!("server info: {info:?}");

    let network_id = format!("{}", jose::unix_now());
    let (conn, server) = client.connect(&url, &network_id).await?;
    println!(
        "connected as {network_id}: operator key {} (domain {}), fragments of {} bytes",
        server.key_fingerprint(),
        server.domain,
        conn.max_message_size()
    );

    let big = vec![0xABu8; 200_000];
    conn.send(b"hello from nethernet_client").await?;
    conn.send(&big).await?;
    conn.send_unreliable(b"unreliable ping").await?;
    println!("sent 3 messages (one of {} bytes, fragmented)", big.len());

    // Print whatever comes back (the test server echoes with NETHERNET_ECHO=1).
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(2), conn.recv()).await {
        println!("received {} bytes on {:?}", msg.payload.len(), msg.channel);
    }
    conn.close().await;
    println!("closed");
    Ok(())
}
