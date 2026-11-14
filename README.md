# MCBRS-NetherNet

A Rust implementation of **NetherNet**, the WebRTC-based transport used by Minecraft
Bedrock, following the *NetherNet HTTP Signaling* partner guide. It provides both sides:
a **host** (server) and a **client**.

MCBRS-NetherNet does one thing: it establishes NetherNet connections and moves their
data. It handles HTTP signaling, WebRTC negotiation, identity assertions and message
framing. **It does not implement the game protocol**: no Bedrock packets, worlds, blocks,
entities or physics. You send and receive raw bytes; interpreting them is up to your
server or client.

## Features

- **HTTP signaling**: `GET /v1/join` (server info) and `POST /v1/join/{networkId}`
  (SDP offer → SDP answer) in a single round trip.
- **WebRTC** (via [webrtc-rs](https://github.com/webrtc-rs/webrtc)): UDP only,
  `max-bundle`, full ICE (no trickle). STUN/TURN servers are optional.
- **Both data channels**: `ReliableDataChannel` (ordered, reliable) and
  `UnreliableDataChannel` (unordered, `maxRetransmits = 0`).
- **NetherNet framing**: 1-byte header, automatic fragmentation and reassembly on the
  reliable channel.
- **Player identity** (server side): validation of the client `a=identity` assertion,
  i.e. the auth token plus the signature over the DTLS fingerprints.
- **Operator identity**: every answer is signed with the operator key (self-signed
  ES384 JWT), as the client requires. The client side verifies it and supports Trust On
  First Use.
- **Server policies**: an `Authorizer` hook (allowlists, bans, player limits,
  rate limiting...) that runs before any WebRTC resource is allocated.
- **Deployment helpers**: trusted reverse proxies, static `srflx` candidates,
  STUN/TURN, and client candidate inference.
- **Hardening**: bounded memory per connection, timeouts on every step, and no
  `unsafe` code.

## Installation

```toml
[dependencies]
mcbrs-nethernet = { git = "https://github.com/MCB-RS/MCBRS-NetherNet" }
tokio = { version = "1", features = ["full"] }
```

Minimum supported Rust version: **1.88** (edition 2024). The client's HTTPS support uses
rustls.

## Quick start: server

```rust
use mcbrs_nethernet::{NetherNetConfig, NetherNetListener, ServerIdentity, ServerInfo};

#[tokio::main]
async fn main() -> mcbrs_nethernet::Result<()> {
    // Operator key: generated on first start, then reused.
    let identity = ServerIdentity::load_or_generate("nethernet_server_key.pem")?;

    let listener = NetherNetListener::bind(
        "0.0.0.0:8080", // HTTP signaling address
        NetherNetConfig::default(),
        identity,
        ServerInfo { name: "My server".into(), ..Default::default() },
    )
    .await?;

    while let Some(conn) = listener.accept().await {
        tokio::spawn(async move {
            println!("{} connected", conn.network_id());
            while let Some(msg) = conn.recv().await {
                // msg.channel: Channel::Reliable or Channel::Unreliable
                // msg.payload: the bytes sent by the client
                let _ = conn.send(&msg.payload).await;
            }
        });
    }
    Ok(())
}
```

A complete echo server is included:

```bash
cargo run --example nethernet_server -- 0.0.0.0:8080
```

You can pass public IPs as extra arguments, for example
`-- 0.0.0.0:8080 203.0.113.50`. The `NETHERNET_KEY` environment variable sets the key
file path.

## Quick start: client

```rust
use mcbrs_nethernet::{NetherNetClient, NetherNetClientConfig};

#[tokio::main]
async fn main() -> mcbrs_nethernet::Result<()> {
    let client = NetherNetClient::new(NetherNetClientConfig::default())?;

    let info = client.server_info("https://play.example.com").await?;
    println!("{}: {}/{} players", info.name, info.players, info.max_players);

    let (conn, server) = client.connect("https://play.example.com", "1234567890").await?;
    println!("operator key: {}", server.key_fingerprint());
    conn.send(b"hello").await?;
    Ok(())
}
```

`connect` follows the client flow of the guide:

1. It creates the PeerConnection (UDP only, `max-bundle`, full ICE) and both data
   channels.
2. It gathers every ICE candidate. If `credentials` are set, it adds a signed
   `a=identity`.
3. It sends a single `POST /v1/join/{networkId}`.
4. It verifies the server assertion, then applies your `ServerTrust` policy.
5. It applies the cleaned answer and returns once the data channels are open.

To authenticate, provide `ClientCredentials`: the `GameServerToken` issued by the
Minecraft auth service plus the `SigningKey` matching its `cpk` claim.

### Trusting the server (TOFU)

`NetherNetClientConfig::server_trust` decides whether a verified operator key is
accepted:

- `AcceptAnyServer` (default): accepts any structurally valid assertion. Use it for
  HTTPS signaling, where TLS already authenticates the server.
- `TrustOnFirstUse`: implements the client's §5.2 behavior.
  - HTTPS is accepted without a prompt.
  - Over plaintext HTTP, a known key is accepted silently. An unknown key is passed to
    your prompt callback, then pinned if accepted.
  - Pins are RFC 7638 thumbprints. Persist them with `pins()` / `with_pins()`.
- Your own `ServerTrust` implementation.

## API overview

| Type | Role |
|---|---|
| `NetherNetListener` | All-in-one server: HTTP signaling server + WebRTC host. `bind()`, `accept()`, `shutdown()`. |
| `NetherNetHost` | The WebRTC host alone. It implements `SignalingHandler`, so you can mount it in your own HTTP server or behind a separate signaling service. |
| `NetherNetClient` | The connecting side: `server_info()` and `connect()`. |
| `NetherNetConnection` | An established connection (either side): `recv()`, `send()`, `send_unreliable()`, `send_on()`, `close()`, `network_id()`, `identity()`. |
| `ServerIdentity` | Operator key (P-384): generate, load/save as PEM, sign answers, key fingerprint. |
| `ServerInfo` | Body of `GET /v1/join`. Update it at runtime with `host().update_server_info(...)`. |
| `ClientAuth` / `TokenVerifier` | Player identity validation: `Disabled`, `Optional(verifier)` or `Required(verifier)`. Built-in verifiers: `JwkSetVerifier` and `InsecureTokenDecoder` (development only). |
| `Authorizer` | Async hook that accepts or refuses a join (HTTP 403). |
| `IceServer` | A STUN or TURN server. |

Low-level modules can be used on their own: `framing` (message framing), `sdp`
(`a=identity`, `a=fingerprint`, candidates), `identity` (JWT, detached JWS, canonical
JSON).

### Sending messages

- `send()` uses the reliable channel. A message larger than one SCTP message is
  fragmented automatically, into up to 256 fragments.
- `send_unreliable()` uses the unreliable channel, which never fragments. Oversized
  messages are refused with `Error::MessageTooLarge`. If the peer did not open that
  channel, the message goes over the reliable one.
- The fragment size is `min(max_outgoing_message_size, peer a=max-message-size)`. Offers
  and answers that advertise less than 1024 bytes are rejected.

## Server-side policies with `Authorizer`

The `Authorizer` hook runs for every join attempt, after the player identity was
validated and before any WebRTC resource is allocated. It receives a `JoinRequest`:
`network_id`, `signaling_addr` (the real client address, see below) and `identity`
(validated claims). This is where a server or its plugins implement allowlists, bans,
player limits or **per-IP rate limiting**. The crate deliberately does not hard-code
such policies.

```rust
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mcbrs_nethernet::{Authorizer, JoinRequest};

/// At most 5 join attempts per IP address and per minute.
#[derive(Default)]
struct RateLimit(Mutex<HashMap<IpAddr, (Instant, u32)>>);

#[async_trait::async_trait]
impl Authorizer for RateLimit {
    async fn authorize(&self, request: &JoinRequest) -> Result<(), String> {
        let Some(addr) = request.signaling_addr else { return Ok(()) };
        let mut attempts = self.0.lock().unwrap();
        let now = Instant::now();
        let (since, count) = attempts.entry(addr.ip()).or_insert((now, 0));
        if now.duration_since(*since) > Duration::from_secs(60) {
            (*since, *count) = (now, 0);
        }
        *count += 1;
        if *count > 5 {
            return Err("too many join attempts".into());
        }
        Ok(())
    }
}

// let config = NetherNetConfig { authorizer: Some(Arc::new(RateLimit::default())), ..Default::default() };
```

## Deployment

### HTTPS and trusted reverse proxies

The guide recommends serving signaling over **HTTPS**. Over HTTPS the client trusts the
TLS certificate and never shows the player a trust prompt. The usual setup is a reverse
proxy (Caddy, nginx, ...) in front of the HTTP port.

Add the proxy to `trusted_proxies` so that `signaling_addr` (in `OfferRequest` and in
`JoinRequest`, which the `Authorizer` receives) holds the real player address:

```rust
let config = NetherNetConfig {
    trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
    ..Default::default()
};
```

How the address is resolved:

- Forwarding headers are honored **only** when the TCP peer is a trusted proxy. A client
  that connects directly cannot spoof its address.
- The first header present is used, in this order: `Forwarded` (RFC 7239),
  `X-Forwarded-For`, `X-Real-IP`.
- The chain is walked from the right, skipping trusted proxies. The first untrusted hop
  is the client.
- Malformed or obfuscated entries make the resolver fall back to the TCP peer address.
- When the proxy does not report a port, the port is `0`.

### Operator key

Keep `nethernet_server_key.pem` secret and stable, and share it across your whole fleet:
player trust is tied to this key, not to a host name or an IP address. Rotating it
re-prompts every player who connects over plaintext HTTP. If you accept plaintext HTTP,
publish `ServerIdentity::key_fingerprint()` on a page your players already trust.

### NAT traversal

The host's answer must contain at least one candidate the client can reach. Each
connection uses its own ephemeral UDP ports, so allow inbound UDP. Then pick one of the
following:

- **`public_ips`** (1:1 NAT, cloud VMs): your public IPs are advertised as `srflx`
  candidates. This adds no latency.
- **`ice_servers`**: STUN servers (`stun:`) let the host discover its `srflx` candidate,
  and TURN servers (`turn:`, `turns:`, with `username` and `credential`) provide `relay`
  candidates.

  ```rust
  use mcbrs_nethernet::IceServer;

  let config = NetherNetConfig {
      ice_servers: vec![
          IceServer::stun("stun:stun.example.com:3478"),
          IceServer::turn("turn:turn.example.com:3478?transport=udp", "user", "secret"),
      ],
      ..Default::default()
  };
  ```

  Full ICE waits for every configured server before answering, which adds latency, and
  the guide recommends against STUN/TURN for HTTP signaling. Use them only when needed.
  STUN servers cannot be combined with `public_ips`. `NetherNetClientConfig` has the
  same `ice_servers` option.
- **`infer_client_candidates`** (off by default): the Minecraft client only gathers
  `host` candidates. When every candidate in an offer is non-routable (client behind a
  NAT) and the signaling request came from a routable address, the host adds an `srflx`
  candidate built from that address and the port of the client's `host` candidate. This
  helps hole punching when the client's NAT preserves ports, and it costs nothing
  otherwise. Combine it with `trusted_proxies` when signaling goes through a proxy.

## Server configuration

| `NetherNetConfig` field | Default | Description |
|---|---|---|
| `client_auth` | `Disabled` | Player identity validation. |
| `authorizer` | `None` | Policy hook called for every join attempt. |
| `udp_bind_addrs` | `0.0.0.0:0` | Local UDP addresses for WebRTC (port 0 = ephemeral). |
| `public_ips` | `[]` | Public IPs advertised as `srflx` candidates (1:1 NAT). |
| `ice_servers` | `[]` | STUN/TURN servers. |
| `trusted_proxies` | `[]` | Reverse proxies whose forwarding headers are trusted. |
| `infer_client_candidates` | `false` | Infer a client candidate from the signaling address. |
| `include_loopback_candidates` | `false` | Also advertise `127.0.0.1` (local tests). |
| `max_outgoing_message_size` | 65 536 | Largest SCTP message sent, header included (≤ 262 144). |
| `max_incoming_message_size` | 16 MiB | Largest reassembled incoming message. |
| `max_buffered_incoming_bytes` | 32 MiB | Received bytes waiting for `recv()`. Beyond this, the reliable channel slows the peer down and unreliable messages are dropped. |
| `send_buffer_limit` | 4 MiB | Sent but unacknowledged bytes per channel. Beyond this, `send()` waits. |
| `ice_gathering_timeout` | 5 s | Maximum ICE gathering time before answering. |
| `connect_timeout` | 30 s | Maximum time between the answer and the data channels opening. |
| `max_pending_connections` | 64 | Concurrent negotiations. Beyond this, the server answers HTTP 503. |
| `accept_backlog` | 128 | Established connections waiting for `accept()`. |

`NetherNetClientConfig` provides `credentials`, `server_trust`, `ice_servers`,
`udp_bind_addrs`, the same size and buffer limits, and `http_timeout`,
`ice_gathering_timeout` and `connect_timeout`.

## How it works

```
Minecraft client / NetherNetClient          MCBRS-NetherNet host
     │  GET /v1/join                               │
     │────────────────────────────────────────────►│  server info (JSON)
     │  POST /v1/join/{networkId}                  │
     │  (SDP offer + player identity)              │  1. verify identity, run the Authorizer
     │────────────────────────────────────────────►│  2. create the PeerConnection, gather ICE
     │  200 OK (signed SDP answer)                 │  3. sign the answer with the operator key
     │◄────────────────────────────────────────────│
     │                                             │
     │═════════ ICE → DTLS → SCTP (direct UDP) ════│  4. both data channels open
     │                                             │  5. NetherNetConnection delivered
```

## Scope: no LAN discovery

Bedrock also has LAN discovery and signaling over UDP port 7551. That protocol is not
part of the *NetherNet HTTP Signaling* guide this crate implements, and it is not
publicly specified: implementing it would mean reverse engineering. It would also need
its own sockets, encryption and lifecycle. This crate therefore stays strictly scoped to
the documented HTTP signaling transport. A LAN discovery layer, if ever needed, belongs
in a separate crate that hands its connections to the same WebRTC and framing code.

## Known limitations

- **Tested against the guide, not against the real Minecraft client yet.** The test suite
  uses `NetherNetClient` and a raw webrtc-rs peer that follow the official
  documentation.
- **Auth service keys**: the guide documents neither the Minecraft auth service public
  keys nor the exact `GameServerToken` claims. `cpk` is accepted as a JWK or as base64
  SPKI. The player claim names (`xid`, `pfid`, `uuid`...) are best guesses, and
  `ClientIdentity::claim()` gives access to any other claim.
- **No built-in TLS on the server side**: use a reverse proxy, together with
  `trusted_proxies`.
- **No fixed UDP port**: each connection has its own ephemeral ports.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo doc --no-deps
```

The end-to-end tests (`tests/end_to_end.rs`) start real hosts and connect with
`NetherNetClient`, plus a raw WebRTC peer for hostile traffic. They cover the full
signaling flow, both identities, TOFU, fragmentation in both directions, rejected
offers, extra data channels, trusted proxies, candidate inference and a STUN server.

```
src/
├── lib.rs           entry point, re-exports
├── signaling.rs     HTTP endpoints (axum), trusted proxy resolution
├── host.rs          WebRTC host, NetherNetListener
├── client.rs        NetherNetClient, TOFU
├── peer.rs          PeerConnection setup shared by host and client
├── conn.rs          NetherNetConnection, data channels
├── framing.rs       header, fragmentation, reassembly
├── sdp.rs           a=identity, a=fingerprint, max-message-size, candidates
├── config.rs        NetherNetConfig, IceServer, ServerInfo, ClientAuth, Authorizer
├── error.rs         Error type
└── identity/        JWT / detached JWS, canonical JSON, client and server identities
examples/nethernet_server.rs
tests/end_to_end.rs
```

> **Windows**: if the project path is very long (more than 260 characters in total), the
> MSVC linker fails with `LNK1104`. Move the project to a short path, or point
> `CARGO_TARGET_DIR` to a short directory.

## Licensing & Legal Disclaimer

`mcbrs-nethernet` is an original, independent implementation released under the
**MIT License** (see [LICENSE](LICENSE)), written from the *NetherNet HTTP Signaling* guide. No
proprietary file belonging to Mojang AB or Microsoft Corporation is distributed in this
repository or in the crate.

**NOT AN OFFICIAL MINECRAFT PRODUCT. NOT APPROVED BY OR ASSOCIATED WITH MOJANG OR MICROSOFT.**

- **Publisher / Owner:** MCB-RS (solely responsible for this software; Mojang AB and
  Microsoft Corporation are not responsible for this product).
- **Contact:** [GitHub Issues](https://github.com/MCB-RS/MCBRS-NetherNet/issues) or the
  security contact of the [MCB-RS organization](https://github.com/MCB-RS).

"Minecraft" is a trademark of Mojang Synergies AB. It is used here only to describe
compatibility.
