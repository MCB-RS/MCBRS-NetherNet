//! HTTP signaling endpoints (guide §4).
//!
//! * `GET  /v1/join`              → `200 application/json` [`ServerInfo`]
//! * `POST /v1/join/{networkId}`  → body: SDP offer, response: `200 application/sdp` answer
//!
//! The router only depends on the [`SignalingHandler`] trait, so the signaling
//! server can run in the same process as the WebRTC host ([`crate::NetherNetHost`])
//! or forward offers to remote hosts.
//!
//! Behind a reverse proxy (recommended for HTTPS, guide §5.2), list the proxy in
//! [`SignalingHandler::trusted_proxies`] so the real client address is taken
//! from `Forwarded` / `X-Forwarded-For` / `X-Real-IP`; see [`resolve_client_addr`].

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::net::TcpListener;

use crate::config::ServerInfo;
use crate::error::Error;

/// Maximum accepted SDP offer size.
pub const MAX_OFFER_SIZE: usize = 256 * 1024;

/// Maximum time allowed to receive the offer body (slowloris protection).
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound for a NetworkID (it is opaque, but must stay reasonable).
pub const MAX_NETWORK_ID_LEN: usize = 256;

/// Validates an opaque NetworkID (guide §9): non-empty, bounded length and no
/// control characters (it ends up in logs, where `\n` or ANSI escapes would
/// allow log injection). No other assumption is made about its format.
pub fn validate_network_id(network_id: &str) -> Result<(), String> {
    if network_id.is_empty()
        || network_id.len() > MAX_NETWORK_ID_LEN
        || network_id.chars().any(char::is_control)
    {
        return Err("invalid NetworkID".into());
    }
    Ok(())
}

/// An SDP offer received on `POST /v1/join/{networkId}`.
#[derive(Debug, Clone)]
pub struct OfferRequest {
    /// The client's NetworkID (opaque).
    pub network_id: String,
    /// Raw SDP offer, including the client `a=identity`.
    pub sdp: String,
    /// Address of the client that performed the request: the TCP peer, or the
    /// address reported by a trusted reverse proxy (port `0` when the proxy did
    /// not report one).
    pub signaling_addr: Option<SocketAddr>,
}

/// Failure of a signaling request, mapped to an HTTP status code.
#[derive(Debug, thiserror::Error)]
pub enum SignalingError {
    /// 400 – malformed request.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// 403 – the player is not allowed to join.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// 408 – the client did not send its request in time.
    #[error("request timeout: {0}")]
    RequestTimeout(String),
    /// 503 – the server is overloaded or shutting down.
    #[error("service unavailable: {0}")]
    Unavailable(String),
    /// 500 – anything else.
    #[error("internal error: {0}")]
    Internal(String),
}

impl SignalingError {
    /// HTTP status code returned to the client.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::RequestTimeout(_) => StatusCode::REQUEST_TIMEOUT,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<Error> for SignalingError {
    fn from(e: Error) -> Self {
        match e {
            Error::Sdp(_) | Error::Framing(_) | Error::Json(_) => Self::BadRequest(e.to_string()),
            Error::Identity(_) | Error::Unauthorized(_) => Self::Forbidden(e.to_string()),
            Error::Timeout(_) | Error::Closed => Self::Unavailable(e.to_string()),
            Error::MessageTooLarge { .. } => Self::BadRequest(e.to_string()),
            _ => Self::Internal(e.to_string()),
        }
    }
}

/// Backend of the signaling endpoints.
#[async_trait::async_trait]
pub trait SignalingHandler: Send + Sync + 'static {
    /// Returns the metadata served on `GET /v1/join`.
    async fn server_info(&self) -> ServerInfo;

    /// Handles one SDP offer and returns the complete, signed SDP answer.
    async fn handle_offer(&self, request: OfferRequest) -> Result<String, SignalingError>;

    /// Reverse proxies whose forwarding headers are trusted (none by default).
    fn trusted_proxies(&self) -> &[IpAddr] {
        &[]
    }
}

type SharedHandler = Arc<dyn SignalingHandler>;

/// Builds the axum router exposing the NetherNet signaling endpoints.
///
/// Serve it with `into_make_service_with_connect_info::<SocketAddr>()` to
/// make the client address available to the handler (as [`serve`] does).
pub fn router(handler: Arc<dyn SignalingHandler>) -> Router {
    Router::new()
        .route("/v1/join", get(get_join))
        .route("/v1/join/{network_id}", post(post_join))
        .with_state(handler)
}

/// Serves the signaling router on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    handler: Arc<dyn SignalingHandler>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(handler).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

async fn get_join(State(handler): State<SharedHandler>) -> Response {
    axum::Json(handler.server_info().await).into_response()
}

async fn post_join(
    State(handler): State<SharedHandler>,
    Path(network_id): Path<String>,
    request: Request,
) -> Response {
    let signaling_addr =
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| {
                resolve_client_addr(*peer, request.headers(), handler.trusted_proxies())
            });

    if let Some(ct) = request.headers().get(header::CONTENT_TYPE)
        && !ct.as_bytes().starts_with(b"application/sdp")
    {
        tracing::debug!(?ct, "offer with unexpected content-type, accepting anyway");
    }

    let read = axum::body::to_bytes(request.into_body(), MAX_OFFER_SIZE);
    let body = match tokio::time::timeout(BODY_READ_TIMEOUT, read).await {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return error_response(&SignalingError::BadRequest(
                "body too large or unreadable".into(),
            ));
        }
        Err(_) => {
            return error_response(&SignalingError::RequestTimeout(
                "offer body not received in time".into(),
            ));
        }
    };
    // `Vec::from(Bytes)` reuses the buffer when it is uniquely owned.
    let Ok(sdp) = String::from_utf8(Vec::from(body)) else {
        return error_response(&SignalingError::BadRequest("SDP is not UTF-8".into()));
    };

    let request = OfferRequest {
        network_id,
        sdp,
        signaling_addr,
    };
    let network_id = request.network_id.clone();
    match handler.handle_offer(request).await {
        Ok(answer) => {
            let mut response = Response::new(Body::from(answer));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/sdp"),
            );
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(e) => {
            tracing::info!(
                network_id = %network_id.escape_debug(),
                ?signaling_addr,
                "join refused: {e}"
            );
            error_response(&e)
        }
    }
}

fn error_response(error: &SignalingError) -> Response {
    let body = match error {
        // Internal details (WebRTC / I/O errors) are logged, not sent to clients.
        SignalingError::Internal(_) => "internal error".to_owned(),
        other => other.to_string(),
    };
    (error.status(), body).into_response()
}

/// Determines the real client address of a signaling request.
///
/// Forwarding headers are only honoured when the TCP `peer` is one of the
/// `trusted` proxies; otherwise `peer` is returned unchanged, so a client that
/// connects directly cannot spoof its address. With a trusted peer, the first
/// header present among `Forwarded` (RFC 7239), `X-Forwarded-For` and
/// `X-Real-IP` is read, and the chain is walked from the right, skipping
/// trusted proxies: the first untrusted hop is the client. Malformed or
/// obfuscated entries (`for=unknown`, `for=_hidden`) stop the walk and the
/// peer address is used. A hop without a port gets port `0`.
pub fn resolve_client_addr(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted: &[IpAddr],
) -> SocketAddr {
    let is_trusted = |ip: IpAddr| {
        trusted
            .iter()
            .any(|t| t.to_canonical() == ip.to_canonical())
    };
    if !is_trusted(peer.ip()) {
        return peer;
    }
    let Some(chain) = forwarded_chain(headers) else {
        return peer;
    };
    let mut leftmost = None;
    for hop in chain.iter().rev() {
        let Some(addr) = hop else {
            return peer;
        };
        if !is_trusted(addr.ip()) {
            return *addr;
        }
        leftmost = Some(*addr);
    }
    leftmost.unwrap_or(peer)
}

/// Hops reported by the first forwarding header present, left (client) to
/// right (closest proxy). `None` entries are unparsable hops.
fn forwarded_chain(headers: &HeaderMap) -> Option<Vec<Option<SocketAddr>>> {
    let joined = |name: &str| -> Option<String> {
        let values: Vec<&str> = headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        (!values.is_empty()).then(|| values.join(","))
    };
    if let Some(forwarded) = joined("forwarded") {
        let hops = forwarded
            .split(',')
            .filter_map(|element| {
                element.split(';').find_map(|pair| {
                    let (key, value) = pair.split_once('=')?;
                    key.trim()
                        .eq_ignore_ascii_case("for")
                        .then(|| parse_node(value.trim().trim_matches('"')))
                })
            })
            .collect::<Vec<_>>();
        return (!hops.is_empty()).then_some(hops);
    }
    if let Some(xff) = joined("x-forwarded-for") {
        return Some(xff.split(',').map(|h| parse_node(h.trim())).collect());
    }
    joined("x-real-ip").map(|ip| vec![parse_node(ip.trim())])
}

/// Parses `1.2.3.4`, `1.2.3.4:5678`, `2001:db8::1`, `[2001:db8::1]` or
/// `[2001:db8::1]:5678`.
fn parse_node(node: &str) -> Option<SocketAddr> {
    if let Ok(addr) = node.parse::<SocketAddr>() {
        return Some(addr);
    }
    let ip = node
        .strip_prefix('[')
        .and_then(|n| n.strip_suffix(']'))
        .unwrap_or(node);
    ip.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, value.parse().unwrap());
        }
        map
    }

    const PROXY: &str = "127.0.0.1:443";

    fn sa(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    fn resolve(peer: &str, pairs: &[(&'static str, &str)], trusted: &[&str]) -> SocketAddr {
        let trusted: Vec<IpAddr> = trusted.iter().map(|t| t.parse().unwrap()).collect();
        resolve_client_addr(peer.parse().unwrap(), &headers(pairs), &trusted)
    }

    #[test]
    fn untrusted_peer_cannot_spoof() {
        let addr = resolve(
            "8.8.8.8:5000",
            &[("x-forwarded-for", "1.2.3.4")],
            &["127.0.0.1"],
        );
        assert_eq!(addr, sa("8.8.8.8:5000"));
        let addr = resolve(PROXY, &[("x-forwarded-for", "1.2.3.4")], &[]);
        assert_eq!(addr, sa(PROXY));
    }

    #[test]
    fn x_forwarded_for_rightmost_untrusted_hop() {
        // 6.6.6.6 was written by the client itself; 9.9.9.9 is what our proxy saw.
        let addr = resolve(
            PROXY,
            &[("x-forwarded-for", "6.6.6.6, 9.9.9.9, 10.0.0.2")],
            &["127.0.0.1", "10.0.0.2"],
        );
        assert_eq!(addr, sa("9.9.9.9:0"));
    }

    #[test]
    fn forwarded_header_with_ports_and_ipv6() {
        let addr = resolve(
            PROXY,
            &[(
                "forwarded",
                r#"for="[2001:db8:cafe::17]:4711";proto=https;by=127.0.0.1"#,
            )],
            &["127.0.0.1"],
        );
        assert_eq!(addr, sa("[2001:db8:cafe::17]:4711"));
        let addr = resolve(
            PROXY,
            &[("forwarded", "For=192.0.2.60:1234, for=10.0.0.2")],
            &["127.0.0.1", "10.0.0.2"],
        );
        assert_eq!(addr, sa("192.0.2.60:1234"));
    }

    #[test]
    fn forwarded_takes_precedence_and_x_real_ip_fallback() {
        let addr = resolve(
            PROXY,
            &[("x-forwarded-for", "1.1.1.1"), ("forwarded", "for=2.2.2.2")],
            &["127.0.0.1"],
        );
        assert_eq!(addr.ip(), "2.2.2.2".parse::<IpAddr>().unwrap());
        let addr = resolve(PROXY, &[("x-real-ip", "3.3.3.3")], &["127.0.0.1"]);
        assert_eq!(addr, sa("3.3.3.3:0"));
    }

    #[test]
    fn malformed_or_obfuscated_hops_fall_back_to_peer() {
        for value in ["unknown", "_hidden", "not an ip"] {
            let addr = resolve(
                PROXY,
                &[("forwarded", &format!("for={value}"))],
                &["127.0.0.1"],
            );
            assert_eq!(addr, sa(PROXY), "{value}");
        }
        let addr = resolve(PROXY, &[], &["127.0.0.1"]);
        assert_eq!(addr, sa(PROXY));
    }

    #[test]
    fn ipv4_mapped_peer_matches_trusted_ipv4() {
        let addr = resolve(
            "[::ffff:127.0.0.1]:443",
            &[("x-real-ip", "4.4.4.4")],
            &["127.0.0.1"],
        );
        assert_eq!(addr, sa("4.4.4.4:0"));
    }

    #[test]
    fn network_id_validation() {
        assert!(validate_network_id("9876543210123456789").is_ok());
        assert!(validate_network_id("a1b2c3d4-guid-like").is_ok());
        assert!(validate_network_id("").is_err());
        assert!(validate_network_id(&"1".repeat(MAX_NETWORK_ID_LEN + 1)).is_err());
        assert!(validate_network_id("123\nINFO forged log line").is_err());
        assert!(validate_network_id("123\u{1b}[31m").is_err());
    }
}
