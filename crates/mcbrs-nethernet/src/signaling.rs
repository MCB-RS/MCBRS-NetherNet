//! HTTP signaling endpoints (guide §4).
//!
//! * `GET  /v1/join`              → `200 application/json` [`ServerInfo`]
//! * `POST /v1/join/{networkId}`  → body: SDP offer, response: `200 application/sdp` answer
//!
//! The router only depends on the [`SignalingHandler`] trait, so the signaling
//! server can run in the same process as the WebRTC host ([`crate::NetherNetHost`])
//! or forward offers to remote hosts.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::net::TcpListener;

use crate::config::ServerInfo;
use crate::error::Error;

/// Maximum accepted SDP offer size.
pub const MAX_OFFER_SIZE: usize = 256 * 1024;

/// An SDP offer received on `POST /v1/join/{networkId}`.
#[derive(Debug, Clone)]
pub struct OfferRequest {
    /// The client's NetworkID (opaque).
    pub network_id: String,
    /// Raw SDP offer, including the client `a=identity`.
    pub sdp: String,
    /// Address of the HTTP peer.
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
    let signaling_addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);

    if let Some(ct) = request.headers().get(header::CONTENT_TYPE)
        && !ct.as_bytes().starts_with(b"application/sdp")
    {
        tracing::debug!(?ct, "offer with unexpected content-type, accepting anyway");
    }

    let body = match axum::body::to_bytes(request.into_body(), MAX_OFFER_SIZE).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(SignalingError::BadRequest(
                "body too large or unreadable".into(),
            ));
        }
    };
    let sdp = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(_) => return error_response(SignalingError::BadRequest("SDP is not UTF-8".into())),
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
            tracing::info!(%network_id, ?signaling_addr, "join refused: {e}");
            error_response(e)
        }
    }
}

fn error_response(error: SignalingError) -> Response {
    (error.status(), error.to_string()).into_response()
}
