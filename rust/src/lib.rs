//! L42 Token Handler — Rust backend for l42-cognito-passkey.
//!
//! Same Axum router runs in both Lambda and local dev contexts.
//! Detection via `AWS_LAMBDA_RUNTIME_API` env var.

pub mod cedar;
pub mod cognito;
pub mod config;
pub mod error;
pub mod middleware;
pub mod ocsf;
pub mod routes;
pub mod session;
pub mod types;

use axum::middleware::from_fn;
use axum::Router;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::cedar::engine::CedarState;
use crate::cognito::jwt::JwksCache;
use crate::config::Config;
use crate::session::AnyBackend;
use crate::session::middleware::{SessionLayer, session_middleware};

/// Shared application state available to all route handlers.
pub struct AppState {
    pub config: Config,
    pub http_client: reqwest::Client,
    pub jwks_cache: Arc<JwksCache>,
    pub cedar: Option<CedarState>,
    pub session_layer: Arc<SessionLayer<AnyBackend>>,
}

/// Build the Axum router with all middleware and routes.
///
/// The router is generic over the session backend, but for now we
/// only use `InMemoryBackend` (DynamoDB in Phase 5).
pub fn create_app(state: Arc<AppState>) -> Router {
    let session_layer = state.session_layer.clone();

    // CORS: allow single frontend origin with credentials
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(
            state.config.frontend_url.parse().unwrap(),
        ))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-l42-csrf"),
        ])
        .allow_credentials(true);

    // Routes that require CSRF
    let csrf_routes = Router::new()
        .route(
            "/auth/session",
            axum::routing::post(routes::session::create_session),
        )
        .route(
            "/auth/refresh",
            axum::routing::post(routes::refresh::refresh_tokens),
        )
        .route(
            "/auth/logout",
            axum::routing::post(routes::logout::logout),
        )
        .route(
            "/auth/authorize",
            axum::routing::post(routes::authorize::authorize),
        )
        .layer(from_fn(crate::middleware::csrf::require_csrf));

    // Routes without CSRF
    let open_routes = Router::new()
        .route("/health", axum::routing::get(routes::health::health))
        .route(
            "/auth/token",
            axum::routing::get(routes::token::get_token),
        )
        .route(
            "/auth/callback",
            axum::routing::get(routes::callback::oauth_callback),
        )
        .route("/auth/me", axum::routing::get(routes::me::me));

    Router::new()
        .merge(csrf_routes)
        .merge(open_routes)
        .layer(from_fn(move |req, next| {
            let layer = session_layer.clone();
            session_middleware(layer, req, next)
        }))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
