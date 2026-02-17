//! CSRF validation: require `X-L42-CSRF: 1` header on state-changing requests.
//!
//! Mirrors `app/dependencies.py::require_csrf()`.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;

/// Axum middleware that requires the `X-L42-CSRF: 1` header.
pub async fn require_csrf(req: Request, next: Next) -> Result<Response, impl IntoResponse> {
    if req.headers().get("x-l42-csrf").and_then(|v| v.to_str().ok()) != Some("1") {
        return Err(AppError::CsrfFailed);
    }
    Ok(next.run(req).await)
}
