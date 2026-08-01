//! Application error types with Axum response mapping.
//!
//! Each variant maps to a specific HTTP status + JSON body, matching the
//! exact responses matching the Token Handler protocol spec.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("Token expired")]
    TokenExpired,

    #[error("CSRF validation failed")]
    CsrfFailed,

    #[error("Missing or invalid action")]
    BadRequest(String),

    #[error("Token verification failed")]
    TokenVerificationFailed,

    #[error("No refresh token")]
    NoRefreshToken,

    #[error("Refresh failed: {0}")]
    RefreshFailed(String),

    #[error("Authorization engine not available")]
    CedarUnavailable,

    #[error("Authorization evaluation failed")]
    AuthorizationError(String),

    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("Failed to decode token")]
    TokenDecodeFailed,

    #[error("Credential rejected: {0}")]
    CredentialRejected(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AppError::NotAuthenticated => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "Not authenticated"}),
            ),
            AppError::TokenExpired => (StatusCode::UNAUTHORIZED, json!({"error": "Token expired"})),
            AppError::CsrfFailed => (
                StatusCode::FORBIDDEN,
                json!({
                    "error": "CSRF validation failed",
                    "message": "Missing X-L42-CSRF header"
                }),
            ),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, json!({"error": msg})),
            AppError::TokenVerificationFailed => (
                StatusCode::FORBIDDEN,
                json!({"error": "Token verification failed"}),
            ),
            AppError::NoRefreshToken => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "No refresh token"}),
            ),
            // Deliberately surfaced: this describes the state of the caller's OWN
            // refresh token (e.g. "revoked", "expired") and auth.js shows it on
            // the session-expiry path. It carries no pool/client internals —
            // unlike TokenExchangeFailed/Internal below, which are scrubbed.
            AppError::RefreshFailed(msg) => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "Refresh failed", "message": msg}),
            ),
            AppError::CedarUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "Authorization engine not available", "authorized": false}),
            ),
            AppError::AuthorizationError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"authorized": false, "error": "Authorization evaluation failed"}),
            ),
            AppError::CredentialRejected(msg) => (
                StatusCode::FORBIDDEN,
                json!({"allowed": false, "reason": msg}),
            ),
            // Upstream (Cognito) detail is logged, never returned — the raw text
            // can carry pool/client identifiers and internal failure detail.
            AppError::TokenExchangeFailed(msg) => {
                tracing::error!("Token exchange failed: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "Token exchange failed"}),
                )
            }
            AppError::TokenDecodeFailed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "Failed to decode token"}),
            ),
            // Internal messages are diagnostics for operators, not clients.
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "Internal error"}),
                )
            }
        };

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    /// Render an AppError through the REAL `IntoResponse` impl.
    ///
    /// Previously this test module re-implemented the status/body mapping,
    /// which meant the tests could pass while `into_response` drifted (and it
    /// did — the scrubbing of Internal/TokenExchangeFailed would not have been
    /// caught). Now it exercises the shipping code path.
    async fn render(err: AppError) -> (StatusCode, serde_json::Value) {
        let resp = err.into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("body should be JSON");
        (status, json)
    }

    #[tokio::test]
    async fn test_not_authenticated() {
        let (status, body) = render(AppError::NotAuthenticated).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "Not authenticated");
    }

    #[tokio::test]
    async fn test_csrf_failed() {
        let (status, body) = render(AppError::CsrfFailed).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "CSRF validation failed");
        assert_eq!(body["message"], "Missing X-L42-CSRF header");
    }

    #[tokio::test]
    async fn test_cedar_unavailable() {
        let (status, body) = render(AppError::CedarUnavailable).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["authorized"], false);
    }

    #[tokio::test]
    async fn test_token_expired() {
        let (status, body) = render(AppError::TokenExpired).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "Token expired");
    }

    #[tokio::test]
    async fn test_bad_request() {
        let (status, body) = render(AppError::BadRequest("Missing field".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "Missing field");
    }

    #[tokio::test]
    async fn test_credential_rejected() {
        let (status, body) =
            render(AppError::CredentialRejected("AAGUID not in allowlist".into())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["allowed"], false);
        assert_eq!(body["reason"], "AAGUID not in allowlist");
    }

    #[tokio::test]
    async fn test_refresh_failed_surfaces_own_token_state() {
        // Deliberately surfaced — describes the caller's own refresh token.
        let (status, body) = render(AppError::RefreshFailed("Token revoked".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "Refresh failed");
        assert_eq!(body["message"], "Token revoked");
    }

    #[tokio::test]
    async fn test_internal_does_not_leak_message() {
        let (status, body) = render(AppError::Internal(
            "dynamodb table l42_sessions AccessDenied for arn:aws:iam::123".into(),
        ))
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "Internal error");
        let rendered = body.to_string();
        assert!(!rendered.contains("dynamodb"), "must not leak internals");
        assert!(!rendered.contains("arn:aws"), "must not leak ARNs");
    }

    #[tokio::test]
    async fn test_token_exchange_failed_does_not_leak_upstream_detail() {
        let (status, body) = render(AppError::TokenExchangeFailed(
            "invalid_client: client us-west-2_pool/abc123 secret mismatch".into(),
        ))
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "Token exchange failed");
        let rendered = body.to_string();
        assert!(!rendered.contains("invalid_client"), "must not leak upstream text");
        assert!(!rendered.contains("abc123"), "must not leak client identifiers");
    }
}
