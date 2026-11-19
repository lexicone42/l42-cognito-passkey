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
            AppError::TokenExchangeFailed(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("Token exchange failed: {}", msg)}),
            ),
            AppError::TokenDecodeFailed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "Failed to decode token"}),
            ),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": msg})),
        };

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render through the real `IntoResponse` and read the body back, so the
    /// test can only pass if the mapping the server sends is the one asserted.
    async fn render(err: AppError) -> (StatusCode, serde_json::Value) {
        let resp = err.into_response();
        let status = resp.status();
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "every error body is JSON"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn every_variant_renders_its_documented_status_and_body() {
        let cases: Vec<(AppError, StatusCode, serde_json::Value)> = vec![
            (
                AppError::NotAuthenticated,
                StatusCode::UNAUTHORIZED,
                json!({"error": "Not authenticated"}),
            ),
            (
                AppError::TokenExpired,
                StatusCode::UNAUTHORIZED,
                json!({"error": "Token expired"}),
            ),
            (
                AppError::CsrfFailed,
                StatusCode::FORBIDDEN,
                json!({"error": "CSRF validation failed", "message": "Missing X-L42-CSRF header"}),
            ),
            (
                AppError::BadRequest("Missing field".into()),
                StatusCode::BAD_REQUEST,
                json!({"error": "Missing field"}),
            ),
            (
                AppError::TokenVerificationFailed,
                StatusCode::FORBIDDEN,
                json!({"error": "Token verification failed"}),
            ),
            (
                AppError::NoRefreshToken,
                StatusCode::UNAUTHORIZED,
                json!({"error": "No refresh token"}),
            ),
            (
                AppError::RefreshFailed("Token revoked".into()),
                StatusCode::UNAUTHORIZED,
                json!({"error": "Refresh failed", "message": "Token revoked"}),
            ),
            (
                AppError::CedarUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "Authorization engine not available", "authorized": false}),
            ),
            (
                AppError::AuthorizationError("boom".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"authorized": false, "error": "Authorization evaluation failed"}),
            ),
            (
                AppError::TokenExchangeFailed("boom".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "Token exchange failed: boom"}),
            ),
            (
                AppError::TokenDecodeFailed,
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "Failed to decode token"}),
            ),
            (
                AppError::CredentialRejected("AAGUID not in allowlist".into()),
                StatusCode::FORBIDDEN,
                json!({"allowed": false, "reason": "AAGUID not in allowlist"}),
            ),
            (
                AppError::Internal("db".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "db"}),
            ),
        ];
        for (err, want_status, want_body) in cases {
            let name = format!("{err:?}");
            let (status, body) = render(err).await;
            assert_eq!(status, want_status, "{name}");
            assert_eq!(body, want_body, "{name}");
        }
    }

    #[tokio::test]
    async fn internal_details_never_leak_through_authorization_errors() {
        // The Cedar failure variant carries a diagnostic string for the log,
        // but the client sees only the generic message.
        let (_, body) = render(AppError::AuthorizationError(
            "policy parse at line 3".into(),
        ))
        .await;
        assert!(!body.to_string().contains("line 3"));
    }
}
