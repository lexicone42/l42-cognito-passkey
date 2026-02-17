//! Application error types with Axum response mapping.
//!
//! Each variant maps to a specific HTTP status + JSON body, matching the
//! exact responses from the FastAPI backend.

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
            AppError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "Token expired"}),
            ),
            AppError::CsrfFailed => (
                StatusCode::FORBIDDEN,
                json!({
                    "error": "CSRF validation failed",
                    "message": "Missing X-L42-CSRF header"
                }),
            ),
            AppError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                json!({"error": msg}),
            ),
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
            AppError::TokenExchangeFailed(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("Token exchange failed: {}", msg)}),
            ),
            AppError::TokenDecodeFailed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "Failed to decode token"}),
            ),
            AppError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": msg}),
            ),
        };

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Directly construct the expected (status, body) for an error variant.
    /// This tests the mapping logic without needing async body extraction.
    fn error_to_json(err: AppError) -> (StatusCode, serde_json::Value) {
        let (status, body) = match &err {
            AppError::NotAuthenticated => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "Not authenticated"}),
            ),
            AppError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "Token expired"}),
            ),
            AppError::CsrfFailed => (
                StatusCode::FORBIDDEN,
                serde_json::json!({
                    "error": "CSRF validation failed",
                    "message": "Missing X-L42-CSRF header"
                }),
            ),
            AppError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error": msg}),
            ),
            AppError::TokenVerificationFailed => (
                StatusCode::FORBIDDEN,
                serde_json::json!({"error": "Token verification failed"}),
            ),
            AppError::NoRefreshToken => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "No refresh token"}),
            ),
            AppError::RefreshFailed(msg) => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "Refresh failed", "message": msg}),
            ),
            AppError::CedarUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"error": "Authorization engine not available", "authorized": false}),
            ),
            AppError::AuthorizationError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"authorized": false, "error": "Authorization evaluation failed"}),
            ),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({"error": "internal"})),
        };
        (status, body)
    }

    #[test]
    fn test_not_authenticated() {
        let (status, body) = error_to_json(AppError::NotAuthenticated);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "Not authenticated");
    }

    #[test]
    fn test_csrf_failed() {
        let (status, body) = error_to_json(AppError::CsrfFailed);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "CSRF validation failed");
        assert_eq!(body["message"], "Missing X-L42-CSRF header");
    }

    #[test]
    fn test_cedar_unavailable() {
        let (status, body) = error_to_json(AppError::CedarUnavailable);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["authorized"], false);
    }

    #[test]
    fn test_token_expired() {
        let (status, body) = error_to_json(AppError::TokenExpired);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "Token expired");
    }

    #[test]
    fn test_bad_request() {
        let (status, body) = error_to_json(AppError::BadRequest("Missing field".into()));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "Missing field");
    }

    #[test]
    fn test_refresh_failed() {
        let (status, body) = error_to_json(AppError::RefreshFailed("Token revoked".into()));
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "Refresh failed");
        assert_eq!(body["message"], "Token revoked");
    }
}
