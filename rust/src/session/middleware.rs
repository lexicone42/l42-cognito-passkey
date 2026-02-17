//! Axum session middleware layer.
//!
//! Extracts signed session ID from cookie, loads session data from the
//! backend, makes it available via request extensions, and saves/clears
//! on response.
//!
//! The session data is passed through request extensions:
//! - `SessionHandle` — shared mutable access to session data
//! - Route handlers clone/modify the inner data via the handle
//! - The middleware checks for changes after the handler returns

use axum::extract::{FromRequestParts, Request};
use axum::http::header;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::cookie::{sign_session_id, verify_cookie};
use super::{SessionBackend, SessionData};

const COOKIE_NAME: &str = "l42_session";
const MAX_AGE_SECS: u64 = 30 * 24 * 3600; // 30 days

/// Shared handle to session state, inserted into request extensions.
#[derive(Clone)]
pub struct SessionHandle {
    pub id: String,
    pub data: Arc<Mutex<SessionData>>,
    pub destroyed: Arc<Mutex<bool>>,
}

/// Extract SessionHandle from request extensions (put there by session middleware).
impl<S> FromRequestParts<S> for SessionHandle
where
    S: Send + Sync,
{
    type Rejection = crate::error::AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<SessionHandle>()
            .cloned()
            .ok_or(crate::error::AppError::Internal(
                "Session middleware not configured".into(),
            ))
    }
}

impl SessionHandle {
    fn new(id: String, data: SessionData) -> Self {
        Self {
            id,
            data: Arc::new(Mutex::new(data)),
            destroyed: Arc::new(Mutex::new(false)),
        }
    }
}

/// Session middleware configuration.
pub struct SessionLayer<B: SessionBackend> {
    pub backend: Arc<B>,
    pub secret: String,
    pub https_only: bool,
}

/// Axum middleware function for session handling.
pub async fn session_middleware<B: SessionBackend + 'static>(
    layer: Arc<SessionLayer<B>>,
    mut req: Request,
    next: Next,
) -> Response {
    // Extract session ID from cookie
    let cookie_header = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let session_cookie = parse_cookie(cookie_header, COOKIE_NAME);
    let session_id = session_cookie
        .and_then(|v| verify_cookie(layer.secret.as_bytes(), v));

    let (handle, initial_data, is_new) = match session_id {
        Some(id) => {
            match layer.backend.load(&id).await {
                Some(data) => {
                    let initial = data.clone();
                    (SessionHandle::new(id, data), initial, false)
                }
                None => {
                    // Expired or missing — create new session
                    let new_id = generate_session_id();
                    (
                        SessionHandle::new(new_id, SessionData::new()),
                        SessionData::new(),
                        true,
                    )
                }
            }
        }
        None => {
            let new_id = generate_session_id();
            (
                SessionHandle::new(new_id, SessionData::new()),
                SessionData::new(),
                true,
            )
        }
    };

    let session_id = handle.id.clone();
    req.extensions_mut().insert(handle.clone());

    // Run the route handler
    let mut response = next.run(req).await;

    // After handler: check if session was modified or destroyed
    let destroyed = *handle.destroyed.lock().await;
    let current_data = handle.data.lock().await.clone();

    if destroyed {
        layer.backend.delete(&session_id).await;
        let cookie = make_delete_cookie(&layer.secret, &session_id, layer.https_only);
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie.parse().unwrap(),
        );
    } else if current_data != initial_data || is_new {
        layer.backend.save(&session_id, &current_data).await;
        let cookie = make_set_cookie(&layer.secret, &session_id, layer.https_only);
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie.parse().unwrap(),
        );
    }

    response
}

fn generate_session_id() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

use base64::Engine;

fn make_set_cookie(secret: &str, session_id: &str, https_only: bool) -> String {
    let signed = sign_session_id(secret.as_bytes(), session_id);
    let mut parts = vec![
        format!("{}={}", COOKIE_NAME, signed),
        format!("Max-Age={}", MAX_AGE_SECS),
        "Path=/".into(),
        "HttpOnly".into(),
        "SameSite=Lax".into(),
    ];
    if https_only {
        parts.push("Secure".into());
    }
    parts.join("; ")
}

fn make_delete_cookie(_secret: &str, _session_id: &str, https_only: bool) -> String {
    let mut parts = vec![
        format!("{}=", COOKIE_NAME),
        "Max-Age=0".into(),
        "Path=/".into(),
        "HttpOnly".into(),
        "SameSite=Lax".into(),
    ];
    if https_only {
        parts.push("Secure".into());
    }
    parts.join("; ")
}

/// Parse a specific cookie from a Cookie header value.
fn parse_cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for part in header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(name) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookie_found() {
        let header = "l42_session=abc123; other=xyz";
        assert_eq!(parse_cookie(header, "l42_session"), Some("abc123"));
    }

    #[test]
    fn test_parse_cookie_not_found() {
        let header = "other=xyz";
        assert_eq!(parse_cookie(header, "l42_session"), None);
    }

    #[test]
    fn test_parse_cookie_empty() {
        assert_eq!(parse_cookie("", "l42_session"), None);
    }

    #[test]
    fn test_make_set_cookie_format() {
        let cookie = make_set_cookie("secret", "sid", false);
        assert!(cookie.starts_with("l42_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn test_make_set_cookie_secure() {
        let cookie = make_set_cookie("secret", "sid", true);
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn test_make_delete_cookie() {
        let cookie = make_delete_cookie("secret", "sid", false);
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.starts_with("l42_session=;"));
    }
}
