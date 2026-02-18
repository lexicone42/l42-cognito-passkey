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
    pub cookie_domain: Option<String>,
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

    let (handle, initial_data) = match session_id {
        Some(id) => {
            match layer.backend.load(&id).await {
                Some(data) => {
                    let initial = data.clone();
                    (SessionHandle::new(id, data), initial)
                }
                None => {
                    // Expired or missing — create new session
                    let new_id = generate_session_id();
                    (
                        SessionHandle::new(new_id, SessionData::new()),
                        SessionData::new(),
                    )
                }
            }
        }
        None => {
            let new_id = generate_session_id();
            (
                SessionHandle::new(new_id, SessionData::new()),
                SessionData::new(),
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

    let domain = layer.cookie_domain.as_deref();

    if destroyed {
        layer.backend.delete(&session_id).await;
        let cookie = make_delete_cookie(&layer.secret, &session_id, layer.https_only, domain);
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie.parse().unwrap(),
        );
    } else if current_data != initial_data {
        // Only persist when the handler actually modified session data.
        // Without this check, every unauthenticated request (including GET /health)
        // would create an empty session in the backend + set a cookie.
        layer.backend.save(&session_id, &current_data).await;
        let cookie = make_set_cookie(&layer.secret, &session_id, layer.https_only, domain);
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie.parse().unwrap(),
        );
    }

    response
}

fn generate_session_id() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().r#gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

use base64::Engine;

fn make_set_cookie(
    secret: &str,
    session_id: &str,
    https_only: bool,
    cookie_domain: Option<&str>,
) -> String {
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
    if let Some(domain) = cookie_domain {
        parts.push(format!("Domain={domain}"));
    }
    parts.join("; ")
}

fn make_delete_cookie(
    _secret: &str,
    _session_id: &str,
    https_only: bool,
    cookie_domain: Option<&str>,
) -> String {
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
    if let Some(domain) = cookie_domain {
        parts.push(format!("Domain={domain}"));
    }
    parts.join("; ")
}

/// Parse a specific cookie from a Cookie header value.
fn parse_cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for part in header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(name)
            && let Some(value) = value.strip_prefix('=')
        {
            return Some(value);
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
        let cookie = make_set_cookie("secret", "sid", false, None);
        assert!(cookie.starts_with("l42_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
        assert!(!cookie.contains("Secure"));
        assert!(!cookie.contains("Domain="));
    }

    #[test]
    fn test_make_set_cookie_secure() {
        let cookie = make_set_cookie("secret", "sid", true, None);
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn test_make_set_cookie_with_domain() {
        let cookie = make_set_cookie("secret", "sid", false, Some(".example.com"));
        assert!(cookie.contains("Domain=.example.com"));
    }

    #[test]
    fn test_make_delete_cookie() {
        let cookie = make_delete_cookie("secret", "sid", false, None);
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.starts_with("l42_session=;"));
        assert!(!cookie.contains("Domain="));
    }

    #[test]
    fn test_make_delete_cookie_with_domain() {
        let cookie = make_delete_cookie("secret", "sid", false, Some(".example.com"));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("Domain=.example.com"));
    }
}
