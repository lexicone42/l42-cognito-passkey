//! GET /auth/login — backend-initiated OAuth (hosted UI) redirect.
//!
//! This closes the design-review gap where the client generated the OAuth
//! `state` + PKCE challenge but the backend callback could neither validate the
//! state (it lives in the client's localStorage, a different origin) nor supply
//! the PKCE verifier at token exchange (so Cognito returned `invalid_grant`).
//!
//! When the backend owns the callback (`oauthCallbackUrl` in the client), the
//! client should hit THIS endpoint instead of building the Cognito URL itself.
//! Here the backend:
//!   1. generates `state` + a PKCE verifier, stores both in the (pre-login)
//!      session cookie,
//!   2. redirects to Cognito with the matching `code_challenge`,
//!   3. and on `/auth/callback` validates `state` against the session and sends
//!      the stored verifier to the token endpoint.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Redirect;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::session::middleware::SessionHandle;

/// Session keys for the in-flight OAuth values (namespaced to avoid collisions).
pub const OAUTH_STATE_KEY: &str = "oauth_state";
pub const OAUTH_VERIFIER_KEY: &str = "oauth_pkce_verifier";

#[derive(Debug, Deserialize)]
pub struct LoginParams {
    /// Optional email hint forwarded to Cognito as `login_hint`.
    pub email: Option<String>,
}

/// Generate a random URL-safe token of `n` bytes (used for state + verifier).
fn random_token(n: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// RFC 7636 code challenge = BASE64URL(SHA256(verifier)).
pub fn code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Build the Cognito authorize URL for the hosted UI.
fn authorize_url(
    config: &crate::config::Config,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    email: Option<&str>,
) -> String {
    let mut params = vec![
        ("client_id", config.cognito_client_id.as_str()),
        ("response_type", "code"),
        ("scope", "openid email profile aws.cognito.signin.user.admin"),
        ("redirect_uri", redirect_uri),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    if let Some(hint) = email {
        params.push(("login_hint", hint));
    }
    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("https://{}/oauth2/authorize?{}", config.cognito_domain, query)
}

/// GET /auth/login — start the backend-owned OAuth flow.
pub async fn login(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    session: SessionHandle,
    Query(params): Query<LoginParams>,
) -> Redirect {
    let oauth_state = random_token(32);
    let verifier = random_token(48);
    let challenge = code_challenge(&verifier);

    // Persist state + verifier in the pre-login session so the callback (same
    // session cookie) can validate state and supply the verifier.
    {
        let mut data = session.data.lock().await;
        data.set(OAUTH_STATE_KEY, serde_json::Value::String(oauth_state.clone()));
        data.set(OAUTH_VERIFIER_KEY, serde_json::Value::String(verifier));
    }

    let redirect_uri = crate::routes::callback::self_callback_url(&state.config, &headers);
    let url = authorize_url(
        &state.config,
        &redirect_uri,
        &oauth_state,
        &challenge,
        params.email.as_deref(),
    );
    Redirect::temporary(&url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_challenge_is_deterministic_base64url() {
        // Known RFC 7636 test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = code_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        // base64url: no +, /, or =
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert!(!challenge.contains('='));
    }

    #[test]
    fn test_random_token_length_and_uniqueness() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        // 32 bytes -> 43 base64url chars (no padding)
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn test_authorize_url_contains_pkce_and_state() {
        let config = crate::config::Config::test_default();
        let url = authorize_url(&config, "https://app/auth/callback", "st8", "chal", Some("a@b.com"));
        assert!(url.contains("code_challenge=chal"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=st8"));
        assert!(url.contains("login_hint=a%40b.com"));
        assert!(url.starts_with("https://test.auth.us-west-2.amazoncognito.com/oauth2/authorize?"));
    }
}
