//! GET /auth/callback

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Redirect;
use serde::Deserialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::cognito::client;
use crate::cognito::jwt::decode_jwt_unverified;
use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::SessionTokens;

/// Extract the viewer-facing host, preferring `X-Forwarded-Host` (set by CDN/reverse
/// proxy) over the standard `Host` header. Falls back to `"localhost"`.
fn extract_host(headers: &HeaderMap) -> &str {
    headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
}

/// The `X-Forwarded-Proto` scheme, falling back to https/http per `session_https_only`.
fn forwarded_scheme<'a>(config: &crate::config::Config, headers: &'a HeaderMap) -> &'a str {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|s| *s == "http" || *s == "https")
        .unwrap_or(if config.session_https_only {
            "https"
        } else {
            "http"
        })
}

/// Compute this backend's public `/auth/callback` URL — the OAuth `redirect_uri`.
///
/// It MUST be byte-identical in the authorization request (built by the
/// `/auth/login` endpoint) and in the token exchange here, or Cognito rejects
/// the exchange. Both call this function so they can't drift.
pub fn self_callback_url(config: &crate::config::Config, headers: &HeaderMap) -> String {
    if !config.callback_use_origin && !config.frontend_url.is_empty() {
        format!("{}{}/callback", config.frontend_url, config.auth_path_prefix)
    } else {
        let host = extract_host(headers);
        let scheme = forwarded_scheme(config, headers);
        format!("{}://{}{}/callback", scheme, host, config.auth_path_prefix)
    }
}

/// Query parameters from Cognito OAuth redirect.
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// OAuth callback — exchange code for tokens, store in session, redirect to frontend.
pub async fn oauth_callback(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    session: SessionHandle,
    Query(params): Query<CallbackParams>,
) -> Redirect {
    // When callback_use_origin is true, derive the redirect target from the
    // request's origin (X-Forwarded-Host + X-Forwarded-Proto) instead of the
    // static frontend_url. This lets a single Lambda serve multiple CloudFront
    // distributions that redirect back to the correct origin after OAuth.
    let frontend: std::borrow::Cow<'_, str> = if state.config.callback_use_origin {
        let host = extract_host(&headers);
        let scheme = forwarded_scheme(&state.config, &headers);
        let origin = format!("{}://{}", scheme, host);

        // Validate origin against allowed list (prevents open redirect via header injection)
        if !state.config.callback_allowed_origins.is_empty()
            && !state
                .config
                .callback_allowed_origins
                .iter()
                .any(|o| o == &origin.to_lowercase())
        {
            ocsf::authentication_event(
                ocsf::ACTIVITY_AUTH_TICKET,
                "Authentication Ticket",
                ocsf::STATUS_FAILURE,
                ocsf::SEVERITY_HIGH,
                None,
                ocsf::AUTH_PROTOCOL_OAUTH2,
                "OAuth 2.0/OIDC",
                &format!("Callback origin rejected: {origin}"),
            );
            session.destroy().await;
            return Redirect::temporary(&format!(
                "{}/login?error=Invalid+callback+origin",
                state.config.frontend_url
            ));
        }

        origin.into()
    } else {
        std::borrow::Cow::Borrowed(&state.config.frontend_url)
    };

    // redirect_uri must match the one used in the authorization request — both
    // sides call self_callback_url so they can't drift.
    let redirect_uri = self_callback_url(&state.config, &headers);

    // Validate `state` against the value the /auth/login endpoint stored in this
    // session, and take the stored PKCE verifier. Presence of a stored state
    // means this login was backend-initiated: enforce CSRF + supply the verifier.
    // Absence means a legacy client-initiated flow hit the backend callback —
    // preserve backward-compatible behavior (no server-side state to check).
    let (stored_state, stored_verifier) = {
        let data = session.data.lock().await;
        let s = data
            .get(crate::routes::login::OAUTH_STATE_KEY)
            .and_then(|v| v.as_str())
            .map(String::from);
        let v = data
            .get(crate::routes::login::OAUTH_VERIFIER_KEY)
            .and_then(|v| v.as_str())
            .map(String::from);
        (s, v)
    };

    if let Some(ref expected) = stored_state {
        let provided = params.state.as_deref().unwrap_or("");
        let matches: bool = expected.as_bytes().ct_eq(provided.as_bytes()).into();
        if !matches {
            ocsf::authentication_event(
                ocsf::ACTIVITY_AUTH_TICKET,
                "Authentication Ticket",
                ocsf::STATUS_FAILURE,
                ocsf::SEVERITY_HIGH,
                None,
                ocsf::AUTH_PROTOCOL_OAUTH2,
                "OAuth 2.0/OIDC",
                "OAuth state mismatch — possible CSRF",
            );
            session.destroy().await;
            return Redirect::temporary(&format!(
                "{}/login?error=Invalid+OAuth+state",
                frontend
            ));
        }
    }

    // Handle OAuth error from Cognito
    if let Some(ref error) = params.error {
        let msg = params.error_description.as_deref().unwrap_or(error);

        ocsf::authentication_event(
            ocsf::ACTIVITY_AUTH_TICKET,
            "Authentication Ticket",
            ocsf::STATUS_FAILURE,
            ocsf::SEVERITY_HIGH,
            None,
            ocsf::AUTH_PROTOCOL_OAUTH2,
            "OAuth 2.0/OIDC",
            &format!("OAuth error: {}", error),
        );

        // Destroy session — no valid tokens, prevent stale empty session
        session.destroy().await;

        return Redirect::temporary(&format!(
            "{}/login?error={}",
            frontend,
            urlencoding::encode(msg)
        ));
    }

    // Require authorization code
    let code = match params.code {
        Some(ref c) if !c.is_empty() => c.as_str(),
        _ => {
            session.destroy().await;
            return Redirect::temporary(&format!(
                "{}/login?error=Missing+authorization+code",
                frontend
            ));
        }
    };

    // Exchange code for tokens (with the stored PKCE verifier if this was a
    // backend-initiated login).
    match client::exchange_code_for_tokens(
        &state.http_client,
        &state.config,
        code,
        &redirect_uri,
        stored_verifier.as_deref(),
    )
    .await
    {
        Ok(token_map) => {
            let access_token = token_map
                .get("access_token")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let id_token = token_map
                .get("id_token")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let refresh_token = token_map
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(String::from);

            // Extract email for OCSF (best-effort)
            let email = decode_jwt_unverified(id_token).ok().and_then(|c| c.email);

            // Store tokens; drop the single-use OAuth state + verifier.
            let tokens = SessionTokens {
                access_token: access_token.to_string(),
                id_token: id_token.to_string(),
                refresh_token,
                auth_method: Some("oauth".into()),
            };
            {
                let mut data = session.data.lock().await;
                data.set("tokens", serde_json::to_value(&tokens).unwrap());
                // Single-use OAuth values — drop after a successful exchange.
                data.remove(crate::routes::login::OAUTH_STATE_KEY);
                data.remove(crate::routes::login::OAUTH_VERIFIER_KEY);
            }
            // Rotate the session ID on login (session-fixation defense).
            session.rotate_id().await;

            ocsf::authentication_event(
                ocsf::ACTIVITY_AUTH_TICKET,
                "Authentication Ticket",
                ocsf::STATUS_SUCCESS,
                ocsf::SEVERITY_INFORMATIONAL,
                email.as_deref(),
                ocsf::AUTH_PROTOCOL_OAUTH2,
                "OAuth 2.0/OIDC",
                "OAuth token exchange succeeded",
            );

            let redirect_target = match params.state {
                Some(ref s) if !s.is_empty() => {
                    format!("{}/auth/success?state={}", frontend, urlencoding::encode(s))
                }
                _ => format!("{}/auth/success", frontend),
            };
            Redirect::temporary(&redirect_target)
        }
        Err(e) => {
            ocsf::authentication_event(
                ocsf::ACTIVITY_AUTH_TICKET,
                "Authentication Ticket",
                ocsf::STATUS_FAILURE,
                ocsf::SEVERITY_MEDIUM,
                None,
                ocsf::AUTH_PROTOCOL_OAUTH2,
                "OAuth 2.0/OIDC",
                &format!("OAuth token exchange failed: {}", e),
            );

            // Destroy session — exchange failed, no valid tokens
            session.destroy().await;

            Redirect::temporary(&format!("{}/login?error=Authentication+failed", frontend))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_prefers_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "internal-lambda.amazonaws.com".parse().unwrap());
        headers.insert("x-forwarded-host", "app.example.com".parse().unwrap());
        assert_eq!(extract_host(&headers), "app.example.com");
    }

    #[test]
    fn test_extract_host_falls_back_to_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "api.example.com".parse().unwrap());
        assert_eq!(extract_host(&headers), "api.example.com");
    }

    #[test]
    fn test_extract_host_defaults_to_localhost() {
        let headers = HeaderMap::new();
        assert_eq!(extract_host(&headers), "localhost");
    }
}
