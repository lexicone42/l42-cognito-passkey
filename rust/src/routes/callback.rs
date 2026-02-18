//! GET /auth/callback

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Redirect;
use serde::Deserialize;
use std::sync::Arc;

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
    let frontend = &state.config.frontend_url;

    // Build redirect_uri that must match the one used in the authorization request.
    // Behind CDN/reverse proxy, Host header may be the internal API Gateway hostname,
    // not the public domain. Use frontend_url when available (it matches Cognito config).
    let self_callback_url = if !state.config.frontend_url.is_empty() {
        format!(
            "{}{}/callback",
            state.config.frontend_url, state.config.auth_path_prefix
        )
    } else {
        let host = extract_host(&headers);
        let scheme = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(if state.config.session_https_only {
                "https"
            } else {
                "http"
            });
        format!(
            "{}://{}{}/callback",
            scheme, host, state.config.auth_path_prefix
        )
    };

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
            return Redirect::temporary(&format!(
                "{}/login?error=Missing+authorization+code",
                frontend
            ))
        }
    };

    let redirect_uri = self_callback_url;

    // Exchange code for tokens
    match client::exchange_code_for_tokens(&state.http_client, &state.config, code, &redirect_uri)
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
            let email = decode_jwt_unverified(id_token)
                .ok()
                .and_then(|c| c.email);

            // Store in session
            let tokens = SessionTokens {
                access_token: access_token.to_string(),
                id_token: id_token.to_string(),
                refresh_token,
                auth_method: Some("oauth".into()),
            };
            {
                let mut data = session.data.lock().await;
                data.set("tokens", serde_json::to_value(&tokens).unwrap());
            }

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
                    format!(
                        "{}/auth/success?state={}",
                        frontend,
                        urlencoding::encode(s)
                    )
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

            Redirect::temporary(&format!(
                "{}/login?error=Authentication+failed",
                frontend
            ))
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
