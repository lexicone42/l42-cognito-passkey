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

    // Extract host from Host header (standard HTTP/1.1) or fallback
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    // Determine scheme from X-Forwarded-Proto (behind proxy/ALB) or config
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(if state.config.session_https_only {
            "https"
        } else {
            "http"
        });
    // Build redirect_uri from the backend's own URL (must match Cognito app client config)
    let self_callback_url = format!("{}://{}/auth/callback", scheme, host);

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
