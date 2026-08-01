//! Cognito HTTP client: token exchange and refresh.
//!
//! Mirrors `app/cognito.py` — `exchange_code_for_tokens` and `cognito_request`.

use serde_json::Value;
use std::collections::HashMap;

use crate::config::Config;

/// Exchange an OAuth authorization code for tokens.
///
/// POST to `{domain}/oauth2/token` with grant_type=authorization_code.
pub async fn exchange_code_for_tokens(
    http_client: &reqwest::Client,
    config: &Config,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
) -> Result<HashMap<String, Value>, CognitoError> {
    let mut params = vec![
        ("grant_type", "authorization_code".to_string()),
        ("client_id", config.cognito_client_id.clone()),
        ("code", code.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
    ];

    if !config.cognito_client_secret.is_empty() {
        params.push(("client_secret", config.cognito_client_secret.clone()));
    }

    // PKCE: send the verifier when the authorize request carried a challenge
    // (backend-initiated flow). Cognito returns invalid_grant otherwise.
    if let Some(verifier) = code_verifier {
        params.push(("code_verifier", verifier.to_string()));
    }

    let resp = http_client
        .post(config.cognito_token_url())
        .form(&params)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .map_err(|e| CognitoError::RequestFailed(e.to_string()))?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(CognitoError::TokenExchangeFailed(text));
    }

    resp.json()
        .await
        .map_err(|e| CognitoError::RequestFailed(e.to_string()))
}

/// Make a request to Cognito IDP (e.g., InitiateAuth for refresh).
///
/// Uses the `X-Amz-Target` header pattern for Cognito's JSON API.
pub async fn cognito_request(
    http_client: &reqwest::Client,
    config: &Config,
    action: &str,
    body: &Value,
) -> Result<Value, CognitoError> {
    let resp = http_client
        .post(config.cognito_idp_url())
        .header("Content-Type", "application/x-amz-json-1.1")
        .header(
            "X-Amz-Target",
            format!("AWSCognitoIdentityProviderService.{}", action),
        )
        .json(body)
        .send()
        .await
        .map_err(|e| CognitoError::RequestFailed(e.to_string()))?;

    // Capture status before consuming the body
    let status = resp.status();

    let data: Value = resp
        .json()
        .await
        .map_err(|e| CognitoError::RequestFailed(e.to_string()))?;

    // Check HTTP status AND Cognito error marker
    if !status.is_success() || data.get("__type").is_some() {
        let msg = data
            .get("message")
            .or_else(|| data.get("__type"))
            .and_then(|v| v.as_str())
            .unwrap_or("Cognito request failed");
        return Err(CognitoError::CognitoError(msg.to_string()));
    }

    Ok(data)
}

/// Refresh tokens via Cognito's `GetTokensFromRefreshToken` API.
///
/// This is the current refresh API (replacing the legacy
/// `InitiateAuth`/`REFRESH_TOKEN_AUTH` flow) and is required to use **refresh
/// token rotation**: when rotation is enabled on the app client, the response's
/// `AuthenticationResult.RefreshToken` is a *new* refresh token that supersedes
/// the one sent — the caller must persist it (the `/auth/refresh` handler
/// already stores a returned RefreshToken back into the session). Without
/// rotation enabled, the response omits `RefreshToken` and the caller keeps the
/// existing one; this function behaves correctly either way.
///
/// The response shape (`AuthenticationResult` with Access/Id/optional Refresh)
/// matches the old flow, so downstream parsing is unchanged.
pub async fn refresh_tokens(
    http_client: &reqwest::Client,
    config: &Config,
    refresh_token: &str,
) -> Result<Value, CognitoError> {
    let mut body = serde_json::json!({
        "ClientId": config.cognito_client_id,
        "RefreshToken": refresh_token,
    });
    // Confidential clients pass the secret directly (no SECRET_HASH needed).
    if !config.cognito_client_secret.is_empty() {
        body["ClientSecret"] = serde_json::Value::String(config.cognito_client_secret.clone());
    }

    cognito_request(http_client, config, "GetTokensFromRefreshToken", &body).await
}

#[derive(Debug, thiserror::Error)]
pub enum CognitoError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),

    #[error("Token exchange failed: {0}")]
    TokenExchangeFailed(String),

    #[error("Cognito error: {0}")]
    CognitoError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config_with_url(server_url: &str) -> Config {
        Config {
            cognito_client_id: "test-client-id".into(),
            cognito_client_secret: String::new(),
            cognito_user_pool_id: "us-west-2_test123".into(),
            cognito_domain: "test.auth.us-west-2.amazoncognito.com".into(),
            cognito_region: "us-west-2".into(),
            // COGNITO_ENDPOINT override points the real URL builders at wiremock.
            cognito_endpoint: server_url.to_string(),
            session_secret: "test-secret-key-at-least-32-chars!".into(),
            frontend_url: "http://localhost:3000".into(),
            port: 3001,
            session_backend: "memory".into(),
            dynamodb_table: "l42_sessions".into(),
            dynamodb_endpoint: String::new(),
            session_https_only: false,
            cookie_domain: None,
            auth_path_prefix: "/auth".into(),
            callback_use_origin: false,
            callback_allowed_origins: Vec::new(),
            aaguid_allowlist: Vec::new(),
            require_device_bound: false,
            service_token: None,
            additional_audience: Vec::new(),
            entity_table: None,
            entity_strict_ownership: false,
        }
    }

    // These tests exercise the REAL client functions by pointing Config's URL
    // builders at wiremock via the COGNITO_ENDPOINT override (`cognito_endpoint`).

    #[tokio::test]
    async fn test_exchange_code_success() {
        let server = MockServer::start().await;
        let config = test_config_with_url(&server.uri());

        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at-new",
                "id_token": "it-new",
                "refresh_token": "rt-new"
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        // Call the REAL function under test.
        let tokens = exchange_code_for_tokens(
            &client,
            &config,
            "auth-code-123",
            "http://localhost:3000/auth/callback",
            Some("verifier-abc"),
        )
        .await
        .expect("exchange should succeed");

        assert_eq!(tokens["access_token"], "at-new");
        assert_eq!(tokens["id_token"], "it-new");
        assert_eq!(tokens["refresh_token"], "rt-new");
    }

    #[tokio::test]
    async fn test_exchange_code_sends_verifier() {
        let server = MockServer::start().await;
        let config = test_config_with_url(&server.uri());

        // Assert the PKCE verifier is actually included in the form body.
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("code_verifier=verifier-abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at", "id_token": "it"
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let result = exchange_code_for_tokens(
            &client,
            &config,
            "code",
            "http://localhost/cb",
            Some("verifier-abc"),
        )
        .await;
        assert!(result.is_ok(), "verifier must be sent so the mock matches");
    }

    #[tokio::test]
    async fn test_refresh_tokens_success() {
        let server = MockServer::start().await;
        let config = test_config_with_url(&server.uri());

        Mock::given(method("POST"))
            .and(header(
                "X-Amz-Target",
                "AWSCognitoIdentityProviderService.GetTokensFromRefreshToken",
            ))
            .and(body_string_contains("\"RefreshToken\":\"rt-123\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "AuthenticationResult": {
                    "AccessToken": "at-refreshed",
                    "IdToken": "it-refreshed"
                }
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        // Call the REAL refresh_tokens function.
        let data = refresh_tokens(&client, &config, "rt-123")
            .await
            .expect("refresh should succeed");
        assert_eq!(data["AuthenticationResult"]["AccessToken"], "at-refreshed");
    }

    #[tokio::test]
    async fn test_refresh_rotation_returns_new_refresh_token() {
        // With rotation enabled, GetTokensFromRefreshToken returns a NEW
        // RefreshToken that supersedes the one sent.
        let server = MockServer::start().await;
        let config = test_config_with_url(&server.uri());

        Mock::given(method("POST"))
            .and(header(
                "X-Amz-Target",
                "AWSCognitoIdentityProviderService.GetTokensFromRefreshToken",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "AuthenticationResult": {
                    "AccessToken": "at-rotated",
                    "IdToken": "it-rotated",
                    "RefreshToken": "rt-ROTATED-new"
                }
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let data = refresh_tokens(&client, &config, "rt-old").await.unwrap();
        assert_eq!(
            data["AuthenticationResult"]["RefreshToken"], "rt-ROTATED-new",
            "rotation must surface the new refresh token so the handler persists it"
        );
    }

    #[tokio::test]
    async fn test_refresh_tokens_error_maps_to_cognito_error() {
        let server = MockServer::start().await;
        let config = test_config_with_url(&server.uri());

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "__type": "NotAuthorizedException",
                "message": "Refresh Token has been revoked"
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let err = refresh_tokens(&client, &config, "rt-revoked")
            .await
            .expect_err("revoked refresh token must be an error");
        match err {
            CognitoError::CognitoError(msg) => {
                assert!(msg.contains("revoked"), "got: {msg}");
            }
            other => panic!("expected CognitoError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_refresh_omitting_refresh_token_is_rotation_signal() {
        // Cognito omits RefreshToken from a refresh response unless it rotated.
        // The refresh handler must preserve the old one in that case (v0.21
        // rotation-preservation fix). This test pins the wire behavior the
        // handler depends on: a refresh response with no RefreshToken field.
        let server = MockServer::start().await;
        let config = test_config_with_url(&server.uri());

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "AuthenticationResult": {
                    "AccessToken": "at2",
                    "IdToken": "it2"
                    // no RefreshToken -> caller keeps the existing one
                }
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let data = refresh_tokens(&client, &config, "rt-keep").await.unwrap();
        let result = &data["AuthenticationResult"];
        assert_eq!(result["AccessToken"], "at2");
        assert!(
            result.get("RefreshToken").is_none(),
            "Cognito omits RefreshToken when it did not rotate"
        );
    }
}
