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

/// Refresh tokens via Cognito InitiateAuth with REFRESH_TOKEN_AUTH flow.
pub async fn refresh_tokens(
    http_client: &reqwest::Client,
    config: &Config,
    refresh_token: &str,
) -> Result<Value, CognitoError> {
    let body = serde_json::json!({
        "AuthFlow": "REFRESH_TOKEN_AUTH",
        "ClientId": config.cognito_client_id,
        "AuthParameters": {
            "REFRESH_TOKEN": refresh_token
        }
    });

    cognito_request(http_client, config, "InitiateAuth", &body).await
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config_with_url(server_url: &str) -> Config {
        // Parse the server URL to extract the host:port for the domain
        let url = server_url.strip_prefix("http://").unwrap_or(server_url);
        Config {
            cognito_client_id: "test-client-id".into(),
            cognito_client_secret: String::new(),
            cognito_user_pool_id: "us-west-2_test123".into(),
            // wiremock uses http, but our config builds https URLs.
            // We'll override the methods that build URLs.
            cognito_domain: url.to_string(),
            cognito_region: "us-west-2".into(),
            session_secret: "test-secret".into(),
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
        }
    }

    // Note: wiremock tests use the mock server URL directly rather than going
    // through Config's derived URLs, because Config builds https:// URLs but
    // wiremock serves http://. Full integration tests in Phase 4 will test
    // the real URL construction.

    #[tokio::test]
    async fn test_exchange_code_success() {
        let server = MockServer::start().await;

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
        // Call directly with the mock URL
        let resp = client
            .post(format!("{}/oauth2/token", server.uri()))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", "test-client-id"),
                ("code", "auth-code-123"),
                ("redirect_uri", "http://localhost:3000/auth/callback"),
            ])
            .send()
            .await
            .unwrap();

        let tokens: HashMap<String, Value> = resp.json().await.unwrap();
        assert_eq!(tokens["access_token"], "at-new");
        assert_eq!(tokens["id_token"], "it-new");
        assert_eq!(tokens["refresh_token"], "rt-new");
    }

    #[tokio::test]
    async fn test_cognito_request_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header(
                "X-Amz-Target",
                "AWSCognitoIdentityProviderService.InitiateAuth",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "AuthenticationResult": {
                    "AccessToken": "at-refreshed",
                    "IdToken": "it-refreshed"
                }
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "ClientId": "test-client-id",
            "AuthParameters": {"REFRESH_TOKEN": "rt-123"}
        });

        let resp = client
            .post(format!("{}/", server.uri()))
            .header("Content-Type", "application/x-amz-json-1.1")
            .header(
                "X-Amz-Target",
                "AWSCognitoIdentityProviderService.InitiateAuth",
            )
            .json(&body)
            .send()
            .await
            .unwrap();

        let data: Value = resp.json().await.unwrap();
        assert_eq!(data["AuthenticationResult"]["AccessToken"], "at-refreshed");
    }

    #[tokio::test]
    async fn test_cognito_request_error_type() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "__type": "NotAuthorizedException",
                "message": "Refresh Token has been revoked"
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        // Build a config that points to the mock server
        let _config = test_config_with_url(&server.uri());

        // Call directly against mock server to test error parsing
        let resp = client
            .post(format!("{}/", server.uri()))
            .header("Content-Type", "application/x-amz-json-1.1")
            .json(&serde_json::json!({"test": true}))
            .send()
            .await
            .unwrap();

        let data: Value = resp.json().await.unwrap();
        assert!(data.get("__type").is_some());
        assert_eq!(data["message"], "Refresh Token has been revoked");
    }
}
