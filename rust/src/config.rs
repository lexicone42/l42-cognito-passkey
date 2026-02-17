//! Application configuration via environment variables.
//!
//! Mirrors the FastAPI Settings class in `app/config.py`.

use std::env;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub cognito_client_id: String,
    pub cognito_client_secret: String,
    pub cognito_user_pool_id: String,
    pub cognito_domain: String,
    pub cognito_region: String,
    pub session_secret: String,
    pub frontend_url: String,
    pub port: u16,
    pub session_backend: String,
    pub dynamodb_table: String,
    pub dynamodb_endpoint: String,
    pub session_https_only: bool,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Required: `COGNITO_CLIENT_ID`, `COGNITO_USER_POOL_ID`, `COGNITO_DOMAIN`.
    /// All others have sensible defaults matching the FastAPI backend.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            cognito_client_id: required_env("COGNITO_CLIENT_ID")?,
            cognito_client_secret: env::var("COGNITO_CLIENT_SECRET").unwrap_or_default(),
            cognito_user_pool_id: required_env("COGNITO_USER_POOL_ID")?,
            cognito_domain: required_env("COGNITO_DOMAIN")?,
            cognito_region: env::var("COGNITO_REGION").unwrap_or_else(|_| "us-west-2".into()),
            session_secret: env::var("SESSION_SECRET")
                .unwrap_or_else(|_| "change-me-in-production".into()),
            frontend_url: env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3000".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3001),
            session_backend: env::var("SESSION_BACKEND")
                .unwrap_or_else(|_| "memory".into()),
            dynamodb_table: env::var("DYNAMODB_TABLE")
                .unwrap_or_else(|_| "l42_sessions".into()),
            dynamodb_endpoint: env::var("DYNAMODB_ENDPOINT").unwrap_or_default(),
            session_https_only: env::var("SESSION_HTTPS_ONLY")
                .map(|v| v == "true" || v == "1" || v == "True")
                .unwrap_or(false),
        })
    }

    /// Cognito OIDC issuer URL.
    pub fn cognito_issuer(&self) -> String {
        format!(
            "https://cognito-idp.{}.amazonaws.com/{}",
            self.cognito_region, self.cognito_user_pool_id
        )
    }

    /// JWKS endpoint URL.
    pub fn jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.cognito_issuer())
    }

    /// Cognito IDP endpoint for InitiateAuth etc.
    pub fn cognito_idp_url(&self) -> String {
        format!(
            "https://cognito-idp.{}.amazonaws.com/",
            self.cognito_region
        )
    }

    /// Cognito OAuth2 token endpoint.
    pub fn cognito_token_url(&self) -> String {
        format!("https://{}/oauth2/token", self.cognito_domain)
    }
}

/// Configuration for testing — all fields settable directly.
impl Config {
    pub fn test_default() -> Self {
        Self {
            cognito_client_id: "test-client-id".into(),
            cognito_client_secret: String::new(),
            cognito_user_pool_id: "us-west-2_test123".into(),
            cognito_domain: "test.auth.us-west-2.amazoncognito.com".into(),
            cognito_region: "us-west-2".into(),
            session_secret: "test-secret-key".into(),
            frontend_url: "http://localhost:3000".into(),
            port: 3001,
            session_backend: "memory".into(),
            dynamodb_table: "l42_sessions".into(),
            dynamodb_endpoint: String::new(),
            session_https_only: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingEnv(String),
}

fn required_env(key: &str) -> Result<String, ConfigError> {
    env::var(key).map_err(|_| ConfigError::MissingEnv(key.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_creates_valid_config() {
        let cfg = Config::test_default();
        assert_eq!(cfg.cognito_client_id, "test-client-id");
        assert_eq!(cfg.cognito_region, "us-west-2");
        assert_eq!(cfg.port, 3001);
        assert!(!cfg.session_https_only);
    }

    #[test]
    fn test_derived_urls() {
        let cfg = Config::test_default();
        assert_eq!(
            cfg.cognito_issuer(),
            "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test123"
        );
        assert_eq!(
            cfg.jwks_url(),
            "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test123/.well-known/jwks.json"
        );
        assert_eq!(
            cfg.cognito_idp_url(),
            "https://cognito-idp.us-west-2.amazonaws.com/"
        );
        assert_eq!(
            cfg.cognito_token_url(),
            "https://test.auth.us-west-2.amazoncognito.com/oauth2/token"
        );
    }

    #[test]
    fn test_from_env_missing_required() {
        // Clear any existing env vars to ensure this fails
        env::remove_var("COGNITO_CLIENT_ID");
        let result = Config::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("COGNITO_CLIENT_ID"));
    }
}
