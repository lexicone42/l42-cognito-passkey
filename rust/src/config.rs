//! Application configuration via environment variables.
//!
//! Application configuration from environment variables.

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
    pub cookie_domain: Option<String>,
    pub auth_path_prefix: String,
    pub callback_use_origin: bool,
    pub callback_allowed_origins: Vec<String>,
    pub aaguid_allowlist: Vec<String>,
    pub require_device_bound: bool,
    pub service_token: Option<String>,
    /// Additional client IDs accepted as valid JWT audiences (for dual-client setups).
    pub additional_audience: Vec<String>,
    /// DynamoDB table for resource entity ownership lookups (closes S1 gap).
    /// When set, the `/auth/authorize` endpoint queries this table to verify
    /// `resource.owner` instead of trusting the client-provided value.
    pub entity_table: Option<String>,
    /// Strict ownership enforcement for `:own` actions. When true, an `:own`
    /// action is denied unless the entity provider can positively confirm the
    /// principal owns the resource — untracked resources and requests with no
    /// entity provider configured are denied rather than trusting the client.
    /// Defaults to false for backward compatibility; will become the default
    /// at 1.0. Env: `ENTITY_STRICT_OWNERSHIP`.
    pub entity_strict_ownership: bool,
    /// Override base URL for Cognito IDP + token endpoints (test only — points
    /// the real `refresh_tokens`/`exchange_code_for_tokens` at a mock server).
    /// Empty in production. Env: `COGNITO_ENDPOINT`.
    pub cognito_endpoint: String,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Required: `COGNITO_CLIENT_ID`, `COGNITO_USER_POOL_ID`, `COGNITO_DOMAIN`, `SESSION_SECRET`.
    /// All others have sensible defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        // Check order matters for error messages: client id first (matches docs).
        let cognito_client_id = required_env("COGNITO_CLIENT_ID")?;
        let cognito_user_pool_id = required_env("COGNITO_USER_POOL_ID")?;
        Ok(Self {
            cognito_client_id,
            cognito_client_secret: env::var("COGNITO_CLIENT_SECRET").unwrap_or_default(),
            cognito_domain: required_env("COGNITO_DOMAIN")?,
            // Region default is DERIVED from the pool id (issue #28): pool ids are
            // always `<region>_<id>`, so a hardcoded default (us-west-2) silently
            // produced a wrong JWKS/issuer URL for pools in any other region —
            // hosted-UI login kept working while every direct login died with a
            // generic 403. COGNITO_REGION remains as an explicit override.
            cognito_region: env::var("COGNITO_REGION").unwrap_or_else(|_| {
                derive_region_from_pool_id(&cognito_user_pool_id)
                    .unwrap_or_else(|| "us-west-2".into())
            }),
            cognito_user_pool_id,
            session_secret: required_env("SESSION_SECRET")?,
            frontend_url: env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3000".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3001),
            session_backend: env::var("SESSION_BACKEND").unwrap_or_else(|_| {
                // Auto-detect Lambda: default to DynamoDB since in-memory sessions
                // don't persist across Lambda invocations (issue #24).
                if env::var("AWS_LAMBDA_FUNCTION_NAME").is_ok() {
                    "dynamodb".into()
                } else {
                    "memory".into()
                }
            }),
            dynamodb_table: env::var("DYNAMODB_TABLE").unwrap_or_else(|_| "l42_sessions".into()),
            dynamodb_endpoint: env::var("DYNAMODB_ENDPOINT").unwrap_or_default(),
            session_https_only: env::var("SESSION_HTTPS_ONLY")
                .map(|v| v == "true" || v == "1" || v == "True")
                .unwrap_or(false),
            cookie_domain: env::var("COOKIE_DOMAIN").ok().filter(|s| !s.is_empty()),
            auth_path_prefix: normalize_path_prefix(
                &env::var("AUTH_PATH_PREFIX").unwrap_or_else(|_| "/auth".into()),
            ),
            callback_use_origin: env::var("CALLBACK_USE_ORIGIN")
                .map(|v| v == "true" || v == "1" || v == "True")
                .unwrap_or(false),
            callback_allowed_origins: env::var("CALLBACK_ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            aaguid_allowlist: env::var("AAGUID_ALLOWLIST")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            require_device_bound: env::var("REQUIRE_DEVICE_BOUND")
                .map(|v| v == "true" || v == "1" || v == "True")
                .unwrap_or(false),
            service_token: env::var("SERVICE_TOKEN").ok().filter(|s| !s.is_empty()),
            additional_audience: env::var("ADDITIONAL_AUDIENCE")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            entity_table: env::var("ENTITY_TABLE").ok().filter(|s| !s.is_empty()),
            entity_strict_ownership: env::var("ENTITY_STRICT_OWNERSHIP")
                .map(|v| v == "true" || v == "1" || v == "True")
                .unwrap_or(false),
            cognito_endpoint: env::var("COGNITO_ENDPOINT").unwrap_or_default(),
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
        if !self.cognito_endpoint.is_empty() {
            return format!("{}/", self.cognito_endpoint.trim_end_matches('/'));
        }
        format!("https://cognito-idp.{}.amazonaws.com/", self.cognito_region)
    }

    /// Cognito OAuth2 token endpoint.
    pub fn cognito_token_url(&self) -> String {
        if !self.cognito_endpoint.is_empty() {
            return format!("{}/oauth2/token", self.cognito_endpoint.trim_end_matches('/'));
        }
        format!("https://{}/oauth2/token", self.cognito_domain)
    }

    /// If the configured region disagrees with the region encoded in the pool
    /// id, return `(pool_region, configured_region)`. Used for a startup
    /// warning: with an explicit-but-wrong `COGNITO_REGION`, JWKS/issuer URLs
    /// 404 and every direct login fails with a generic 403 (issue #28).
    pub fn region_pool_mismatch(&self) -> Option<(String, String)> {
        let pool_region = derive_region_from_pool_id(&self.cognito_user_pool_id)?;
        if pool_region != self.cognito_region {
            Some((pool_region, self.cognito_region.clone()))
        } else {
            None
        }
    }
}

/// Extract the AWS region from a Cognito user pool id (`<region>_<id>`).
///
/// Returns `None` when the prefix doesn't look like a region (no `-`), so
/// degenerate values fall back to the caller's default rather than producing
/// an obviously-broken URL.
fn derive_region_from_pool_id(pool_id: &str) -> Option<String> {
    let prefix = pool_id.split('_').next()?;
    if !prefix.is_empty() && prefix.contains('-') {
        Some(prefix.to_string())
    } else {
        None
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
            cognito_endpoint: String::new(),
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

/// Normalize a path prefix: ensure leading `/`, strip trailing `/`.
/// Examples: `"_auth"` → `"/_auth"`, `"/auth/"` → `"/auth"`, `""` → `""`.
fn normalize_path_prefix(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let with_slash = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    with_slash.trim_end_matches('/').to_string()
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
        assert_eq!(cfg.cookie_domain, None);
        assert_eq!(cfg.auth_path_prefix, "/auth");
        assert_eq!(cfg.entity_table, None);
        assert!(!cfg.entity_strict_ownership);
    }

    #[test]
    fn test_normalize_path_prefix() {
        assert_eq!(normalize_path_prefix("/auth"), "/auth");
        assert_eq!(normalize_path_prefix("_auth"), "/_auth");
        assert_eq!(normalize_path_prefix("/auth/"), "/auth");
        assert_eq!(normalize_path_prefix("/_auth/"), "/_auth");
        assert_eq!(normalize_path_prefix(""), "");
        assert_eq!(normalize_path_prefix("  "), "");
        assert_eq!(normalize_path_prefix("api/auth"), "/api/auth");
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
        // Clear any existing env vars to ensure this fails.
        // SAFETY: This test runs single-threaded — no concurrent env access.
        unsafe { env::remove_var("COGNITO_CLIENT_ID") };
        let result = Config::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("COGNITO_CLIENT_ID"));
    }

    // ── Region derivation from pool id (issue #28) ──

    #[test]
    fn test_derive_region_from_pool_id() {
        assert_eq!(
            derive_region_from_pool_id("us-east-1_AbC123"),
            Some("us-east-1".into())
        );
        assert_eq!(
            derive_region_from_pool_id("ap-southeast-2_Xy"),
            Some("ap-southeast-2".into())
        );
        assert_eq!(
            derive_region_from_pool_id("us-gov-west-1_Z9"),
            Some("us-gov-west-1".into())
        );
        // Degenerate values (no region-shaped prefix) → None, caller falls back
        assert_eq!(derive_region_from_pool_id("nounderscore"), None);
        assert_eq!(derive_region_from_pool_id("test_pool"), None);
        assert_eq!(derive_region_from_pool_id("_leading"), None);
        assert_eq!(derive_region_from_pool_id(""), None);
    }

    #[test]
    fn test_region_pool_mismatch_detected() {
        let mut cfg = Config::test_default();
        // test_default: pool "us-west-2_test123", region "us-west-2" → consistent
        assert_eq!(cfg.region_pool_mismatch(), None);

        // Explicit wrong region (the issue #28 field failure): pool in us-east-1,
        // region configured (or defaulted pre-fix) to us-west-2.
        cfg.cognito_user_pool_id = "us-east-1_AbC123".into();
        assert_eq!(
            cfg.region_pool_mismatch(),
            Some(("us-east-1".into(), "us-west-2".into()))
        );

        // Degenerate pool id → no basis for a mismatch claim
        cfg.cognito_user_pool_id = "weird".into();
        assert_eq!(cfg.region_pool_mismatch(), None);
    }

    #[test]
    fn test_jwks_url_uses_derived_region_shape() {
        // The exact field-failure shape from issue #28: with the region matching
        // the pool id, the JWKS URL is well-formed for the pool's real region.
        let mut cfg = Config::test_default();
        cfg.cognito_user_pool_id = "us-east-1_AbC123".into();
        cfg.cognito_region = "us-east-1".into(); // what derivation now produces
        assert_eq!(
            cfg.jwks_url(),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbC123/.well-known/jwks.json"
        );
    }
}
