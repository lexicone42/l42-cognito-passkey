//! JWT decode, verify, and JWKS cache.
//!
//! Provides both unverified decode (for server-trusted tokens already in
//! the session) and full RS256 verification via JWKS (for tokens received
//! from the browser in POST /auth/session).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::config::Config;

/// JWT claims from a Cognito ID token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub token_use: Option<String>,
    #[serde(rename = "cognito:groups", default)]
    pub cognito_groups: Vec<String>,
}

/// JWKS key entry from Cognito's /.well-known/jwks.json
#[derive(Debug, Clone, Deserialize)]
pub struct JwkKey {
    pub kid: String,
    pub kty: String,
    pub n: String,
    pub e: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,
}

/// JWKS response from Cognito.
#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

/// Cached JWKS keys with TTL-based expiry.
pub struct JwksCache {
    keys: RwLock<Option<(HashMap<String, DecodingKey>, Instant)>>,
    ttl: Duration,
    http_client: reqwest::Client,
}

impl JwksCache {
    pub fn new(http_client: reqwest::Client) -> Self {
        Self {
            keys: RwLock::new(None),
            ttl: Duration::from_secs(3600), // 1 hour, matching Python backend
            http_client,
        }
    }

    /// Fetch or return cached JWKS keys.
    pub async fn get_keys(
        &self,
        jwks_url: &str,
    ) -> Result<HashMap<String, DecodingKey>, JwtError> {
        // Try read lock first
        {
            let guard = self.keys.read().await;
            if let Some((keys, fetched_at)) = guard.as_ref()
                && fetched_at.elapsed() < self.ttl
            {
                return Ok(keys.clone());
            }
        }

        // Cache miss or expired — fetch and update
        let resp = self
            .http_client
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| JwtError::JwksFetchFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(JwtError::JwksFetchFailed(format!(
                "HTTP {}",
                resp.status()
            )));
        }

        let jwks: JwksResponse = resp
            .json()
            .await
            .map_err(|e| JwtError::JwksFetchFailed(e.to_string()))?;

        let mut key_map = HashMap::new();
        for key in &jwks.keys {
            if let Ok(dk) = DecodingKey::from_rsa_components(&key.n, &key.e) {
                key_map.insert(key.kid.clone(), dk);
            }
        }

        let mut guard = self.keys.write().await;
        *guard = Some((key_map.clone(), Instant::now()));

        Ok(key_map)
    }

    /// Clear the cache. For testing.
    pub async fn clear(&self) {
        let mut guard = self.keys.write().await;
        *guard = None;
    }
}

/// Decode a JWT payload without signature verification.
///
/// Used for server-trusted tokens already stored in the session.
/// Decode a JWT payload without signature verification (for reading claims).
pub fn decode_jwt_unverified(token: &str) -> Result<Claims, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat);
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| {
            // Try with padding
            let padded = match parts[1].len() % 4 {
                2 => format!("{}==", parts[1]),
                3 => format!("{}=", parts[1]),
                _ => parts[1].to_string(),
            };
            URL_SAFE_NO_PAD.decode(&padded)
        })
        .map_err(|_| JwtError::InvalidFormat)?;

    serde_json::from_slice(&payload_bytes).map_err(|_| JwtError::InvalidFormat)
}

/// Check if a JWT is expired based on its `exp` claim.
pub fn is_token_expired(token: &str) -> bool {
    match decode_jwt_unverified(token) {
        Ok(claims) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            claims.exp.is_none_or(|exp| now >= exp)
        }
        Err(_) => true,
    }
}

/// Verify an ID token's RS256 signature, issuer, audience, and expiry.
///
/// Used by POST /auth/session to ensure tokens sent from the browser
/// were actually issued by Cognito.
pub async fn verify_id_token(
    token: &str,
    jwks_cache: &JwksCache,
    config: &Config,
) -> Result<Claims, JwtError> {
    // Extract kid from header
    let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::InvalidFormat)?;
    let kid = header.kid.ok_or(JwtError::MissingKid)?;

    // Get signing keys
    let keys = jwks_cache.get_keys(&config.jwks_url()).await?;
    let decoding_key = keys.get(&kid).ok_or(JwtError::KeyNotFound(kid))?;

    // Validate
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&config.cognito_issuer()]);
    validation.set_audience(&[&config.cognito_client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    let token_data =
        decode::<Claims>(token, decoding_key, &validation).map_err(|e| JwtError::Validation(e.to_string()))?;

    Ok(token_data.claims)
}

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Invalid JWT format")]
    InvalidFormat,

    #[error("Token missing kid header")]
    MissingKid,

    #[error("Signing key not found for kid: {0}")]
    KeyNotFound(String),

    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),

    #[error("JWT validation failed: {0}")]
    Validation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_unsigned_jwt(claims: &serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT","kid":"test-key-1"}"#);
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"fake-signature");
        format!("{}.{}.{}", header, payload, sig)
    }

    #[test]
    fn test_decode_jwt_unverified() {
        let claims = serde_json::json!({
            "sub": "user-123",
            "email": "test@example.com",
            "iss": "https://cognito-idp.us-west-2.amazonaws.com/pool123",
            "aud": "client-id",
            "exp": 9999999999u64,
            "iat": 1700000000u64,
            "token_use": "id",
            "cognito:groups": ["admin", "users"]
        });
        let token = make_unsigned_jwt(&claims);
        let decoded = decode_jwt_unverified(&token).unwrap();

        assert_eq!(decoded.sub, "user-123");
        assert_eq!(decoded.email, Some("test@example.com".into()));
        assert_eq!(decoded.cognito_groups, vec!["admin", "users"]);
    }

    #[test]
    fn test_decode_jwt_unverified_no_groups() {
        let claims = serde_json::json!({
            "sub": "user-456",
            "exp": 9999999999u64
        });
        let token = make_unsigned_jwt(&claims);
        let decoded = decode_jwt_unverified(&token).unwrap();

        assert_eq!(decoded.sub, "user-456");
        assert!(decoded.cognito_groups.is_empty());
        assert!(decoded.email.is_none());
    }

    #[test]
    fn test_decode_invalid_format() {
        assert!(decode_jwt_unverified("not-a-jwt").is_err());
        assert!(decode_jwt_unverified("a.b").is_err());
        assert!(decode_jwt_unverified("").is_err());
    }

    #[test]
    fn test_is_token_expired_valid() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let claims = serde_json::json!({"sub": "u", "exp": future_exp});
        let token = make_unsigned_jwt(&claims);
        assert!(!is_token_expired(&token));
    }

    #[test]
    fn test_is_token_expired_past() {
        let claims = serde_json::json!({"sub": "u", "exp": 1000});
        let token = make_unsigned_jwt(&claims);
        assert!(is_token_expired(&token));
    }

    #[test]
    fn test_is_token_expired_no_exp() {
        let claims = serde_json::json!({"sub": "u"});
        let token = make_unsigned_jwt(&claims);
        assert!(is_token_expired(&token));
    }

    #[test]
    fn test_is_token_expired_garbage() {
        assert!(is_token_expired("garbage"));
    }
}
