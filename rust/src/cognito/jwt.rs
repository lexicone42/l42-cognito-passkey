//! JWT decode, verify, and JWKS cache.
//!
//! Provides both unverified decode (for server-trusted tokens already in
//! the session) and full RS256 verification via JWKS (for tokens received
//! from the browser in POST /auth/session).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
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

    /// A cache pre-seeded with keys that never fetches. For tests, or for a
    /// deployment that pins its signing keys.
    pub fn with_keys(keys: HashMap<String, DecodingKey>) -> Self {
        Self {
            keys: RwLock::new(Some((keys, Instant::now()))),
            ttl: Duration::from_secs(3600),
            http_client: reqwest::Client::new(),
        }
    }

    /// Fetch or return cached JWKS keys.
    pub async fn get_keys(&self, jwks_url: &str) -> Result<HashMap<String, DecodingKey>, JwtError> {
        // Try read lock first
        {
            let guard = self.keys.read().await;
            if let Some((keys, fetched_at)) = guard.as_ref()
                && fetched_at.elapsed() < self.ttl
            {
                return Ok(keys.clone());
            }
        }
        self.refetch(jwks_url).await
    }

    /// Fetch the JWKS now, replacing whatever is cached. Used on a cache miss
    /// and when a token names a `kid` the cache has not seen: Cognito rotates
    /// signing keys by publishing a new `kid`, and a cache that waited out its
    /// TTL would reject every fresh login for up to an hour.
    pub async fn refetch(&self, jwks_url: &str) -> Result<HashMap<String, DecodingKey>, JwtError> {
        let resp = self
            .http_client
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| JwtError::JwksFetchFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(JwtError::JwksFetchFailed(format!("HTTP {}", resp.status())));
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

    // Get signing keys; an unknown kid means a rotation happened since the
    // last fetch, so look once more before giving up.
    let keys = jwks_cache.get_keys(&config.jwks_url()).await?;
    let decoding_key = match keys.get(&kid) {
        Some(k) => k.clone(),
        None => {
            let fresh = jwks_cache.refetch(&config.jwks_url()).await?;
            fresh.get(&kid).cloned().ok_or(JwtError::KeyNotFound(kid))?
        }
    };

    // Validate
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&config.cognito_issuer()]);
    let mut audiences: Vec<&str> = vec![&config.cognito_client_id];
    for aud in &config.additional_audience {
        audiences.push(aud.as_str());
    }
    validation.set_audience(&audiences);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| JwtError::Validation(e.to_string()))?;

    // Cognito signs access tokens with the same keys and issuer; only an ID
    // token carries the identity claims a session is built from.
    if token_data.claims.token_use.as_deref() != Some("id") {
        return Err(JwtError::Validation("token_use is not 'id'".into()));
    }

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

    // ───── Verification against real RS256 signatures ─────

    struct Signer {
        key: jsonwebtoken::EncodingKey,
        kid: String,
        jwk: serde_json::Value,
        decoding: DecodingKey,
    }

    fn signer(kid: &str) -> Signer {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let n = URL_SAFE_NO_PAD.encode(private.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(private.e().to_bytes_be());
        // jsonwebtoken's `from_rsa_der` wants PKCS#1 (RSAPrivateKey), not PKCS#8.
        let der = private.to_pkcs1_der().unwrap();
        Signer {
            key: jsonwebtoken::EncodingKey::from_rsa_der(der.as_bytes()),
            kid: kid.into(),
            jwk: serde_json::json!({"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": n, "e": e}),
            decoding: DecodingKey::from_rsa_components(&n, &e).unwrap(),
        }
    }

    fn signed(s: &Signer, config: &Config, token_use: &str) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let claims = serde_json::json!({
            "sub": "user-1", "email": "u@example.com", "iss": config.cognito_issuer(),
            "aud": config.cognito_client_id, "exp": exp, "iat": exp - 600, "token_use": token_use,
        });
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some(s.kid.clone());
        jsonwebtoken::encode(&header, &claims, &s.key).unwrap()
    }

    #[tokio::test]
    async fn verify_accepts_an_id_token_and_rejects_an_access_token() {
        let config = Config::test_default();
        let s = signer("k1");
        let cache = JwksCache::with_keys(HashMap::from([(s.kid.clone(), s.decoding.clone())]));

        let claims = verify_id_token(&signed(&s, &config, "id"), &cache, &config)
            .await
            .unwrap();
        assert_eq!(claims.sub, "user-1");

        let err = verify_id_token(&signed(&s, &config, "access"), &cache, &config)
            .await
            .expect_err("an access token must not open a session");
        assert!(err.to_string().contains("token_use"), "got: {err}");
    }

    #[tokio::test]
    async fn an_unknown_kid_refetches_the_jwks_once_so_rotation_does_not_lock_users_out() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let mut config = Config::test_default();
        config.cognito_endpoint = server.uri();
        let old = signer("old-kid");
        let new = signer("new-kid");
        // The JWKS now publishes only the new key.
        Mock::given(method("GET"))
            .and(path_regex(r".*/\.well-known/jwks\.json$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"keys": [new.jwk.clone()]})),
            )
            // One refetch for the rotated key, one for the ghost below; never more.
            .expect(2)
            .mount(&server)
            .await;
        // The cache still holds the old key, well within its TTL.
        let cache = JwksCache::with_keys(HashMap::from([(old.kid.clone(), old.decoding.clone())]));

        let claims = verify_id_token(&signed(&new, &config, "id"), &cache, &config)
            .await
            .expect("a token under the rotated key must verify after one refetch");
        assert_eq!(claims.sub, "user-1");

        // A token under a kid nobody publishes still fails, after the refetch.
        let ghost = signer("ghost");
        let err = verify_id_token(&signed(&ghost, &config, "id"), &cache, &config)
            .await
            .unwrap_err();
        assert!(
            matches!(err, JwtError::KeyNotFound(ref k) if k == "ghost"),
            "got: {err:?}"
        );
    }
}
