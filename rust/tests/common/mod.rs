//! Test utilities: RSA keypair, JWT factory, test app builder, wiremock setup.

#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use l42_token_handler::cedar::engine::CedarState;
use l42_token_handler::cognito::jwt::JwksCache;
use l42_token_handler::config::Config;
use l42_token_handler::session::memory::InMemoryBackend;
use l42_token_handler::session::middleware::SessionLayer;
use l42_token_handler::session::AnyBackend;
use l42_token_handler::{create_app, AppState};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

/// Test RSA keypair for signing JWTs.
pub struct TestKeys {
    pub private_key: RsaPrivateKey,
    pub kid: String,
}

impl TestKeys {
    pub fn generate() -> Self {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");
        Self {
            private_key,
            kid: "test-key-1".into(),
        }
    }

    /// Build a signed JWT with the given claims.
    pub fn sign_jwt(&self, claims: &serde_json::Value) -> String {
        let der = self
            .private_key
            .to_pkcs8_der()
            .expect("failed to encode private key");
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_der(der.as_bytes());

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        jsonwebtoken::encode(&header, claims, &encoding_key).expect("failed to sign JWT")
    }

    /// Build an unsigned JWT (for session-stored tokens that skip verification).
    pub fn make_unsigned_jwt(claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT","kid":"test-key-1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-signature");
        format!("{header}.{payload}.{sig}")
    }

    /// Build JWKS JSON response for wiremock.
    pub fn jwks_json(&self) -> serde_json::Value {
        let public_key = self.private_key.to_public_key();
        let der = public_key
            .to_pkcs1_der()
            .expect("failed to encode public key");

        // Parse the DER to get n and e components
        let (n, e) = parse_rsa_public_key_der(der.as_bytes());

        json!({
            "keys": [{
                "kid": self.kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": URL_SAFE_NO_PAD.encode(&n),
                "e": URL_SAFE_NO_PAD.encode(&e)
            }]
        })
    }
}

/// Parse RSA public key DER to get (n, e) byte vectors.
fn parse_rsa_public_key_der(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // PKCS#1 RSAPublicKey is: SEQUENCE { n INTEGER, e INTEGER }
    // We'll use a simple DER parser
    let mut pos = 0;

    // Outer SEQUENCE
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_seq_len, consumed) = parse_der_length(&der[pos..]);
    pos += consumed;

    // n INTEGER
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (n_len, consumed) = parse_der_length(&der[pos..]);
    pos += consumed;
    let mut n = der[pos..pos + n_len].to_vec();
    // Strip leading zero byte if present (DER encoding of positive integers)
    if !n.is_empty() && n[0] == 0x00 {
        n.remove(0);
    }
    pos += n_len;

    // e INTEGER
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (e_len, consumed) = parse_der_length(&der[pos..]);
    pos += consumed;
    let e = der[pos..pos + e_len].to_vec();

    (n, e)
}

fn parse_der_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        (len, 1 + num_bytes)
    }
}

/// Standard test claims for a user with groups.
pub fn test_claims(sub: &str, email: &str, groups: &[&str]) -> serde_json::Value {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    json!({
        "sub": sub,
        "email": email,
        "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test123",
        "aud": "test-client-id",
        "exp": exp,
        "iat": exp - 3600,
        "token_use": "id",
        "cognito:groups": groups
    })
}

/// Build expired test claims.
pub fn expired_claims(sub: &str) -> serde_json::Value {
    json!({
        "sub": sub,
        "email": "expired@example.com",
        "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test123",
        "aud": "test-client-id",
        "exp": 1000,
        "iat": 900,
        "token_use": "id",
        "cognito:groups": ["users"]
    })
}

/// Build a test app with InMemoryBackend and optional Cedar.
pub fn build_test_app(with_cedar: bool) -> (axum::Router, Arc<AppState>) {
    let config = Config::test_default();
    let http_client = reqwest::Client::new();
    let jwks_cache = Arc::new(JwksCache::new(http_client.clone()));

    let cedar = if with_cedar {
        let cedar_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cedar");
        CedarState::init(
            &cedar_dir.join("schema.cedarschema.json"),
            &cedar_dir.join("policies"),
        )
        .ok()
    } else {
        None
    };

    let session_backend = AnyBackend::Memory(InMemoryBackend::new());
    let session_layer = Arc::new(SessionLayer {
        backend: Arc::new(session_backend),
        secret: config.session_secret.clone(),
        https_only: config.session_https_only,
        cookie_domain: config.cookie_domain.clone(),
    });

    let state = Arc::new(AppState {
        config,
        http_client,
        jwks_cache,
        cedar,
        session_layer,
    });

    let app = create_app(state.clone());
    (app, state)
}

/// Build a test app with a custom Config and optional Cedar.
pub fn build_test_app_with_config(config: Config, with_cedar: bool) -> (axum::Router, Arc<AppState>) {
    let http_client = reqwest::Client::new();
    let jwks_cache = Arc::new(JwksCache::new(http_client.clone()));

    let cedar = if with_cedar {
        let cedar_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cedar");
        CedarState::init(
            &cedar_dir.join("schema.cedarschema.json"),
            &cedar_dir.join("policies"),
        )
        .ok()
    } else {
        None
    };

    let session_backend = AnyBackend::Memory(InMemoryBackend::new());
    let session_layer = Arc::new(SessionLayer {
        backend: Arc::new(session_backend),
        secret: config.session_secret.clone(),
        https_only: config.session_https_only,
        cookie_domain: config.cookie_domain.clone(),
    });

    let state = Arc::new(AppState {
        config,
        http_client,
        jwks_cache,
        cedar,
        session_layer,
    });

    let app = create_app(state.clone());
    (app, state)
}

/// Helper to create a session cookie by calling POST /auth/session.
/// Returns the session cookie value for subsequent requests.
pub async fn create_auth_session(
    app: &axum::Router,
    access_token: &str,
    id_token: &str,
    refresh_token: Option<&str>,
) -> Option<String> {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let body = json!({
        "access_token": access_token,
        "id_token": id_token,
        "refresh_token": refresh_token,
        "auth_method": "passkey"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/auth/session")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();

    // Extract session cookie from Set-Cookie header
    if response.status() == StatusCode::OK {
        response
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| {
                s.split(';')
                    .next()
                    .and_then(|c| c.strip_prefix("l42_session="))
                    .map(String::from)
            })
    } else {
        None
    }
}
