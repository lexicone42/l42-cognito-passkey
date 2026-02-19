//! Integration tests for all HTTP route handlers.
//!
//! Uses Tower's `oneshot()` to test the full Axum app including middleware.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ciborium::Value as CborValue;
use common::{build_test_app, build_test_app_with_config, expired_claims, test_claims, TestKeys};
use l42_token_handler::config::Config;
use l42_token_handler::session::cookie::sign_session_id;
use l42_token_handler::session::{SessionBackend, SessionData};
use l42_token_handler::types::SessionTokens;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Helper to read response body as JSON.
async fn body_json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Helper to store tokens directly in the session backend.
async fn seed_session(
    state: &l42_token_handler::AppState,
    session_id: &str,
    tokens: &SessionTokens,
) {
    let mut data = SessionData::new();
    data.set("tokens", serde_json::to_value(tokens).unwrap());
    state.session_layer.backend.save(session_id, &data).await;
}

/// Build a request with session cookie.
fn request_with_session(method: &str, uri: &str, session_id: &str, secret: &str) -> Request<Body> {
    let signed = sign_session_id(secret.as_bytes(), session_id);
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::empty())
        .unwrap()
}

fn request_with_session_and_csrf(
    method: &str,
    uri: &str,
    session_id: &str,
    secret: &str,
) -> Request<Body> {
    let signed = sign_session_id(secret.as_bytes(), session_id);
    Request::builder()
        .method(method)
        .uri(uri)
        .header("Cookie", format!("l42_session={}", signed))
        .header("X-L42-CSRF", "1")
        .body(Body::empty())
        .unwrap()
}

// ───── GET /health ─────

#[tokio::test]
async fn test_health_with_cedar() {
    let (app, _state) = build_test_app(true);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["mode"], "token-handler");
    assert_eq!(body["cedar"], "ready");
}

#[tokio::test]
async fn test_health_without_cedar() {
    let (app, _state) = build_test_app(false);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["cedar"], "unavailable");
}

// ───── GET /auth/token ─────

#[tokio::test]
async fn test_token_returns_tokens() {
    let (app, state) = build_test_app(false);
    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-123".into(),
        id_token,
        refresh_token: Some("rt-456".into()),
        auth_method: Some("passkey".into()),
    };
    seed_session(&state, "sid-1", &tokens).await;

    let req = request_with_session("GET", "/auth/token", "sid-1", &state.config.session_secret);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["access_token"], "at-123");
    assert_eq!(body["auth_method"], "passkey");
    // refresh_token must never be in the response
    assert!(body.get("refresh_token").is_none());
}

#[tokio::test]
async fn test_token_no_session() {
    let (app, _state) = build_test_app(false);

    let req = Request::builder()
        .uri("/auth/token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    // No session cookie → no tokens → 401
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_token_expired() {
    let (app, state) = build_test_app(false);
    let claims = expired_claims("user-1");
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-expired".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-exp", &tokens).await;

    let req = request_with_session(
        "GET",
        "/auth/token",
        "sid-exp",
        &state.config.session_secret,
    );
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "Token expired");
}

// ───── POST /auth/session (CSRF required) ─────

#[tokio::test]
async fn test_session_requires_csrf() {
    let (app, _state) = build_test_app(false);

    let body = json!({
        "access_token": "at",
        "id_token": "it",
        "auth_method": "passkey"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/auth/session")
        .header("Content-Type", "application/json")
        // No X-L42-CSRF header
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_session_missing_tokens() {
    let (app, _state) = build_test_app(false);

    let body = json!({
        "access_token": "",
        "id_token": "some-token"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/auth/session")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "Missing access_token or id_token");
}

// ───── POST /auth/logout ─────

#[tokio::test]
async fn test_logout_destroys_session() {
    let (app, state) = build_test_app(false);
    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-123".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-logout", &tokens).await;

    let req = request_with_session_and_csrf(
        "POST",
        "/auth/logout",
        "sid-logout",
        &state.config.session_secret,
    );
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["success"], true);

    // Session should be destroyed
    use l42_token_handler::session::SessionBackend;
    let loaded = state.session_layer.backend.load("sid-logout").await;
    assert!(loaded.is_none());
}

#[tokio::test]
async fn test_logout_requires_csrf() {
    let (app, state) = build_test_app(false);

    let req = request_with_session(
        "POST",
        "/auth/logout",
        "sid-1",
        &state.config.session_secret,
    );
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ───── GET /auth/me ─────

#[tokio::test]
async fn test_me_returns_user_info() {
    let (app, state) = build_test_app(false);
    let claims = test_claims("user-sub-1", "me@example.com", &["admin", "users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-me".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-me", &tokens).await;

    let req = request_with_session("GET", "/auth/me", "sid-me", &state.config.session_secret);
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["email"], "me@example.com");
    assert_eq!(body["sub"], "user-sub-1");
    let groups = body["groups"].as_array().unwrap();
    assert!(groups.contains(&json!("admin")));
    assert!(groups.contains(&json!("users")));
}

#[tokio::test]
async fn test_me_no_session() {
    let (app, _state) = build_test_app(false);

    let req = Request::builder()
        .uri("/auth/me")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ───── POST /auth/authorize ─────

#[tokio::test]
async fn test_authorize_admin_allowed() {
    let (app, state) = build_test_app(true);
    let claims = test_claims("admin-sub", "admin@example.com", &["admin"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-admin".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-admin", &tokens).await;

    let body = json!({"action": "admin:delete-user"});
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-admin");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/authorize")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["authorized"], true);
}

#[tokio::test]
async fn test_authorize_user_denied_admin_action() {
    let (app, state) = build_test_app(true);
    let claims = test_claims("user-sub", "user@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-user".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-user", &tokens).await;

    let body = json!({"action": "admin:delete-user"});
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-user");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/authorize")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["authorized"], false);
}

#[tokio::test]
async fn test_authorize_cedar_unavailable() {
    let (app, state) = build_test_app(false); // no Cedar
    let claims = test_claims("user-sub", "user@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-user".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-no-cedar", &tokens).await;

    let body = json!({"action": "read:content"});
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-no-cedar");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/authorize")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_authorize_requires_csrf() {
    let (app, state) = build_test_app(true);

    let body = json!({"action": "read:content"});
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-x");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/authorize")
        .header("Content-Type", "application/json")
        .header("Cookie", format!("l42_session={}", signed))
        // No CSRF
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_authorize_missing_action() {
    let (app, state) = build_test_app(true);
    let claims = test_claims("user-sub", "user@example.com", &["admin"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-user".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-action", &tokens).await;

    let body = json!({"action": ""});
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-action");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/authorize")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ───── POST /auth/refresh (requires CSRF + auth) ─────

#[tokio::test]
async fn test_refresh_requires_csrf() {
    let (app, state) = build_test_app(false);

    let req = request_with_session(
        "POST",
        "/auth/refresh",
        "sid-1",
        &state.config.session_secret,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_refresh_no_refresh_token() {
    let (app, state) = build_test_app(false);
    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-123".into(),
        id_token,
        refresh_token: None, // No refresh token
        auth_method: None,
    };
    seed_session(&state, "sid-no-rt", &tokens).await;

    let req = request_with_session_and_csrf(
        "POST",
        "/auth/refresh",
        "sid-no-rt",
        &state.config.session_secret,
    );
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "No refresh token");
}

// ───── Cedar Ownership Enforcement ─────

#[tokio::test]
async fn test_ownership_enforcement_own_resource() {
    let (app, state) = build_test_app(true);
    let claims = test_claims("user-sub", "user@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-user".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-own", &tokens).await;

    // Write own resource (owner matches principal)
    let body = json!({
        "action": "write:own",
        "resource": {"id": "doc-1", "type": "document", "owner": "user-sub"}
    });
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-own");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/authorize")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["authorized"], true);
}

#[tokio::test]
async fn test_ownership_enforcement_other_resource() {
    let (app, state) = build_test_app(true);
    let claims = test_claims("user-sub", "user@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-user".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-other", &tokens).await;

    // Write someone else's resource → denied by forbid policy
    let body = json!({
        "action": "write:own",
        "resource": {"id": "doc-2", "type": "document", "owner": "other-user"}
    });
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-other");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/authorize")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["authorized"], false);
}

// ───── Session Isolation ─────

#[tokio::test]
async fn test_session_isolation() {
    let (app, state) = build_test_app(false);

    // Create two sessions with different users
    let claims1 = test_claims("user-1", "user1@example.com", &["admin"]);
    let claims2 = test_claims("user-2", "user2@example.com", &["users"]);
    let id1 = TestKeys::make_unsigned_jwt(&claims1);
    let id2 = TestKeys::make_unsigned_jwt(&claims2);

    let tokens1 = SessionTokens {
        access_token: "at-1".into(),
        id_token: id1,
        refresh_token: None,
        auth_method: None,
    };
    let tokens2 = SessionTokens {
        access_token: "at-2".into(),
        id_token: id2,
        refresh_token: None,
        auth_method: None,
    };

    seed_session(&state, "sid-iso-1", &tokens1).await;
    seed_session(&state, "sid-iso-2", &tokens2).await;

    // Session 1 should see user-1
    let req1 = request_with_session("GET", "/auth/me", "sid-iso-1", &state.config.session_secret);
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    let body1 = body_json(resp1).await;
    assert_eq!(body1["email"], "user1@example.com");

    // Session 2 should see user-2
    let req2 = request_with_session("GET", "/auth/me", "sid-iso-2", &state.config.session_secret);
    let resp2 = app.oneshot(req2).await.unwrap();
    let body2 = body_json(resp2).await;
    assert_eq!(body2["email"], "user2@example.com");
}

// ───── Expired Token Rejection ─────

#[tokio::test]
async fn test_authorize_expired_token_rejected() {
    let (app, state) = build_test_app(true);
    let claims = expired_claims("user-1");
    let id_token = TestKeys::make_unsigned_jwt(&claims);

    let tokens = SessionTokens {
        access_token: "at-expired".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-exp-auth", &tokens).await;

    let body = json!({"action": "read:content"});
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-exp-auth");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/authorize")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ───── Cookie Domain ─────
//
// POST /auth/session verifies the JWT via JWKS, so we can't easily test set-cookie
// with fake tokens. Instead, we test Domain= on delete cookies (via logout) since
// the middleware uses the same `cookie_domain` for both paths. Set-cookie format
// is covered by unit tests in session::middleware.

#[tokio::test]
async fn test_cookie_includes_domain_when_configured() {
    let mut config = Config::test_default();
    config.cookie_domain = Some(".example.com".into());
    let (app, state) = build_test_app_with_config(config, false);

    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-123".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-domain", &tokens).await;

    let req = request_with_session_and_csrf(
        "POST",
        "/auth/logout",
        "sid-domain",
        &state.config.session_secret,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let cookie = resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        cookie.contains("Domain=.example.com"),
        "cookie should include Domain: {cookie}"
    );
}

#[tokio::test]
async fn test_cookie_no_domain_by_default() {
    let (app, state) = build_test_app(false);

    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-123".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-no-domain", &tokens).await;

    let req = request_with_session_and_csrf(
        "POST",
        "/auth/logout",
        "sid-no-domain",
        &state.config.session_secret,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let cookie = resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        !cookie.contains("Domain="),
        "cookie should not include Domain by default: {cookie}"
    );
}

// ───── Callback Multi-Origin Redirect ─────

#[tokio::test]
async fn test_callback_use_origin_redirects_to_request_origin() {
    let mut config = Config::test_default();
    config.callback_use_origin = true;
    let (app, _state) = build_test_app_with_config(config, false);

    // Missing code → redirect to login with error, using request origin
    let req = Request::builder()
        .uri("/auth/callback")
        .header("x-forwarded-host", "app.example.com")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with("https://app.example.com/login"),
        "should redirect to request origin, got: {location}"
    );
}

#[tokio::test]
async fn test_callback_use_origin_different_hosts() {
    let mut config = Config::test_default();
    config.callback_use_origin = true;
    let (app, _state) = build_test_app_with_config(config, false);

    // First request from staging
    let req1 = Request::builder()
        .uri("/auth/callback")
        .header("x-forwarded-host", "staging.example.com")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    let resp1 = app.clone().oneshot(req1).await.unwrap();
    let loc1 = resp1.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc1.starts_with("https://staging.example.com/"),
        "staging host: {loc1}"
    );

    // Second request from production
    let req2 = Request::builder()
        .uri("/auth/callback")
        .header("x-forwarded-host", "app.example.com")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    let resp2 = app.oneshot(req2).await.unwrap();
    let loc2 = resp2.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc2.starts_with("https://app.example.com/"),
        "prod host: {loc2}"
    );
}

#[tokio::test]
async fn test_callback_default_uses_frontend_url() {
    // Default: callback_use_origin = false
    let (app, _state) = build_test_app(false);

    let req = Request::builder()
        .uri("/auth/callback")
        .header("x-forwarded-host", "app.example.com")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with("http://localhost:3000/"),
        "should use frontend_url, got: {location}"
    );
}

#[tokio::test]
async fn test_callback_use_origin_with_oauth_error() {
    let mut config = Config::test_default();
    config.callback_use_origin = true;
    let (app, _state) = build_test_app_with_config(config, false);

    let req = Request::builder()
        .uri("/auth/callback?error=access_denied&error_description=User+cancelled")
        .header("x-forwarded-host", "app.example.com")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with("https://app.example.com/login?error="),
        "error redirect should use request origin: {location}"
    );
}

#[tokio::test]
async fn test_callback_use_origin_scheme_fallback() {
    let mut config = Config::test_default();
    config.callback_use_origin = true;
    // No x-forwarded-proto → fallback to http (session_https_only is false)
    let (app, _state) = build_test_app_with_config(config, false);

    let req = Request::builder()
        .uri("/auth/callback")
        .header("host", "app.example.com")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with("http://app.example.com/"),
        "should fall back to http scheme: {location}"
    );
}

// ───── Custom Auth Path Prefix ─────

#[tokio::test]
async fn test_custom_prefix_routes_work() {
    let mut config = Config::test_default();
    config.auth_path_prefix = "/_auth".into();
    let (app, state) = build_test_app_with_config(config, false);

    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-prefix".into(),
        id_token,
        refresh_token: None,
        auth_method: None,
    };
    seed_session(&state, "sid-prefix", &tokens).await;

    let req = request_with_session(
        "GET",
        "/_auth/token",
        "sid-prefix",
        &state.config.session_secret,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["access_token"], "at-prefix");
}

#[tokio::test]
async fn test_health_stays_at_root_with_custom_prefix() {
    let mut config = Config::test_default();
    config.auth_path_prefix = "/_auth".into();
    let (app, _state) = build_test_app_with_config(config, false);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_old_prefix_404_with_custom_prefix() {
    let mut config = Config::test_default();
    config.auth_path_prefix = "/_auth".into();
    let (app, _state) = build_test_app_with_config(config, false);

    let req = Request::builder()
        .uri("/auth/token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ───── POST /auth/validate-credential ─────

/// Build a minimal CBOR attestationObject with given flags and optional AAGUID.
fn build_test_attestation_object(flags: u8, aaguid: Option<[u8; 16]>) -> String {
    let mut auth_data = vec![0u8; 32]; // rpIdHash
    auth_data.push(flags);
    auth_data.extend_from_slice(&[0, 0, 0, 0]); // signCount
    if let Some(aaguid_bytes) = aaguid {
        auth_data.extend_from_slice(&aaguid_bytes);
        auth_data.extend_from_slice(&[0, 0]); // credIdLen
    }

    let cbor = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("none".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(vec![]),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&cbor, &mut buf).unwrap();
    STANDARD.encode(&buf)
}

const TEST_AAGUID: [u8; 16] = [
    0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54,
    0xa8,
];

#[tokio::test]
async fn test_validate_credential_allowed_empty_allowlist() {
    let (app, state) = build_test_app(false);
    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-vc".into(),
        id_token,
        refresh_token: None,
        auth_method: Some("passkey".into()),
    };
    seed_session(&state, "sid-vc1", &tokens).await;

    let att_obj = build_test_attestation_object(0x01 | 0x04 | 0x40, Some(TEST_AAGUID));
    let body = json!({
        "attestation_object": att_obj,
        "client_data_json": STANDARD.encode(b"{}")
    });
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-vc1");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/validate-credential")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["allowed"], true);
    assert_eq!(
        body["device"]["aaguid"],
        "cb69481e-8ff7-4039-93ec-0a2729a154a8"
    );
}

#[tokio::test]
async fn test_validate_credential_aaguid_not_in_allowlist() {
    let mut config = Config::test_default();
    config.aaguid_allowlist = vec!["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into()];
    let (app, state) = build_test_app_with_config(config, false);

    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-vc2".into(),
        id_token,
        refresh_token: None,
        auth_method: Some("passkey".into()),
    };
    seed_session(&state, "sid-vc2", &tokens).await;

    let att_obj = build_test_attestation_object(0x01 | 0x04 | 0x40, Some(TEST_AAGUID));
    let body = json!({
        "attestation_object": att_obj,
        "client_data_json": STANDARD.encode(b"{}")
    });
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-vc2");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/validate-credential")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["allowed"], false);
    assert!(body["reason"].as_str().unwrap().contains("not in allowlist"));
}

#[tokio::test]
async fn test_validate_credential_aaguid_in_allowlist() {
    let mut config = Config::test_default();
    config.aaguid_allowlist = vec!["cb69481e-8ff7-4039-93ec-0a2729a154a8".into()];
    let (app, state) = build_test_app_with_config(config, false);

    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-vc3".into(),
        id_token,
        refresh_token: None,
        auth_method: Some("passkey".into()),
    };
    seed_session(&state, "sid-vc3", &tokens).await;

    let att_obj = build_test_attestation_object(0x01 | 0x04 | 0x40, Some(TEST_AAGUID));
    let body = json!({
        "attestation_object": att_obj,
        "client_data_json": STANDARD.encode(b"{}")
    });
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-vc3");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/validate-credential")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["allowed"], true);
}

#[tokio::test]
async fn test_validate_credential_device_bound_required_but_syncable() {
    let mut config = Config::test_default();
    config.require_device_bound = true;
    let (app, state) = build_test_app_with_config(config, false);

    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-vc4".into(),
        id_token,
        refresh_token: None,
        auth_method: Some("passkey".into()),
    };
    seed_session(&state, "sid-vc4", &tokens).await;

    // UP + UV + BE + AT — backup eligible
    let att_obj = build_test_attestation_object(0x01 | 0x04 | 0x08 | 0x40, Some(TEST_AAGUID));
    let body = json!({
        "attestation_object": att_obj,
        "client_data_json": STANDARD.encode(b"{}")
    });
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-vc4");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/validate-credential")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["allowed"], false);
    assert!(body["reason"].as_str().unwrap().contains("backup-eligible"));
}

#[tokio::test]
async fn test_validate_credential_device_bound_required_and_bound() {
    let mut config = Config::test_default();
    config.require_device_bound = true;
    let (app, state) = build_test_app_with_config(config, false);

    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-vc5".into(),
        id_token,
        refresh_token: None,
        auth_method: Some("passkey".into()),
    };
    seed_session(&state, "sid-vc5", &tokens).await;

    // UP + UV + AT — no BE flag, device-bound
    let att_obj = build_test_attestation_object(0x01 | 0x04 | 0x40, Some(TEST_AAGUID));
    let body = json!({
        "attestation_object": att_obj,
        "client_data_json": STANDARD.encode(b"{}")
    });
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-vc5");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/validate-credential")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        .header("Cookie", format!("l42_session={}", signed))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["allowed"], true);
}

#[tokio::test]
async fn test_validate_credential_no_session() {
    let (app, _state) = build_test_app(false);

    let att_obj = build_test_attestation_object(0x01 | 0x04 | 0x40, Some(TEST_AAGUID));
    let body = json!({
        "attestation_object": att_obj,
        "client_data_json": STANDARD.encode(b"{}")
    });
    let req = Request::builder()
        .method("POST")
        .uri("/auth/validate-credential")
        .header("Content-Type", "application/json")
        .header("X-L42-CSRF", "1")
        // No session cookie
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_validate_credential_no_csrf() {
    let (app, state) = build_test_app(false);
    let claims = test_claims("user-1", "test@example.com", &["users"]);
    let id_token = TestKeys::make_unsigned_jwt(&claims);
    let tokens = SessionTokens {
        access_token: "at-vc7".into(),
        id_token,
        refresh_token: None,
        auth_method: Some("passkey".into()),
    };
    seed_session(&state, "sid-vc7", &tokens).await;

    let att_obj = build_test_attestation_object(0x01 | 0x04 | 0x40, Some(TEST_AAGUID));
    let body = json!({
        "attestation_object": att_obj,
        "client_data_json": STANDARD.encode(b"{}")
    });
    let signed = sign_session_id(state.config.session_secret.as_bytes(), "sid-vc7");
    let req = Request::builder()
        .method("POST")
        .uri("/auth/validate-credential")
        .header("Content-Type", "application/json")
        .header("Cookie", format!("l42_session={}", signed))
        // No X-L42-CSRF header
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
