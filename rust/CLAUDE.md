# Rust Token Handler — Claude Code Guide

Guide for Claude instances working on the Rust Token Handler backend.

## Quick Reference

```bash
cargo test            # 108 tests (81 unit + 27 integration)
cargo clippy -- -D warnings   # Must pass clean
cargo run             # Local dev server on :3001 (needs .env)
```

**Edition**: Rust 2024 (requires Rust 1.85+). Uses `let chains`, `r#gen` (reserved keyword), and `unsafe` for `env::remove_var` in tests.

## Architecture

This is a **Token Handler** backend — it stores JWT tokens server-side in HttpOnly session cookies and proxies auth decisions to the client-side `auth.js` library. The same `auth.js` client works against this backend, the Express backend, or the FastAPI backend without changes.

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Native `cedar-policy` crate | Eliminates WASM marshalling overhead — the whole point of the Rust rewrite |
| `AnyBackend` enum dispatch | `SessionBackend` trait uses RPITIT, so it's not object-safe. Enum avoids `Box<dyn>` + pin overhead |
| `SessionHandle` as extractor | Implements `FromRequestParts` — pulls session from request extensions set by middleware |
| HMAC-SHA256 cookies (not itsdangerous) | Clean format: `base64url(id).base64url(hmac)`. Not compatible with Python's itsdangerous |
| `CedarState` shared via `Arc` | `Authorizer`, `PolicySet`, `Schema` are all `Send + Sync` — pre-parsed at startup |

### Module Map

| Module | Purpose | Key Type |
|--------|---------|----------|
| `config` | Env var parsing | `Config` |
| `error` | HTTP error responses | `AppError` (12 variants) |
| `types` | Request/response DTOs | `SessionTokens`, `AuthorizeRequest`, etc. |
| `cognito::jwt` | JWT decode + JWKS verification | `JwksCache`, `Claims` |
| `cognito::client` | Cognito HTTP API | `exchange_code_for_tokens`, `refresh_tokens` |
| `cedar::engine` | Native Cedar evaluation | `CedarState` (Authorizer + PolicySet + Schema) |
| `cedar::entities` | Build Cedar entities from JWT claims | `build_entities()` |
| `cedar::groups` | Cognito group alias resolution | `DEFAULT_GROUP_MAP` (30+ aliases → 8 groups) |
| `session::cookie` | HMAC-SHA256 session cookie signing | `sign_session_id`, `verify_cookie` |
| `session::memory` | In-memory session store | `InMemoryBackend` (DashMap) |
| `session::dynamodb` | DynamoDB session store | `DynamoDbBackend` |
| `session::middleware` | Axum session middleware | `SessionHandle`, `SessionLayer` |
| `middleware::csrf` | CSRF header check | `require_csrf` |
| `ocsf` | OCSF security event logging | `authentication_event`, `authorization_event` |
| `routes::*` | 8 HTTP handlers | One handler per file |
| `lib` | App assembly (`Router::nest` for auth prefix) | `AppState`, `create_app()` |
| `main` | Dual-mode entrypoint | Lambda detection via `AWS_LAMBDA_RUNTIME_API` |

## Common Tasks

### Adding a new route

1. Create `src/routes/new_route.rs` with the handler function
2. Add `pub mod new_route;` to `src/routes/mod.rs`
3. Register in `lib.rs` — add to `csrf_routes` (if state-changing) or `open_routes`
4. The handler signature determines extractors: `State<Arc<AppState>>`, `SessionHandle`, `Json<T>`, `Query<T>`

### Adding a new Cedar action

1. Add the action to `cedar/schema.cedarschema.json` under `actions`
2. Add a permit policy in the appropriate `cedar/policies/*.cedar` file
3. Run `cargo test cedar::engine` to verify

### Modifying session data

Session data flows through `SessionHandle`:
```rust
// Read
let data = session.data.lock().await;
let tokens: SessionTokens = data.get("tokens")
    .and_then(|v| serde_json::from_value(v.clone()).ok())
    .ok_or(AppError::NotAuthenticated)?;

// Write
let mut data = session.data.lock().await;
data.set("tokens", serde_json::to_value(&tokens).unwrap());

// Destroy
*session.destroyed.lock().await = true;
session.data.lock().await.clear();
```

The middleware automatically saves modified sessions and deletes destroyed ones after the handler returns.

## Gotchas

### Axum 0.8 API changes
- `Next` has no generic parameter (was `Next<B>` in 0.7)
- `Request` is `axum::extract::Request` (no body generic needed)
- Extractors implement `FromRequestParts<S>` where `S` is the state type
- `Host` extractor moved to `axum-extra` — we extract the `Host` header manually via `HeaderMap` instead to avoid the extra dependency

### Cedar `cedar-policy` v4 API
- `EntityUid::from_type_name_and_id(type_name, id)` — both args are `impl Into<_>`
- `EntityTypeName::from_str("App::User")` — uses `::` separator
- `PolicySet::from_str(&all_policies)` — concatenate all `.cedar` files into one string; individual `Policy::parse(None, text)` assigns duplicate default IDs
- `Entity::new(uid, attrs, parents)` — attrs is `HashMap<String, RestrictedExpression>`, parents is `HashSet<EntityUid>`
- `RestrictedExpression::new_string(s)`, `new_bool(b)`, `from_str(cedar_literal)` — for entity attributes
- Entity references in attrs: `RestrictedExpression::from_str("App::User::\"owner-id\"")` — Cedar entity literal syntax

### Session cookie format
```
base64url(session_id).base64url(hmac_sha256(secret, session_id))
```
NOT compatible with Python's `itsdangerous.URLSafeTimedSerializer`. If migrating from FastAPI, existing sessions will be invalidated (users re-login).

### OCSF logging
Events go to `tracing::info!(target: "ocsf", ...)` as JSON strings. In Lambda, configure the JSON tracing subscriber to capture these. The `emit()` function never panics — errors are silently caught.

### Callback redirect_uri
The OAuth callback handler constructs `redirect_uri` from the incoming request's `X-Forwarded-Host` header (preferred), falling back to `Host`, then `"localhost"`. The scheme comes from `X-Forwarded-Proto`. The auth path prefix comes from `Config::auth_path_prefix`. This MUST match the callback URL registered in your Cognito app client settings.

### CloudFront / reverse proxy deployment
Three env vars handle CDN deployment:

| Env Var | Default | Purpose |
|---------|---------|---------|
| `COOKIE_DOMAIN` | (none) | `Domain=` on session cookies for cross-subdomain SSO (e.g. `.example.com`) |
| `AUTH_PATH_PREFIX` | `/auth` | Route prefix for all auth endpoints. Set to `/_auth` if CloudFront routes `/_auth/*` to Lambda |
| (none — uses headers) | — | `X-Forwarded-Host` header preferred over `Host` for callback `redirect_uri` |

Example CloudFront config: CloudFront routes `/_auth/*` to Lambda origin, sets `X-Forwarded-Host: app.example.com`. Lambda env: `AUTH_PATH_PREFIX=/_auth`, `COOKIE_DOMAIN=.example.com`.

Auth routes are mounted via `Router::nest(&auth_prefix, auth_routes)` — `/health` always stays at the root.

## Testing Patterns

### Integration tests use `tower::ServiceExt::oneshot()`
```rust
let (app, state) = build_test_app(true); // true = with Cedar
seed_session(&state, "sid-1", &tokens).await;
let req = request_with_session("GET", "/auth/token", "sid-1", &state.config.session_secret);
let resp = app.oneshot(req).await.unwrap();
assert_eq!(resp.status(), StatusCode::OK);
```

### Custom config for tests
```rust
let mut config = Config::test_default();
config.cookie_domain = Some(".example.com".into());
config.auth_path_prefix = "/_auth".into();
let (app, state) = build_test_app_with_config(config, false);
```

### Seeding sessions for tests
```rust
async fn seed_session(state: &AppState, session_id: &str, tokens: &SessionTokens) {
    let mut data = SessionData::new();
    data.set("tokens", serde_json::to_value(tokens).unwrap());
    state.session_layer.backend.save(session_id, &data).await;
}
```

### Test JWT tokens (unsigned, for session-stored tokens)
```rust
let claims = test_claims("user-sub", "user@example.com", &["admin"]);
let id_token = TestKeys::make_unsigned_jwt(&claims);
```

### Test JWT tokens (RS256-signed, for POST /auth/session verification)
```rust
let keys = TestKeys::generate();
let id_token = keys.sign_jwt(&claims);
let jwks = keys.jwks_json(); // Use with wiremock to mock JWKS endpoint
```

## Reference Implementations

| This file | Ported from |
|-----------|-------------|
| `cedar/engine.rs` | `examples/backends/express/cedar-engine.js` |
| `session/middleware.rs` | `examples/backends/fastapi/app/session/middleware.py` |
| `routes/*.rs` | `examples/backends/fastapi/app/routes/*.py` |
| `cognito/client.rs` | `examples/backends/fastapi/app/cognito.py` |
| `ocsf.rs` | `examples/backends/fastapi/app/ocsf.py` |
| `cedar/policies/` | `examples/backends/express/cedar/policies/` (identical) |
