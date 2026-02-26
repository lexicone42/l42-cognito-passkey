# Changelog

All notable changes to this project will be documented in this file.

## [0.20.0] - 2026-02-21

### Added

- **Service token bypass** for headless/programmatic API access
  - `SERVICE_TOKEN` env var + `X-Service-Token` header bypass session cookies and CSRF
  - Constant-time comparison via `subtle::ConstantTimeEq`
  - Synthetic `SessionHandle` with `"__service__"` ID for service requests
  - OCSF authentication event with `AUTH_PROTOCOL_SERVICE_TOKEN` (100)
  - Startup warning if token < 32 chars
  - 5 integration + 3 unit tests

### Documentation

- **Consolidated 18 doc files into 6 focused guides** — removed duplication, updated all cross-references
- Removed stale pre-v0.15.0 references (localStorage, memory mode, FastAPI)
- README badges for version, tests, license, and Rust backend

## [0.19.0] - 2026-02-20

### Added

- **WebAuthn authenticator metadata** — `parseAuthenticatorData()` extracts UP/UV/BE/BS/AT/ED flags, signCount, and AAGUID from raw `authenticatorData`
  - `authenticatorMetadata` field on registration and login credential responses
  - OCSF events include backup eligibility, backup state, AAGUID, and attestation level
  - `attestation` option on `registerPasskey()` and `upgradeToPasskey()` ('none'/'indirect'/'direct'/'enterprise')
  - 38 tests in `authenticator-metadata.test.js`

- **Pre-registration credential validation gate** (Rust backend)
  - `POST /auth/validate-credential` — CSRF-protected, requires session
  - AAGUID allowlist (`AAGUID_ALLOWLIST` env var) and device-bound policy (`REQUIRE_DEVICE_BOUND`)
  - CBOR attestation parsing via `ciborium` crate
  - Client-side `validateCredentialEndpoint` config option, gate in `registerPasskey()` and `upgradeToPasskey()`
  - 17 unit + 7 integration + 13 JS tests

- **Multi-origin OAuth callback** (Rust backend)
  - `CALLBACK_USE_ORIGIN` env var — redirects to request origin instead of static `FRONTEND_URL`
  - `CALLBACK_ALLOWED_ORIGINS` — validates `X-Forwarded-Host` to prevent open redirect
  - Enables one Lambda behind multiple CloudFront distributions

### Security

- **v1.0 security hardening** — 4 blocking + 7 important + 8 hardening items addressed
  - `validateTokenClaims()` now requires `aud`/`client_id` and `exp` claims (fixes S2)
  - `SESSION_SECRET` required at startup (was silently defaulting)
  - `clientDataJSON` origin validation in credential.rs
  - Refresh token rotation preservation from Cognito
  - OCSF coverage on `/token`, `/me`, fixed `/logout` auth_method
  - 10 PKCE + 13 credential + 3 Cedar forbid composition property tests
  - `X-Forwarded-Proto` validation (only "http"/"https")
  - Callback session cleanup on all error paths
  - Startup warnings for HTTPS_ONLY mismatch + empty allowed origins

### Removed

- **FastAPI backend** (`app/` directory) — Rust backend is now the sole recommended backend

### Tests

- 733 vitest + 149 → 157 cargo tests

## [0.18.0] - 2026-02-17

### Added

- **CloudFront deployment config for Rust backend** (#19, #20, #21)
  - `X-Forwarded-Host` support: OAuth callback prefers `X-Forwarded-Host` over `Host` header for `redirect_uri`
  - `COOKIE_DOMAIN` env var: sets `Domain=` on session cookies for cross-subdomain SSO
  - `AUTH_PATH_PREFIX` env var: configurable route prefix (default `/auth`) via `Router::nest()`
  - `/health` stays at root regardless of prefix

### Fixed

- DynamoDB session save: `PutItem` → `UpdateItem` with `if_not_exists(created_at)` to prevent TTL reset on every write
- Rust edition 2024, `let` chains in JWKS cache

## [0.17.0] - 2026-02-17

### Added

- **Rust Token Handler backend** — Native Rust implementation replacing WASM/FFI Cedar calls (#18)
  - New `rust/` directory with full Axum-based HTTP server (8 endpoints matching FastAPI/Express exactly)
  - Native `cedar-policy` crate evaluation — no WASM marshalling, direct Rust calls
  - Dual-mode binary: Lambda (`lambda_http`) + local dev (`axum::serve`), auto-detected via `AWS_LAMBDA_RUNTIME_API`
  - HMAC-SHA256 session cookies with InMemory (dev) + DynamoDB (prod) backends
  - OCSF structured security event logging via `tracing::info!`
  - Same `auth.js` client works against Rust backend without changes
  - 97 tests (75 unit + 22 integration), clippy clean
  - Comprehensive CLAUDE.md guide for other Claude instances working on the Rust backend
  - Expected improvements: Lambda cold start 2-5s → 10-50ms, memory 512MB → 128-256MB, single static binary

## [0.16.0] - 2026-02-12

### Added

- **OCSF event logging for FastAPI backend** — Server-side security events matching the client-side auth.js OCSF schema (#15)
  - New `app/ocsf.py` module with `emit()`, `authentication_event()`, and `authorization_event()` helpers
  - Events logged to Python's `ocsf` named logger as JSON — consumers attach their own handlers (CloudWatch, Firehose, structlog)
  - Session creation/failure → Logon events (passkey/password/direct protocols detected)
  - OAuth callback success/failure → Authentication Ticket events
  - Token refresh success/failure → Service Ticket events
  - Logout → Logoff events
  - Cedar permit/deny/error/unavailable → Authorization events (activity 99/Other)
  - 44 new tests: module unit tests + route emission verification
  - Updated `docs/ocsf-logging.md` with server-side event table, Python logging integration, and CloudWatch example

## [0.15.1] - 2026-02-10

### Tests

- **Expanded Cedar authorization suite**: 25 new tests across 8 suites (658 total, was 633)
  - Exhaustive role × action permission matrix (8 roles × 22 actions)
  - Delete action boundary testing (only admin gets delete)
  - Multi-role combinatorial property tests (union semantics + forbid override)
  - Admin vs. forbid-overrides-permit for delete actions
  - Unknown/invalid action handling (schema validation)
  - Resource ID & type edge case fuzzing
  - S7 sharp-edge: fail-closed behavior (invalid entities, empty providers)
  - Entity provider edge cases (conflicting principal, stripped groups, ownership)
- Cedar authorization tests: 132 (was 107)

### Fixed

- **Release pipeline**: `sync-test-counts` now runs automatically during release, and `validate-docs` checks version refs + test counts in the `preversion` hook

## [0.15.0] - 2026-02-10

### BREAKING CHANGES

- **Removed `localStorage` and `memory` token storage modes** — handler mode is now the only supported mode. Passing `tokenStorage: 'localStorage'` or `tokenStorage: 'memory'` to `configure()` will throw an error. All deployments must use a Token Handler backend.
- **Handler endpoints are always required** — `tokenEndpoint`, `refreshEndpoint`, and `logoutEndpoint` must be provided to `configure()`.

### Added

- **`sessionEndpoint` config option** — new endpoint for persisting server sessions after direct login (passkey/password). When configured, the library automatically POSTs tokens to this endpoint after `loginWithPasskey()`, `loginWithPassword()`, or `loginWithConditionalUI()` completes. This fixes the issue where direct login in handler mode didn't create a server session, causing the user to appear logged out on page reload (#12).
- **`POST /auth/session` endpoint** in Express backend — accepts tokens from direct login, validates `id_token` audience claim, and stores tokens in the server session.
- **11 new session persistence tests** — covers CSRF protection, error handling, and mode guards.

### Removed

- `LocalStorageTokenStore` and `MemoryTokenStore` — dead code removed from `src/auth.js`
- Client-side cookie management in `setTokens()` and `clearTokens()` — server manages session cookies
- Deprecation warnings for non-handler modes — replaced with hard error

### Tests

- 633 tests (was 649 — removed deprecated handler-mode-only tests, added 11 session persistence tests)

## [0.14.0] - 2026-02-09

### Deprecated

- **`localStorage` and `memory` token storage modes** — `configure()` now emits a console warning when using non-handler storage modes. Both modes will be removed in v1.0. Use `tokenStorage: 'handler'` for all production deployments.

### Changed

- **Handler mode is now the recommended default** — all documentation, README, and examples updated to present handler mode as the primary deployment path
- README restructured with "Client + Server" (recommended) and "Client-Only" (deprecated) tiers

### Documentation

- All docs updated to reflect handler mode as recommended: architecture.md, api-reference.md, design-decisions.md, handler-mode.md, integration-guide.md, security-hardening.md, migration.md
- Added v0.14.0 migration guide with localStorage → handler checklist

## [0.13.0] - 2026-02-09

### Added

- **Cedar Policy Authorization** — server-side authorization via `@cedar-policy/cedar-wasm` (Apache-2.0)
  - `cedar-engine.js` — Cedar WASM wrapper for Express backends with pre-parsed stateful evaluation (<0.1ms/request)
  - 9 Cedar policy files covering all RBAC roles (admin, editor, reviewer, publisher, readonly, user, moderator, developer, owner-only)
  - Cedar JSON schema mapping Cognito groups, users, and resources to typed Cedar entities
  - Group alias resolution matching `rbac-roles.js` (e.g., 'admins' → 'admin', 'dev' → 'developers')
  - `EntityProvider` interface for post-1.0 persistent entity stores (DynamoDB, Redis)
  - Fail-closed design: server returns 503 if Cedar unavailable
  - Ownership enforcement via `forbid` policies (Cedar forbid-overrides-permit)
- **Improved `requireServerAuthorization()`** — now supports handler mode (session cookies + CSRF header) and accepts `resource` parameter
  - Default endpoint changed from `/api/authorize` to `/auth/authorize`
- **Sharp-edges property tests** — 16 new property-based tests for token validation, rate limiting, ownership, and context injection

### Tests

- 101 Cedar authorization tests + 16 sharp-edges property tests (649 total)

## [0.12.2] - 2026-02-06

### Added

- **Tree-Shaking Support** — bundler optimization hints for Webpack, Rollup, Vite, and esbuild
  - `"sideEffects": false` in `package.json` enables bundlers to eliminate unused exports
  - `/*#__PURE__*/` annotations on 11 internal constants (`DEFAULT_CONFIG`, `OCSF_*`, `RETRY_CONFIG`, `REFRESH_CONFIG`, `AUTO_REFRESH_DEFAULTS`, `PUBLIC_SUFFIXES`) enable minifiers to drop unused definitions
  - No API or behavioral changes — purely bundler hints

### Changed

- **Cedar backlog** updated to reference open-source Cedar (`@cedar-policy/cedar-wasm`) instead of Amazon Verified Permissions, aligning with the library's self-hosted philosophy

## [0.12.1] - 2026-02-05

### Added

- **Client-Side Login Rate Limiting** — exponential backoff on failed login attempts
  - Per-email attempt tracking with configurable threshold (`maxLoginAttemptsBeforeDelay`, default: 3)
  - Exponential backoff with jitter (`loginBackoffBaseMs`: 1000ms, `loginBackoffMaxMs`: 30s)
  - Rate limiting applied to `loginWithPassword()`, `loginWithPasskey()`, `loginWithConditionalUI()` (Mode A)
  - Counter resets on successful login, lives only in memory (page reload clears)
  - `getLoginAttemptInfo(email)` — exported for UI to display "try again in N seconds" messages
  - OCSF event (HIGH severity) logged when threshold is first breached
  - Cognito account lockout detection — `NotAuthorizedException` with "temporarily locked" or "password attempts exceeded" re-thrown with clear message and CRITICAL OCSF event

### TypeScript

- New interface: `LoginAttemptInfo` (attemptsRemaining, nextRetryMs, isThrottled)
- New config options: `maxLoginAttemptsBeforeDelay`, `loginBackoffBaseMs`, `loginBackoffMaxMs`
- New export: `getLoginAttemptInfo(email: string): LoginAttemptInfo | null`

### Tests

- 40 new tests in `login-rate-limiting.test.js` (532 total)

## [0.12.0] - 2026-02-05

### Added

- **Conditional UI / Passkey Autofill** (`loginWithConditionalUI()`)
  - Mode A: With email — single biometric prompt via Cognito challenge + `mediation: 'conditional'`
  - Mode B: Without email — discovery flow extracts `userHandle`, then re-authenticates via `loginWithPasskey()`
  - Internal `AbortController` management — conditional requests auto-cancelled on other login/logout calls
  - User-provided `AbortSignal` support via options parameter

- **Conditional Create / Passkey Upgrade** (`upgradeToPasskey()`)
  - Silent passkey registration after password login using `mediation: 'conditional'` on `navigator.credentials.create()`
  - Non-blocking — failures return `false` instead of throwing
  - `autoUpgradeToPasskey` config option for automatic fire-and-forget upgrade after password login
  - Requires Chrome 136+ or Safari 18+ for conditional create support

- **Token Validation on Load** (internal `validateTokenClaims()`)
  - `isAuthenticated()`, `isAuthenticatedAsync()`, and `ensureValidTokens()` now validate token claims against config
  - Detects tokens from wrong Cognito pool (issuer region mismatch)
  - Detects tokens from wrong app (client_id/aud mismatch)
  - Rejects tokens with unreasonable expiry (> 30 days)
  - Invalid tokens are automatically cleared from storage

- **WebAuthn Level 3 `getClientCapabilities()`** — `getPasskeyCapabilities()` enhanced:
  - Uses `PublicKeyCredential.getClientCapabilities()` when available
  - New fields: `conditionalCreate`, `hybridTransport`, `passkeyPlatformAuthenticator`, `userVerifyingPlatformAuthenticator`, `relatedOrigins`, `signalAllAcceptedCredentials`, `signalCurrentUserDetails`, `signalUnknownCredential`, `isWebView`, `source`
  - Handles both camelCase and kebab-case capability keys
  - Falls back to individual feature detection when Level 3 API unavailable
  - `detectWebView()` helper for Android WebView, iOS WKWebView, Electron detection

- **Helper extraction**: `buildAssertionResponse()` and `buildCredentialResponse()` shared helpers (DRY refactor)

### Changed

- **`registerPasskey(options)`** now accepts an options parameter:
  - `authenticatorAttachment`: `'platform'`, `'cross-platform'`, or omit (any — new default)
  - `residentKey`: default changed from `'preferred'` to `'required'` (needed for conditional UI)
  - `userVerification`: configurable, default remains `'preferred'`
  - Server-provided `authenticatorSelection` values used as base, caller options override

- **Login methods** (`loginWithPasskey`, `loginWithPassword`, `loginWithHostedUI`) and `logout()` now abort any pending conditional UI request

### TypeScript

- New interfaces: `ConditionalUIOptions`, `PasskeyRegistrationOptions`, `UpgradeToPasskeyOptions`
- Expanded `PasskeyCapabilities` interface (14 fields, was 4)
- `AuthConfigOptions` gains `autoUpgradeToPasskey?: boolean`
- Updated `registerPasskey(options?)` signature
- Added `loginWithConditionalUI()` and `upgradeToPasskey()` declarations

### Stats

- **492 tests passing** (was 384)
- 4 new test files: `conditional-ui.test.js` (32), `conditional-create.test.js` (23), `token-validation.test.js` (31), `webauthn-capabilities.test.js` (22)

## [0.11.0] - 2026-02-05

### Added

- **Debug Logging & Diagnostics Mode** (`debug` config option)
  - `debug: true` — logs to `console.debug` with `[l42-auth]` prefix
  - `debug: 'verbose'` — includes data payloads in console output
  - `debug: function(event)` — receive events programmatically (for Datadog, Sentry, etc.)
  - In-memory ring buffer of last 100 events with timestamps and version tags

- **`getDebugHistory()`** — retrieve copy of debug event history (newest last)

- **`getDiagnostics()`** — snapshot of current auth state:
  - `configured`, `tokenStorage`, `hasTokens`, `isAuthenticated`, `tokenExpiry`
  - `authMethod`, `userEmail`, `userGroups`, `isAdmin`, `isReadonly`
  - `autoRefreshActive`, `debug`, `version`

- **`clearDebugHistory()`** — reset debug event buffer

- **Instrumented operations** — 16 debug log points across:
  - Token ops: `setTokens`, `clearTokens`, `refreshTokens:success/failed`
  - Auth flows: `loginWithPassword:success/failed`, `loginWithPasskey:success/failed`, `loginWithHostedUI:redirect`, `exchangeCodeForTokens:success/failed`, `logout`
  - State changes: `authStateChange`, `login`, `logout`
  - Auto-refresh: `autoRefresh:start`, `autoRefresh:stop`
  - Sessions: `sessionExpired`
  - Passkeys: `registerPasskey:success/failed`, `deletePasskey:success/failed`

- **TypeScript types**: `DebugEvent`, `DiagnosticsInfo` interfaces; `debug` option in `AuthConfigOptions`

- **34 new tests** for debug logging, ring buffer, diagnostics shape, console modes, function callback, and integration

### Stats

- **384 tests passing** (was 350)

## [0.10.1] - 2026-02-05

### Removed

- **TTRPG roles (`player`, `dm`)**: Removed niche Dungeon Master / Game Master roles from `COGNITO_GROUPS` and `STANDARD_ROLES` in `rbac-roles.js`. Define domain-specific roles in your own project instead.

- **`wasm-multiuser-pattern.html`**: Removed WASM multi-user site pattern template and its 29 tests. The `staticSite` pattern remains as the only built-in site pattern.

- **`wasmMultiuser` site pattern**: Removed from `SITE_PATTERNS` in `rbac-roles.js`.

### Changed

- **`moderator` role** is now pattern-agnostic (previously tied to `wasm-multiuser` pattern). It remains available as a general-purpose community moderation role.

- **Test count**: 379 → 350 (removed 29 wasm-multiuser-pattern tests).

## [0.10.0] - 2026-02-05

### Removed (BREAKING)

- **`createAuthenticatedWebSocket()`**: Removed WebSocket auth helper — speculative feature with no tests or real-world integrations. If you need authenticated WebSocket connections, inject the access token from `ensureValidTokens()` directly.

- **`getTokensAsync()`**: Removed redundant function — use `await getTokens()` instead, which works in all storage modes (localStorage returns sync, handler returns Promise, `await` handles both).

- **`decodeJwtPayload()` and `parseJwt()` deprecated aliases**: These have been deprecated since v0.4.0. Use `UNSAFE_decodeJwtPayload()` instead.

- **Healthcare, Education, SaaS RBAC roles**: Removed speculative role templates from `rbac-roles.js` (patient, nurse, doctor, student, ta, teacher, freeTier, proTier, enterpriseTier, and related COGNITO_GROUPS entries). Also removed API, Organization, E-commerce, Analytics, and Service roles. Kept: admin, readonly, user, editor, reviewer, publisher, moderator, developer.

- **`CONTENTFUL_ROLE_MAPPING` stub**: Removed empty placeholder from `rbac-roles.js`.

- **Healthcare/Education/SaaS site patterns**: Removed from `SITE_PATTERNS`. Kept: staticSite.

- **Speculative docs**: Removed `docs/cedar-integration.md`, `docs/dpop-future.md`, `docs/v1-token-storage-proposal.md` (implemented feature — historical artifact).

### Added

- **Design Decisions guide**: New `docs/design-decisions.md` — 14-section deep-dive into code choices, trade-offs, and common misconfigurations with severity ratings.

### Fixed

- Duplicate JSDoc block on `setTokens()` removed
- Stale "Future: HandlerTokenStore (v0.8.0)" comment updated
- Fixed references to deleted docs across README, CLAUDE.md, BACKLOG.md, and design-decisions.md

### Stats

- **1,721 lines removed** — auth.js: 2,705 → 2,519 lines, rbac-roles.js: 824 → 406 lines
- **379 tests passing** (unchanged — removed code had no test coverage)

## [0.9.0] - 2026-02-05

### Added

- **Background Token Auto-Refresh**: Automatic token refresh with visibility API integration
  - `startAutoRefresh(options)`: Start periodic token refresh (default: every 60s)
  - `stopAutoRefresh()`: Cancel background refresh
  - `isAutoRefreshActive()`: Check if auto-refresh is running
  - Auto-starts on login, auto-stops on logout
  - Pauses when tab is hidden, checks immediately when visible again

- **Session Expiry Handling**: `onSessionExpired(callback)` fires when session can't be recovered
  - Triggered by: refresh failure, server 401, expired tokens with no refresh token
  - Use to redirect users to login page

- **Authenticated Fetch Helper**: `fetchWithAuth(url, options)` convenience wrapper
  - Injects Bearer token automatically
  - Handles 401 with retry-after-refresh
  - Fires `onSessionExpired` if retry fails

- **CSRF Protection for Handler Mode**:
  - Client sends `X-L42-CSRF: 1` header on handler POST requests (refresh, logout)
  - Express backend enforces header via `requireCsrfHeader` middleware
  - Defense-in-depth alongside SameSite cookies

- **Integration Guide**: `docs/integration-guide.md` with Claude Code advice

- **WebAuthn Feature Detection**: `isPasskeySupported()`, `isConditionalMediationAvailable()`, `isPlatformAuthenticatorAvailable()`, `getPasskeyCapabilities()`

- **WebSocket Authentication**: `createAuthenticatedWebSocket(url, options)` with:
  - Message-based auth (default, secure) and query param auth modes
  - Auto-reconnect on 4401/4403 close codes with token refresh
  - WSS enforcement warning for non-localhost URLs

- **Additional RBAC Role Templates**: Healthcare (patient/nurse/doctor), Education (student/ta/teacher), SaaS (free/pro/enterprise) with Cognito group aliases

- **31 new auth property-based tests** for token expiry invariants, admin/readonly mutual exclusion, cookie domain safety, OAuth state uniqueness, JWT decode roundtrip

- **35 new tests** for auto-refresh, fetchWithAuth, session expiry, CSRF, and visibility API

### Changed

- **WebSocket default auth mode**: Changed from `'query'` to `'message'` to prevent token leakage in URLs (server logs, proxy logs)

### Fixed

- **`isPasskeySupported()` now checks `window.isSecureContext`**: Matches documentation that said it checked secure context but didn't

- **Handler Mode Sync API**: 12 sync functions now use `getTokensSync()` instead of async `getTokens()`
  - Affected: `getAuthMethod`, `getIdTokenClaims`, `getUserEmail`, `getUserGroups`, `hasAdminScope`, `isAuthenticated`, `refreshTokens` standard path
  - Async functions (`listPasskeys`, `registerPasskey`, `deletePasskey`) now properly `await getTokens()`

- **`shouldRefreshToken()` in handler mode**: No longer requires `refresh_token` (stays server-side)

- **`isAdmin()` / `isReadonly()` alias support**: Now check all Cognito group aliases case-insensitively
  - `isAdmin()`: admin, admins, administrators
  - `isReadonly()`: readonly, read-only, viewer, viewers (excluding admins)

## [0.8.0] - 2026-02-01

### Added

- **Token Handler Mode**: Server-side token storage for maximum XSS protection
  - Tokens stored in HttpOnly session cookies on the server
  - New `tokenStorage: 'handler'` option
  - `refresh_token` never exposed to client (stays server-side)

- **Handler Configuration Options**:
  - `tokenEndpoint`: GET endpoint to retrieve tokens from session
  - `refreshEndpoint`: POST endpoint to refresh tokens
  - `logoutEndpoint`: POST endpoint to destroy session
  - `oauthCallbackUrl`: Backend OAuth callback URL
  - `handlerCacheTtl`: Cache TTL in milliseconds (default: 30000)

- **New Async Functions**:
  - `getTokensAsync()`: Explicitly async version of `getTokens()`
  - `isAuthenticatedAsync()`: Async auth check that fetches from server

- **Handler Token Store Tests**: 46 new tests covering:
  - HandlerTokenStore fetching and caching
  - Configuration validation (required endpoints)
  - Error handling (401/403 returns null, 500 throws)
  - Security properties (no localStorage, no refresh_token exposure)

- **Express Backend Example**: `examples/backends/express/`
  - Reference implementation of Token Handler endpoints
  - Session management with `express-session`
  - OAuth callback handling

- **Handler Mode Documentation**: `docs/handler-mode.md`

### Changed

- `getTokens()` returns Promise in handler mode (sync in other modes)
- `logout()` calls server endpoint in handler mode
- `refreshTokens()` calls backend endpoint in handler mode
- `loginWithHostedUI()` uses `oauthCallbackUrl` in handler mode
- `isAuthenticated()` uses cache in handler mode (stays sync)
- Total tests: 261 (was 207)

### Security

- Handler mode tokens are stored in HttpOnly cookies (immune to XSS storage scanning)
- `refresh_token` never leaves the server in handler mode
- Tokens briefly cached in memory (30 second TTL by default)

### Migration

No breaking changes for existing users. Handler mode is opt-in:

```javascript
configure({
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout'
});

// Use await for cross-mode compatibility
const tokens = await getTokens();
```

## [0.7.0] - 2026-01-21

### Added

- **Token Storage Modes**: New `tokenStorage` configuration option
  - `'localStorage'` (default): Current behavior, tokens persist across page reloads
  - `'memory'`: Tokens stored in memory only, lost on page reload
  - Foundation for v0.8.0 handler mode (server-side token storage)

- **Token Store Abstraction**: Internal refactoring for pluggable storage backends
  - `LocalStorageTokenStore`: Default storage using localStorage
  - `MemoryTokenStore`: In-memory storage for session-only authentication
  - `getTokenStore()`: Factory function for storage selection

- **Token Storage Tests**: 33 new tests covering:
  - localStorage mode behavior
  - memory mode behavior
  - store selection logic
  - configuration validation
  - security properties
  - token lifecycle

### Changed

- `getTokens()`, `setTokens()`, `clearTokens()` now use storage abstraction
- Total tests: 207 (was 174)

### Security

- Memory mode tokens are not accessible via `localStorage` or `sessionStorage` APIs
- Note: Memory mode tokens are still in JavaScript memory; XSS can access via `getTokens()`
- For full XSS protection, use Token Handler mode (v0.8.0) or BFF pattern

### Configuration

```javascript
// Memory mode (tokens lost on page reload)
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    tokenStorage: 'memory'
});
```

### Related

- Part of Token Handler roadmap: #4 (v0.7.0), #5 (v0.8.0), #6 (v0.9.0)
- See `docs/v1-token-storage-proposal.md` for full security architecture

## [0.6.2] - 2026-01-21

### Added

- **Security Hardening Guide**: `docs/security-hardening.md` with:
  - localStorage token storage risk assessment
  - CSP configuration with nonces (not just allowlists)
  - Backend for Frontend (BFF) pattern implementation
  - Token Handler pattern for lighter-weight security
  - Web Worker token isolation approach
  - DPoP (Demonstrating Proof-of-Possession) future roadmap
  - Threat model-based recommendations (low/medium/high risk)
  - Implementation checklists by risk level

### Documentation

- Comprehensive research on 2024-2025 token theft incidents
- Analysis of CSP bypass techniques and mitigations
- Code examples for Express.js BFF implementation

## [0.6.1] - 2026-01-21

### Added

- **Accessibility Guide**: `docs/accessibility.md` with comprehensive patterns for:
  - ARIA live regions for error announcements
  - Keyboard navigation for login forms
  - WebAuthn/passkey fallback guidance
  - Session timeout warnings
  - Focus management after login/logout
  - Screen reader testing checklist

## [0.6.0] - 2026-01-21

### Added

- **`onLogin(callback)`**: Subscribe to login events with tokens and auth method
  - Only fires on actual login (password, passkey, OAuth), never on token refresh
  - Callback receives `(tokens, method)` where method is 'password', 'passkey', or 'oauth'
  - Returns unsubscribe function
- **`onLogout(callback)`**: Subscribe to logout events
  - Fires when user logs out or tokens are cleared
  - Returns unsubscribe function
- **Claude-to-Claude workflow**: `docs/claude-workflow.md` for GitHub issue collaboration

### Changed

- **OAuth auth_method**: `exchangeCodeForTokens()` now sets `auth_method: 'oauth'` (was 'passkey')

## [0.5.7] - 2026-01-21

### Fixed

- **onAuthStateChange reload loop**: Token refresh no longer triggers `onAuthStateChange(true)`
  - Previously, `setTokens()` always notified listeners, causing infinite reload loops
  - Added `options.isRefresh` flag to skip notification during token refresh
  - `onAuthStateChange` now only fires on new login or logout, not token refresh

### Added

- **OCSF Security Logging**: Structured security events for AWS Security Lake integration
  - Configure via `securityLogger: 'console'` or custom function
  - Events for: login, logout, token refresh, passkey add/delete
  - OCSF v1.0 schema with Authentication (3001) and Account Change (3002) classes
  - See `docs/ocsf-logging.md` for integration guides

### Changed

- **Documentation reorganization**
  - Created `docs/migration.md` with complete v0.3→v0.5.x upgrade guide
  - Streamlined README from 203→127 lines, focused on quick start
  - Updated `docs/api-reference.md` with UNSAFE_ prefix and best practices

## [0.5.6] - 2026-01-21

### Added

- **GitHub Issue Processor**: `pnpm process-issue <number>` fetches and sanitizes GitHub issues
  - Uses `execFileSync` (no shell) to prevent command injection
  - Validates issue number as positive integer
  - Sanitizes all text content (removes control chars, limits length)
  - Detects suspicious patterns (shell injection, path traversal, script tags)
  - Verifies repository before fetching (prevents wrong-repo attacks)
  - Creates `.claude/issues/issue-<number>.md` with bug fix workflow checklist
  - Outputs are gitignored to prevent accidental commits

### Security

- Defense-in-depth against hostile GitHub issue content
- Unicode normalization to prevent homograph attacks

## [0.5.5] - 2026-01-21

### Added

- **Pre-commit hook**: Prevents committing src/auth.js without syncing dist/auth.js
  - Install with: `pnpm setup-hooks`
- **CI check**: Verifies dist/auth.js is in sync with src/auth.js
- **Auto-sync on release**: `npm version` now automatically syncs dist with src

### Scripts

- `pnpm check-dist` - Verify dist is in sync
- `pnpm sync-dist` - Auto-fix by copying src to dist
- `pnpm setup-hooks` - Install git hooks

## [0.5.4] - 2026-01-21

### Fixed

- **dist/auth.js sync**: The dist file was not updated with v0.5.2 and v0.5.3 changes
  - Now includes PKCE, HTTPS enforcement, cognitoDomain validation, and localStorage fix

## [0.5.3] - 2026-01-21

### Fixed

- **OAuth State Storage**: Switched from sessionStorage to localStorage to fix "Invalid OAuth state" errors
  - Safari ITP and Firefox ETP can clear sessionStorage during cross-domain OAuth redirects
  - localStorage survives cross-domain navigation while maintaining security (single-use, cleared immediately)
  - Also affects PKCE code verifier storage

### Added

- 6 new OAuth state storage tests (total: 174 tests)

## [0.5.2] - 2026-01-21

### Security

- **PKCE Implementation**: Added Proof Key for Code Exchange to prevent authorization code interception attacks
  - Generates cryptographically secure code verifier (RFC 7636 compliant)
  - SHA-256 code challenge sent with authorization request
  - Code verifier stored in localStorage and cleared after use (updated from sessionStorage in 0.5.3)

- **HTTPS Enforcement**: Redirect URIs must use HTTPS (except localhost for development)
  - Prevents token interception via network sniffing

- **Domain Validation**: Added cognitoDomain format validation
  - Prevents open redirect attacks via malicious authorization endpoints
  - Accepts standard Cognito domains and valid custom domains

- **Cookie Security Documentation**: Documented HttpOnly limitation
  - Client-side `document.cookie` cannot set HttpOnly (browser limitation)
  - Mitigations: Secure flag, SameSite=Lax, short-lived tokens

### Added

- **OAuth Security Test Suite**: 38 new tests covering:
  - PKCE code verifier/challenge generation
  - CSRF state parameter validation
  - Redirect URI validation
  - Token exchange security
  - Cookie security flags
  - HTTPS enforcement
  - Cognito domain validation

### Changed

- `loginWithHostedUI()` is now async (generates PKCE challenge)
- Total tests: 168 (was 130)

## [0.5.1] - 2026-01-21

### Added

- **Documentation Validation**: `pnpm validate-docs` script checks:
  - Version references in CLAUDE.md files match package.json
  - Test counts are accurate
  - Referenced files exist

- **Updated CLAUDE.md Files**: Comprehensive Claude Code integration guides with:
  - Current version and test counts
  - Release commands (patch/minor/major)
  - Security patterns and best practices
  - RBAC system documentation
  - Troubleshooting guides

### Changed

- CI now runs documentation validation on Node 20
- Version sync script now updates CLAUDE.md version references
- Plugin name standardized to `l42-cognito-passkey`

## [0.5.0] - 2026-01-21

### Added

- **CI/CD Pipeline**: GitHub Actions workflows for automated testing and publishing
  - `ci.yml`: Runs tests on PRs and pushes to main (Node 18, 20, 22)
  - `publish.yml`: Publishes to npm on version tags, creates GitHub releases

- **Semantic Versioning Automation**: Version bump scripts that keep all files in sync
  - `pnpm release:patch` - Bug fixes (0.5.0 → 0.5.1)
  - `pnpm release:minor` - New features (0.5.0 → 0.6.0)
  - `pnpm release:major` - Breaking changes (0.5.0 → 1.0.0)
  - `pnpm release:prerelease` - Pre-release versions (0.5.1-rc.0)

- **Version Sync Script**: `scripts/sync-version.js` automatically updates version in:
  - `src/auth.js` (@version JSDoc)
  - `plugin/plugin.json`
  - All documentation files

- **Release Documentation**: `docs/RELEASING.md` with complete release process

### Changed

- All previous versions are now preserved on npm (semantic versioning)
- Version consistency tests now run in CI

## [0.4.0] - 2026-01-21

### Security Improvements

- **`UNSAFE_decodeJwtPayload()`**: Renamed from `decodeJwtPayload()` to clearly indicate
  the function returns UNVERIFIED claims. The old function name still works but emits
  a deprecation warning. This prevents developers from accidentally using JWT claims
  for authorization decisions.

- **`requireServerAuthorization()`**: New helper that enforces server-side authorization
  checks. Makes the secure path (server validation) the easy path:
  ```javascript
  const result = await auth.requireServerAuthorization('admin:delete-user');
  if (!result.authorized) throw new Error(result.reason);
  ```

- **`UI_ONLY_hasRole()`**: Explicitly named function for client-side role checks that
  are ONLY for UI display purposes (showing/hiding buttons). The name reminds developers
  this is not for authorization.

- **ccTLD Cookie Domain Fix**: Cookie domain detection now correctly handles country-code
  TLDs like `.co.uk`, `.com.au`, `.co.jp` (30+ public suffixes supported). Previously,
  `app.example.co.uk` would incorrectly set domain to `.co.uk`.

### Added

- **Cognito Group Aliases**: `COGNITO_GROUPS` constant centralizes group name handling
  with alias support. Handles singular/plural variations automatically:
  ```javascript
  import { isInCognitoGroup } from './rbac-roles.js';
  isInCognitoGroup(groups, 'ADMIN'); // matches 'admin', 'admins', 'administrators'
  ```

- **`isInCognitoGroup()`**: Case-insensitive group membership check with alias support
- **`isInAnyCognitoGroup()`**: Check membership in any of multiple groups
- **`getCanonicalGroupName()`**: Get standard group name for Cognito configuration

- **Property-Based Tests**: 22 new tests using fast-check that verify RBAC invariants:
  - Role hierarchy transitivity
  - Admin supremacy (level 100, wildcard permissions)
  - Permission inheritance
  - Cognito group alias consistency
  - Role management anti-reflexivity

- **CLAUDE.md**: Integration guide for Claude Code instances
- **docs/cedar-integration.md**: AWS Cedar + Verified Permissions design document

### Changed

- `decodeJwtPayload()` now emits deprecation warning (use `UNSAFE_decodeJwtPayload()`)
- `parseJwt()` now emits deprecation warning (use `UNSAFE_decodeJwtPayload()`)

### Developer Experience

- Added `fast-check` as dev dependency for property-based testing
- All 119 tests pass (97 existing + 22 new property-based)

## [0.3.0] - 2026-01-21

### Added

- **RBAC Role System**: Comprehensive role definitions in `plugin/templates/rbac-roles.js`
  - 3 core roles: `admin`, `readonly`, `user`
  - 20+ standard roles for common patterns
  - Role hierarchy with level-based permissions (10-100)
  - Permission checking: `hasPermission()`, `canManageRole()`, `getRoleHierarchy()`
  - Cognito group mapping: `getCognitoGroupConfig()`

- **Static Site Pattern** (`plugin/templates/static-site-pattern.html`)
  - Public static site + protected auth area architecture
  - Roles: readonly, user, editor, reviewer, publisher, admin
  - 27 unit tests for RBAC and permission logic

- **Admin Panel Pattern** (`plugin/templates/admin-panel-pattern.html`)
  - Admin-only interface for user management
  - User listing with search/filter and pagination
  - User invitation via email with role assignment
  - User enable/disable and password reset
  - Audit logging for admin actions
  - 41 unit tests for access control, invitations, and filtering

- **XSS-Safe Patterns**: All templates use `textContent` for user data
- **CSP Requirements**: Documented Content-Security-Policy headers
- **Test Framework**: Vitest integration with `npm test`
- **BACKLOG.md**: Documented future features and priorities

### Changed

- Session codes now exclude confusing characters (0, O, 1, I, L)
- Updated plugin/CLAUDE.md with comprehensive documentation

### Fixed

- Session code generator test was using outdated character set

## [0.2.0] - 2026-01-21

### Breaking Changes

- **Self-hosted by default**: Library is now designed to be self-hosted. Copy `src/auth.js` to your project.
- **Configuration required**: Must call `configure()` or set `window.L42_AUTH_CONFIG` before using auth functions.
- **Token storage key changed**: Default key is now `l42_auth_tokens` (was `lexicone_auth_tokens`).

### Added

- `VERSION` export for checking library version
- `isConfigured()` function to check configuration status
- Auto-configuration from `window.L42_AUTH_CONFIG`
- Configurable `allowedDomains` for redirect URI validation
- Configurable `cookieDomain` (auto-detected if not set)
- Better error messages when configuration is missing
- Comprehensive documentation (README, API reference, Cognito setup guide)
- Example files for basic usage
- `cognito-setup.py` script for WebAuthn configuration

### Changed

- Allowed domains now auto-include current domain (no explicit allowlist needed for same-domain)
- Cookie domain is auto-detected based on hostname
- Error messages are more descriptive and actionable

### Fixed

- CORS issues when importing from different domains (now self-hosted)
- Hardcoded domain restrictions that blocked third-party integrations
- Hardcoded cookie domain that prevented cross-domain usage
- Token exchange failures when `configure()` not called (now gives clear error)

### Removed

- Hardcoded `lexicone.com` domain restrictions
- CDN dependency (library is self-hosted)

## [0.1.1] - 2026-01-18

### Added

- Token refresh behavior varies by auth method (1-day for password, 30-day for passkey)
- `ensureValidTokens()` for automatic token refresh before API calls
- `getAuthMethod()` to check current auth method
- `shouldRefreshToken()` for proactive refresh checking

### Changed

- OAuth flow now sets `auth_method: 'passkey'` for longer refresh period

## [0.1.0] - 2026-01-15

### Added

- Initial release
- Password authentication via Cognito USER_PASSWORD_AUTH
- WebAuthn passkey authentication
- OAuth2 flow with CSRF protection
- Token management with localStorage
- Cross-subdomain cookie for Lambda@Edge validation
- RBAC via Cognito groups (admin, readonly)
- Auth state change listeners
- Passkey management (list, register, delete)
