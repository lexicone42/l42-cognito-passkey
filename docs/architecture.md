# Architecture

How L42 Cognito Passkey works internally.

## Overview

Two components: a client library (`auth.js`) and a Token Handler backend.

```
┌──────────────────────────────────────────────────────────┐
│  Browser (auth.js)                                        │
│                                                           │
│  ┌────────────┐  ┌──────────────┐  ┌───────────────┐     │
│  │   Login    │  │    Token     │  │    Event      │     │
│  │  Methods   │  │   Cache      │  │   System      │     │
│  │            │  │              │  │               │     │
│  │ password   │  │ 30s TTL     │  │ onLogin()     │     │
│  │ passkey    │  │ from server  │  │ onLogout()    │     │
│  │ hosted UI  │  │              │  │ onExpired()   │     │
│  │ cond. UI   │  │              │  │               │     │
│  └─────┬──────┘  └──────┬───────┘  └───────────────┘     │
│        │                │                                 │
│        ▼                ▼                                 │
│  ┌──────────────────────────┐  ┌────────────────────┐     │
│  │     Auto-Refresh         │  │  UI RBAC (hints)   │     │
│  │  visibility API aware    │  │  isAdmin()         │     │
│  └──────────────────────────┘  └────────────────────┘     │
│                                                           │
│  requireServerAuthorization() ────────────────────┐       │
└───────────────────────────────────────────────────│───────┘
                                                    │
                  ┌─────────────────────────────────▼───┐
                  │  Token Handler Backend                │
                  │                                      │
                  │  /auth/token     → return tokens      │
                  │  /auth/session   → store tokens       │
                  │  /auth/refresh   → Cognito refresh    │
                  │  /auth/logout    → destroy session    │
                  │  /auth/callback  → OAuth exchange     │
                  │  /auth/authorize → Cedar evaluation   │
                  └────────────────┬─────────────────────┘
                                   │
                  ┌────────────────▼─────────────────────┐
                  │  AWS Cognito                          │
                  │                                      │
                  │  User Pool → password auth, tokens   │
                  │  WebAuthn  → passkey register/verify  │
                  │  OAuth2    → hosted UI, code exchange │
                  └──────────────────────────────────────┘
```

## Token Handler Pattern

The Token Handler is a thin backend that manages OAuth/OIDC tokens so the browser never stores them. The browser gets an opaque HttpOnly session cookie; the backend holds the actual JWTs.

```
Browser tab ──► session cookie (HttpOnly, Secure, SameSite=Lax)
                  │
                  ▼
Your Server ──► req.session.tokens
                  ├── access_token
                  ├── id_token
                  └── refresh_token  ← never sent to browser
```

Tokens are invisible to JavaScript entirely — XSS can't steal them. The client calls `await getTokens()` to fetch access/id tokens from the server (cached for 30 seconds).

This is a specific type of Backend-for-Frontend (BFF) pattern. A full BFF proxies all API calls; a Token Handler is lighter — the browser still makes API calls directly but gets tokens from the backend instead of storing them locally. Cedar authorization adds server-verified policy checks, making this an authorization BFF as well.

## Protocol Specification

Any server implementing these endpoints works with `auth.js`, regardless of language.

### Session Contract

The backend stores one structure per session:

```json
{
  "tokens": {
    "access_token": "<JWT>",
    "id_token": "<JWT>",
    "refresh_token": "<JWT or null>",
    "auth_method": "direct | oauth"
  }
}
```

The refresh token **never** leaves the server. Session cookies must be `HttpOnly`, `Secure` (in production), and `SameSite=Lax`.

### Endpoints

| Endpoint | Method | CSRF | Purpose |
|----------|--------|------|---------|
| `/auth/token` | GET | No | Return `{access_token, id_token}` from session |
| `/auth/session` | POST | Yes | Store tokens after passkey/password login |
| `/auth/refresh` | POST | Yes | Refresh tokens via Cognito, return new tokens |
| `/auth/logout` | POST | Yes | Destroy session, clear cookie |
| `/auth/callback` | GET | No* | OAuth code exchange, store tokens, redirect |
| `/auth/authorize` | POST | Yes | Cedar policy evaluation |
| `/auth/me` | GET | No | Return user info from session |
| `/health` | GET | No | Liveness check |

\* `/auth/callback` uses OAuth `state` for CSRF instead.

### CSRF Protection

All POST endpoints require `X-L42-CSRF: 1`. `auth.js` adds this automatically. Cross-origin requests can't set custom headers without a CORS preflight, which your backend rejects for unknown origins.

### Security Invariants

1. Refresh tokens never leave the server
2. Session cookie is HttpOnly
3. CSRF header required on all POSTs (except `/auth/callback`)
4. `/auth/session` verifies `id_token` signature against Cognito JWKS before storing
5. `/auth/authorize` fails closed — denies access if the policy engine errors
6. Session destroyed on refresh failure
7. CORS restricted to frontend origin (no wildcards with credentials)

## Authentication Flows

### Password

```
loginWithPassword(email, password)
    ├── checkLoginRateLimit(email)
    ├── cognitoRequest('InitiateAuth', USER_PASSWORD_AUTH)
    ├── Cognito returns tokens
    ├── POST /auth/session (store tokens server-side)
    ├── resetLoginAttempts(email)
    └── notifyLogin → starts auto-refresh
```

### Passkey

```
loginWithPasskey(email)
    ├── checkLoginRateLimit(email)
    ├── cognitoRequest('InitiateAuth', CUSTOM_AUTH)
    ├── Cognito returns CUSTOM_CHALLENGE with credential request options
    ├── navigator.credentials.get({ publicKey: ... })
    ├── User touches biometric / enters PIN
    ├── buildAssertionResponse(credential)  ← includes authenticatorMetadata
    ├── cognitoRequest('RespondToAuthChallenge', credential)
    ├── Cognito verifies signature, returns tokens
    ├── POST /auth/session (store tokens server-side)
    └── notifyLogin → starts auto-refresh
```

### Conditional UI (Passkey Autofill)

```html
<input type="email" autocomplete="username webauthn">
```

```
loginWithConditionalUI({ mode: 'discovery' })
    ├── Creates AbortController (auto-aborted on other login/logout)
    ├── navigator.credentials.get({ mediation: 'conditional' })
    ├── User picks passkey from autofill dropdown
    └── Same flow as loginWithPasskey from here
```

Two modes: **email** (scoped to one user) and **discovery** (browser shows all passkeys for this domain).

### OAuth / Hosted UI

```
loginWithHostedUI(email?)
    ├── Generate PKCE: code_verifier + code_challenge
    ├── Store state + verifier in localStorage
    ├── Redirect to Cognito hosted UI
    │   User authenticates
    ├── Cognito redirects to /auth/callback?code=...&state=...
    ├── Backend exchanges code for tokens (server-to-server)
    ├── Backend stores tokens in session
    └── Backend redirects to frontend
```

## Token Lifecycle

```
                Token Lifetime (~1 hour)
    ┌────────────────────────────────────────────┐
    │  Valid         Refresh Window     Expired   │
    │ ◄────────────►◄──────────────►◄──────────► │
    │                 (last 5 min)                │
    └────────────────────────────────────────────┘
        getTokens()    shouldRefresh()    try refresh
        returns cache  → refreshTokens()  → if fails: onSessionExpired()
```

### Auto-Refresh

Starts on login, stops on logout:

1. `setInterval` checks every 60s (configurable)
2. If token nearing expiry → proactive `refreshTokens()`
3. Tab hidden → pauses (visibility API)
4. Tab visible → immediate check + resume

## Cedar Authorization

Two authorization layers with different trust levels:

**Client-side (UI hints only):** `isAdmin()`, `isReadonly()`, `UI_ONLY_hasRole()` read unverified JWT claims. Never use for real authorization.

**Server-side (Cedar policies):**

```javascript
const result = await requireServerAuthorization('write:own', {
    resource: { id: 'doc-123', type: 'document', owner: ownerSub }
});
```

The server reads user identity from the verified session, maps Cognito groups to Cedar entities, and evaluates policies:

```cedar
// Editors can read and write content
permit(
    principal in App::UserGroup::"editors",
    action in [App::Action::"read:content", App::Action::"write:content"],
    resource
);

// Nobody can write another user's documents (forbid overrides permit)
forbid(
    principal,
    action == App::Action::"write:own",
    resource
) when { resource has owner && resource.owner != principal };
```

Key principle: **forbid always overrides permit**, making ownership enforcement robust.

Cognito group aliases are resolved automatically: `admin`, `admins`, `administrators` all map to the Cedar entity `App::UserGroup::"admin"`.

## Event System

| Event | Fires When | Signature |
|-------|-----------|-----------|
| `onLogin(cb)` | User logs in | `(tokens, method)` |
| `onLogout(cb)` | User logs out | `()` |
| `onAuthStateChange(cb)` | Login or logout | `(isAuthenticated)` |
| `onSessionExpired(cb)` | Refresh fails permanently | `(reason)` |

`onAuthStateChange` does **not** fire on token refresh. All `on*()` functions return an unsubscribe function.

## Configuration

```javascript
configure({
    // Required
    clientId: 'your-cognito-client-id',
    cognitoDomain: 'yourapp.auth.us-west-2.amazoncognito.com',

    // Handler endpoints (required)
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    sessionEndpoint: '/auth/session',

    // Optional
    oauthCallbackUrl: '/auth/callback',
    handlerCacheTtl: 30000,          // Cache TTL in ms
    relyingPartyId: 'yourdomain.com', // WebAuthn
    maxLoginAttemptsBeforeDelay: 3,
    loginBackoffBaseMs: 1000,
    loginBackoffMaxMs: 30000,
    debug: false,                     // true, 'verbose', or function(event)
});
```

Alternative: set `window.L42_AUTH_CONFIG` before importing `auth.js`.

## Design Decisions & Gotchas

### `getTokens()` always returns a Promise

Always use `await getTokens()`. It fetches from the server when the cache expires. Calling it without `await` gives you a Promise object, not tokens.

### `isAuthenticated()` uses a 30-second cache

It's synchronous and fast, but may briefly return `false` after the cache expires. Use `isAuthenticatedAsync()` when the result is critical. `isAuthenticated()` is fine for UI rendering.

### `fetchWithAuth` retries on 401

If a request gets a 401, `fetchWithAuth` refreshes tokens and retries the entire request — including POST bodies. For non-idempotent requests (payments, order creation), refresh tokens proactively with `ensureValidTokens()` and handle 401 yourself.

### Admin overrides readonly

`isAdmin()` and `isReadonly()` are mutually exclusive. A user in both `admin` and `readonly` groups gets `isAdmin() === true`, `isReadonly() === false`.

### `:own` vs `:all` actions

The ownership forbid policy fires unconditionally when `resource.owner != principal` — even for admins. Admins must use `:all` variants (`write:all`, `delete:all`) to modify other users' resources.

### `resource.owner` is caller-controlled

The client sends `resource.owner` in the request body. A malicious client can lie. For production ownership enforcement, the server must look up the true owner from a database (EntityProvider interface). Client-supplied ownership is acceptable only as defense-in-depth in UI-gated workflows.

## File Layout

```
src/auth.js              ← The library (~1400 lines, self-contained)
src/auth.d.ts            ← TypeScript declarations

rust/                    ← Rust Token Handler backend (recommended)
├── src/
│   ├── main.rs          ← Dual-mode: Lambda or local Axum server
│   ├── cedar/engine.rs  ← Native Cedar evaluation
│   ├── session/         ← HMAC-SHA256 session cookies
│   └── routes/*.rs      ← HTTP handlers
├── cedar/               ← Schema + 9 policy files
└── tests/               ← Integration tests

examples/backends/express/  ← Express backend (alternative)
├── server.js
├── cedar-engine.js
└── cedar/

plugin/templates/
├── rbac-roles.js        ← Role definitions and permission helpers
├── *.test.js            ← Test files
└── *.html               ← Integration template patterns
```
