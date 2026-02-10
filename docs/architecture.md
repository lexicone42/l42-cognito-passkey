# Architecture Overview

A developer-friendly guide to how L42 Cognito Passkey works internally.

**Version**: 0.15.0 | **Tests**: 658 | **License**: Apache-2.0

## What This Library Does

L42 Cognito Passkey is a **client-side JavaScript module** that handles authentication against AWS Cognito. You copy a single file (`auth.js`) into your project and import it as an ES module — no build step, no CDN, no npm install required.

It handles:
- Password and passkey (WebAuthn) login against Cognito
- OAuth2/OIDC redirect flows with PKCE
- Token storage, refresh, and lifecycle management
- Role-based access control (RBAC) via Cognito groups
- Server-side authorization via Cedar policies (v0.13.0+)

## The Big Picture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (auth.js)                                              │
│                                                                 │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  Login    │  │    Token     │  │    Event     │              │
│  │  Methods  │  │   Storage    │  │   System     │              │
│  │          │  │              │  │              │              │
│  │ password  │  │ localStorage │  │ onLogin()    │              │
│  │ passkey   │  │ memory       │  │ onLogout()   │              │
│  │ hosted UI │  │ handler      │  │ onAuthState  │              │
│  │ cond. UI  │  │              │  │ onExpired()  │              │
│  └─────┬─────┘  └──────┬───────┘  └──────────────┘              │
│        │               │                                        │
│        ▼               ▼                                        │
│  ┌──────────────────────────┐  ┌────────────────────┐           │
│  │     Auto-Refresh         │  │  UI RBAC (hints)   │           │
│  │  (background interval)   │  │  isAdmin()         │           │
│  │  (visibility API aware)  │  │  isReadonly()       │           │
│  └──────────────────────────┘  └────────────────────┘           │
│                                                                 │
│  requireServerAuthorization() ──────────────────────────┐       │
└──────────────────────────────────────────────────────────│───────┘
                                                           │
                   ┌───────────────────────────────────────▼───┐
                   │  Your Backend (Express example)           │
                   │                                           │
                   │  /auth/token     → session token store    │
                   │  /auth/refresh   → Cognito token refresh  │
                   │  /auth/logout    → session destroy         │
                   │  /auth/authorize → Cedar policy engine    │
                   │                                           │
                   └───────────────┬───────────────────────────┘
                                   │
                   ┌───────────────▼───────────────────────────┐
                   │  AWS Cognito                               │
                   │                                           │
                   │  User Pool → password auth, token issue   │
                   │  WebAuthn  → passkey register/verify      │
                   │  OAuth2    → hosted UI, code exchange     │
                   └───────────────────────────────────────────┘
```

## Token Storage Modes

Handler mode is the only supported token storage mode (since v0.15.0).

Tokens live on your server in an HttpOnly session cookie. The browser never sees the refresh token.

```
Browser tab ──► session cookie (HttpOnly, Secure, SameSite=Strict)
                  │
                  ▼
Your Server ──► req.session.tokens
                  ├── access_token
                  ├── id_token
                  └── refresh_token  ← never sent to browser
```

Tokens are invisible to JavaScript entirely — XSS can't steal them.

### `getTokens()` and `await`

Always use `await getTokens()` — it works in all modes and is required for handler mode:

```javascript
const tokens = await getTokens();
```

## Authentication Flows

### Password Login

The simplest flow — direct Cognito SRP (Secure Remote Password) authentication:

```
loginWithPassword(email, password)
    │
    ├─ checkLoginRateLimit(email)    ← throttle if too many failures
    │
    ├─ cognitoRequest('InitiateAuth', {
    │      AuthFlow: 'USER_PASSWORD_AUTH',
    │      AuthParameters: { USERNAME: email, PASSWORD: password }
    │  })
    │
    ├─ Cognito returns tokens
    │
    ├─ setTokens(tokens, { authMethod: 'password' })
    │      └─ Writes to storage (localStorage/memory/handler)
    │
    ├─ resetLoginAttempts(email)     ← clear failure counter
    │
    └─ notifyLogin(tokens, 'password')
           ├─ fires onLogin() listeners
           └─ starts auto-refresh
```

### Passkey Login

WebAuthn authentication using platform authenticators (Touch ID, Windows Hello, etc.):

```
loginWithPasskey(email)
    │
    ├─ checkLoginRateLimit(email)
    │
    ├─ cognitoRequest('InitiateAuth', {
    │      AuthFlow: 'CUSTOM_AUTH',
    │      AuthParameters: { USERNAME: email }
    │  })
    │
    ├─ Cognito returns challenge:
    │  { ChallengeName: 'CUSTOM_CHALLENGE', Session: '...',
    │    ChallengeParameters: { CREDENTIAL_REQUEST_OPTIONS: '...' } }
    │
    ├─ navigator.credentials.get({
    │      publicKey: {
    │          challenge: ...,
    │          rpId: config.relyingPartyId,
    │          allowCredentials: [...],  ← from Cognito's options
    │          userVerification: 'preferred'
    │      }
    │  })
    │
    ├─ User touches fingerprint sensor / enters PIN
    │
    ├─ buildAssertionResponse(credential)
    │      └─ base64url-encodes authenticatorData, clientDataJSON, signature
    │
    ├─ cognitoRequest('RespondToAuthChallenge', {
    │      ChallengeName: 'CUSTOM_CHALLENGE',
    │      ChallengeResponses: { CREDENTIAL: JSON.stringify(assertion) }
    │  })
    │
    ├─ Cognito verifies the signature, returns tokens
    │
    └─ setTokens → notifyLogin → auto-refresh starts
```

### Conditional UI (Passkey Autofill)

This is the "passkey-first" experience where the browser shows passkeys in the username field's autofill dropdown:

```html
<input type="email" autocomplete="username webauthn">
```

```
loginWithConditionalUI({ mode: 'discovery' })
    │
    ├─ Creates AbortController (_conditionalAbortController)
    │   └─ Auto-aborted if user calls loginWithPassword/logout/etc.
    │
    ├─ navigator.credentials.get({
    │      publicKey: { challenge: ... },
    │      mediation: 'conditional',     ← key: shows in autofill
    │      signal: abortController.signal
    │  })
    │
    ├─ User picks a passkey from autofill dropdown
    │
    └─ Same flow as loginWithPasskey from here
```

Two modes:
- **Mode A (email)**: Scoped to a specific email — shows only that user's passkeys
- **Mode B (discovery)**: Browser shows all passkeys for this domain

### OAuth / Hosted UI

For federated login (Google, SAML, etc.) via Cognito's hosted UI:

```
loginWithHostedUI(email?)
    │
    ├─ Generate PKCE: code_verifier + code_challenge
    │
    ├─ Store OAuth state in localStorage:
    │   { state: random, code_verifier, redirect_uri, timestamp }
    │
    ├─ Redirect browser to:
    │   https://{domain}/oauth2/authorize?
    │     client_id={}&response_type=code&
    │     redirect_uri={}&code_challenge={}&
    │     state={}
    │
    │   ← User authenticates at Cognito hosted UI →
    │
    ├─ Cognito redirects back to redirectUri?code={}&state={}
    │
    └─ exchangeCodeForTokens(code, state)
           ├─ Verify state matches what we stored (CSRF protection)
           ├─ POST /oauth2/token with code + code_verifier (PKCE)
           └─ Store tokens → notify login
```

## Token Lifecycle

Tokens have a lifecycle managed by the auto-refresh system:

```
                    Token Lifetime (~1 hour)
    ┌────────────────────────────────────────────────┐
    │                                                │
    │    Valid           Refresh Window    Expired    │
    │  ◄──────────────►◄──────────────►◄────────►    │
    │                   (last 5 min)                 │
    └────────────────────────────────────────────────┘
         │                   │               │
         │                   │               │
    getTokens()         shouldRefresh()   isExpired()
    returns tokens      → refreshTokens()  → try refresh
                                           → if fails: onSessionExpired()
```

### Auto-Refresh

When auto-refresh is active (started automatically on login):

1. A `setInterval` runs every 60 seconds (configurable)
2. It calls `shouldRefreshToken()` — returns true if expiry < 5 minutes away
3. If true, calls `refreshTokens()` which contacts Cognito for new tokens
4. New tokens are stored silently (no `onAuthStateChange` fired)
5. If the page is hidden (tab in background), refresh pauses to save bandwidth
6. When the tab becomes visible again, it immediately checks and refreshes if needed

### Visibility API Integration

```
Tab visible  → auto-refresh running every 60s
Tab hidden   → auto-refresh paused
Tab visible  → immediate check + resume interval
```

This prevents wasted network requests when the user isn't looking at the page, while ensuring tokens are fresh when they return.

## RBAC and Authorization

The library has two authorization layers with very different trust levels:

### Client-Side (UI Hints Only)

```javascript
isAdmin()     // → reads JWT claims, checks for 'admin' group
isReadonly()  // → reads JWT claims, checks for 'readonly' group
UI_ONLY_hasRole('editor')  // → checks JWT claims for any role
```

These are for **showing/hiding UI elements only**. They read unverified JWT claims that a sophisticated attacker could forge. Never use them for real authorization.

### Server-Side (Cedar Policies)

```javascript
const result = await requireServerAuthorization('admin:delete-user', {
    resource: { id: 'user-123', type: 'user', owner: 'user-456' }
});
// → POSTs to /auth/authorize
// → Server evaluates Cedar policies against verified session
// → Returns { authorized: true/false, reason, diagnostics }
```

This is real authorization. The server:
1. Reads the user's identity from the verified session (not client claims)
2. Maps Cognito groups to Cedar entity types
3. Evaluates Cedar policies: `(principal, action, resource) → allow/deny`
4. Returns a cryptographically trustworthy decision

### Cedar Policy Architecture

Cedar is a declarative policy language from AWS. Policies are simple to read:

```cedar
// Editors can read, write, and publish content
permit(
    principal in App::UserGroup::"editors",
    action in [
        App::Action::"read:content",
        App::Action::"write:content",
        App::Action::"publish:content"
    ],
    resource
);

// Nobody can write another user's documents (forbid overrides permit)
forbid(
    principal,
    action == App::Action::"write:own",
    resource
) when {
    resource has owner &&
    resource.owner != principal
};
```

Key design principle: **forbid always overrides permit**. This makes ownership enforcement robust — even if a user has a `permit` for `write:own`, the `forbid` blocks them if they're not the owner.

### Entity Mapping

```
Cognito Group 'admins'
        │
        ▼  (group alias resolution)
Cedar Entity: App::UserGroup::"admin"
        │
        ▼  (policy evaluation)
permit(principal in App::UserGroup::"admin", action, resource)
        │
        ▼
Decision: ALLOW (for any action)
```

The group alias system handles the common problem of Cognito groups being named inconsistently (`admin`, `admins`, `administrators` all map to the Cedar group `admin`).

## Event System

The library provides four event channels:

| Event | Fires When | Callback Signature |
|-------|-----------|-------------------|
| `onLogin(cb)` | User logs in (any method) | `(tokens, method)` |
| `onLogout(cb)` | User logs out | `()` |
| `onAuthStateChange(cb)` | Auth state changes (login or logout) | `(isAuthenticated)` |
| `onSessionExpired(cb)` | Token refresh fails permanently | `(reason)` |

Important: `onAuthStateChange` does **not** fire on token refresh. This prevents infinite reload loops that plagued earlier versions.

```javascript
// Typical usage
onLogin((tokens, method) => {
    analytics.track('login', { method });
    router.push('/dashboard');
});

onLogout(() => {
    router.push('/login');
});

onSessionExpired((reason) => {
    showModal('Your session has expired. Please log in again.');
    router.push('/login?expired=true');
});
```

All `on*()` functions return an unsubscribe function:

```javascript
const unsub = onLogin(handler);
// Later:
unsub(); // Removes the listener
```

## Security Architecture

### What's Verified Where

| Check | Client-Side | Server-Side |
|-------|------------|-------------|
| Token not expired | `isTokenExpired()` | Session TTL |
| Token issuer correct | `validateTokenClaims()` | Cognito verification |
| Token audience correct | `validateTokenClaims()` | Cognito verification |
| User has role | `isAdmin()` (untrusted) | Cedar policy evaluation |
| User owns resource | N/A | Cedar `forbid` policy |
| CSRF on mutations | N/A | `X-L42-CSRF` header check |
| PKCE on OAuth | `code_verifier` stored client-side | Cognito verifies at `/oauth2/token` |
| Rate limiting | `checkLoginRateLimit()` (client) | Cognito account lockout |

### Trust Boundaries

```
┌─────────────────────────────────┐
│  UNTRUSTED: Browser             │
│                                 │
│  JWT claims (can be forged)     │
│  Client RBAC (UI hints only)    │
│  Rate limiting (can be bypassed)│
│  localStorage (XSS-accessible)  │
└──────────────┬──────────────────┘
               │
    ═══════════╪═══════════  Trust Boundary
               │
┌──────────────▼──────────────────┐
│  TRUSTED: Server                │
│                                 │
│  Session cookies (HttpOnly)     │
│  Cedar policy evaluation        │
│  Token refresh (refresh_token   │
│    never leaves server)         │
│  Cognito API calls              │
└─────────────────────────────────┘
```

### Known Limitations (Sharp-Edges)

These are documented, tested, and by-design:

1. **`resource.owner` is caller-controlled (S1)**: The client sends `resource.owner` in the request body. A malicious client can lie about ownership. The fix (post-1.0) is the `EntityProvider` interface that loads ownership from a trusted database.

2. **`validateTokenClaims()` skips missing fields (S2)**: If a JWT lacks an `iss` claim, the issuer check is skipped (not failed). This is intentional for backwards compatibility but means tokens from misconfigured pools may pass validation.

3. **Rate limiting is client-side only (S3)**: The `checkLoginRateLimit()` delays are enforced in JavaScript. A determined attacker can bypass them. Cognito's server-side lockout is the real protection.

## File Layout

```
src/
├── auth.js              ← The library (~1400 lines, self-contained)
└── auth.d.ts            ← TypeScript declarations

dist/
└── auth.js              ← Copy of src/auth.js (for package consumers)

plugin/templates/
├── rbac-roles.js        ← Role definitions and permission helpers
├── *.test.js            ← 17 test files (658 tests)
└── *.html               ← Integration template patterns

examples/backends/express/
├── server.js            ← Token Handler Express backend
├── cedar-engine.js      ← Cedar WASM wrapper (~300 lines)
└── cedar/
    ├── schema.cedarschema.json  ← Entity types and actions
    └── policies/
        ├── admin.cedar          ← Admin wildcard permit
        ├── editor.cedar         ← Content editing
        ├── reviewer.cedar       ← Content review
        ├── publisher.cedar      ← Content publishing
        ├── readonly.cedar       ← Read-only access
        ├── user.cedar           ← Own-resource access
        ├── moderator.cedar      ← Community moderation
        ├── developer.cedar      ← Dev tools and APIs
        └── owner-only.cedar     ← Ownership enforcement (forbid)

docs/
├── architecture.md      ← This file
├── api-reference.md     ← Complete function documentation
├── cedar-integration.md ← Cedar setup and usage guide
├── handler-mode.md      ← Token Handler mode guide
├── migration.md         ← Version upgrade guide
├── design-decisions.md  ← Why things are the way they are
├── security-hardening.md← CSP, BFF, threat models
└── ...
```

## Configuration Reference

```javascript
configure({
    // Required
    clientId: 'your-cognito-client-id',
    cognitoDomain: 'yourapp.auth.us-west-2.amazoncognito.com',

    // Token storage — handler mode recommended for production
    tokenStorage: 'handler',  // 'localStorage' and 'memory' are deprecated

    // Handler mode endpoints (required)
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    oauthCallbackUrl: '/auth/callback',

    // WebAuthn
    relyingPartyId: 'yourdomain.com',

    // Rate limiting
    maxLoginAttemptsBeforeDelay: 3,
    loginBackoffBaseMs: 1000,
    loginBackoffMaxMs: 30000,

    // Debug
    debug: false,  // true, 'verbose', or function(event)
});
```

## Testing

The library has 658 tests across 17 files, organized by feature:

| Test File | Tests | What It Covers |
|-----------|-------|----------------|
| `cedar-authorization.test.js` | 132 | Policy evaluation, ownership, group aliases, property tests |
| `handler-sync-api.test.js` | 52 | Handler mode token operations |
| `oauth-security.test.js` | 44 | PKCE, CSRF, OAuth state validation |
| `token-storage.test.js` | 41 | localStorage/memory/handler storage |
| `admin-panel-pattern.test.js` | 41 | Admin UI patterns |
| `login-rate-limiting.test.js` | 40 | Rate limiting and exponential backoff |
| `static-site-pattern.test.js` | 36 | Static site integration |
| `auto-refresh.test.js` | 35 | Background token refresh |
| `debug-diagnostics.test.js` | 34 | Debug logging |
| `auth-properties.test.js` | 41 | Property-based tests (fast-check) |
| `conditional-ui.test.js` | 32 | Passkey autofill |
| `token-validation.test.js` | 31 | Token claim validation |
| `conditional-create.test.js` | 23 | Passkey upgrade |
| `rbac-roles.property.test.js` | 22 | RBAC property tests |
| `webauthn-capabilities.test.js` | 22 | WebAuthn feature detection |
| `version-consistency.test.js` | 11 | Version sync across files |
| `handler-token-store.test.js` | 37 | Handler mode token store |

Tests use Vitest with jsdom environment. Property-based tests use fast-check for invariant verification (e.g., "admin is always permitted", "backoff delay never exceeds max").

## Where to Go Next

- **Setting up for the first time?** Start with [the Quick Start in README.md](../README.md#quick-start)
- **Using handler mode?** See [handler-mode.md](handler-mode.md)
- **Adding Cedar authorization?** See [cedar-integration.md](cedar-integration.md)
- **Upgrading from an older version?** See [migration.md](migration.md)
- **Understanding design trade-offs?** See [design-decisions.md](design-decisions.md)
- **Hardening for production?** See [security-hardening.md](security-hardening.md)
