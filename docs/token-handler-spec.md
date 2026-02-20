# Token Handler Protocol Specification

> **Version**: 1.0 (aligned with l42-cognito-passkey v0.15.1)
>
> This document specifies the HTTP protocol contract between `auth.js` (the browser client) and a Token Handler backend. Any server that implements these endpoints with the described semantics will work with `auth.js`, regardless of language or framework.

## Overview

The Token Handler is a thin backend that manages OAuth/OIDC token lifecycle so the browser never stores tokens directly. The browser receives an opaque session cookie; the backend holds the actual JWT tokens server-side.

```
Browser (auth.js)                    Token Handler Backend
─────────────────                    ─────────────────────
configure({                          Implements 8 endpoints
  tokenEndpoint,                     Stores tokens in server-side session
  refreshEndpoint,                   Returns session ID via HttpOnly cookie
  logoutEndpoint,
  sessionEndpoint,
  oauthCallbackUrl
})
```

## Session Contract

### Session Data Shape

The backend stores exactly one data structure per session:

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

| Field | Type | Description |
|---|---|---|
| `access_token` | string | Cognito access token JWT |
| `id_token` | string | Cognito ID token JWT (contains user claims) |
| `refresh_token` | string \| null | Cognito refresh token. **Never returned to the browser.** |
| `auth_method` | string | How the session was created: `"direct"` (passkey/password) or `"oauth"` (hosted UI flow) |

### Session Cookie Requirements

The session ID cookie **must** have these properties:

| Property | Value | Rationale |
|---|---|---|
| `HttpOnly` | `true` | Prevents JavaScript access (XSS protection) |
| `Secure` | `true` in production | HTTPS-only transport |
| `SameSite` | `Lax` | CSRF protection for cross-origin form posts |
| `Max-Age` | Configurable (default: 30 days) | Session lifetime |

The cookie name is implementation-defined (Express uses `connect.sid`, the Rust backend uses HMAC-signed session IDs). `auth.js` sends cookies via `credentials: 'include'` and does not read the cookie name.

### Session Storage

The session **must** be stored server-side. Signed cookie-based sessions (where the data is in the cookie itself) will not work because JWT token sets are typically 2-4KB, exceeding cookie size limits.

Suitable backends:
- **In-memory** (dev/testing only)
- **Redis** (production, non-serverless)
- **DynamoDB** (production, serverless/Lambda)
- **PostgreSQL** (production, if already in stack)
- **File-based** (single-server deployments)

## CSRF Protection

All state-changing endpoints (`POST`, `PUT`, `DELETE`) **must** require the custom header:

```
X-L42-CSRF: 1
```

`auth.js` adds this header automatically on all handler-mode requests. The CSRF check works because:
1. Cross-origin requests cannot set custom headers without a CORS preflight
2. The CORS policy restricts `Access-Control-Allow-Origin` to the frontend origin
3. Therefore, a forged cross-origin POST (e.g., from a malicious page) cannot include this header

If the header is missing or has the wrong value, return:

```json
HTTP 403
{
  "error": "CSRF validation failed",
  "message": "Missing X-L42-CSRF header"
}
```

## CORS Configuration

The backend **must** configure CORS to:
- Allow the frontend origin (`Access-Control-Allow-Origin: <frontend-url>`)
- Allow credentials (`Access-Control-Allow-Credentials: true`)
- Allow the `X-L42-CSRF` custom header (`Access-Control-Allow-Headers` must include it)
- Allow `Content-Type` header

Do **not** use `Access-Control-Allow-Origin: *` — this is incompatible with `credentials: true`.

## Endpoints

### GET /auth/token

Returns the current session's tokens to the browser. **Never includes the refresh token.**

**Called by**: `getTokens()` in `auth.js` (when cache is expired or empty)

**Request**: No body. Session cookie sent automatically.

**Success Response** (200):
```json
{
  "access_token": "<JWT>",
  "id_token": "<JWT>",
  "auth_method": "direct"
}
```

**Error Responses**:
- `401` — No session or no tokens in session:
  ```json
  { "error": "Not authenticated" }
  ```
- `401` — Tokens expired:
  ```json
  { "error": "Token expired" }
  ```

**Implementation Notes**:
- Check `id_token` expiry before returning (decode the JWT `exp` claim)
- Return `auth_method` so the client knows how the session was established

---

### POST /auth/session

Stores tokens from a direct login (passkey or password). When `loginWithPasskey()` or `loginWithPassword()` completes, the Cognito/WebAuthn flow returns tokens to JavaScript. This endpoint bridges those tokens into a server-side session.

**Called by**: `auth.js` automatically after `loginWithPasskey()` / `loginWithPassword()` succeed

**Request Headers**: `X-L42-CSRF: 1`, `Content-Type: application/json`

**Request Body**:
```json
{
  "access_token": "<JWT>",
  "id_token": "<JWT>",
  "refresh_token": "<JWT or null>",
  "auth_method": "passkey"
}
```

**Security Requirement**: The backend **must verify the `id_token` signature** before storing it. This prevents a same-origin XSS attacker from forging JWTs with arbitrary claims (e.g., admin groups) into the server session.

Verification steps:
1. Fetch the JWKS from `https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json`
2. Verify the JWT signature (RS256) against the JWKS
3. Validate the `iss` claim matches `https://cognito-idp.{region}.amazonaws.com/{userPoolId}`
4. Validate the `aud` claim matches the Cognito client ID
5. Validate the token is not expired (`exp` claim)

JWKS can (and should) be cached. Most JWT libraries handle caching automatically.

**Success Response** (200):
```json
{ "success": true }
```

**Error Responses**:
- `400` — Missing required fields:
  ```json
  { "error": "Missing access_token or id_token" }
  ```
- `403` — Token verification failed (bad signature, wrong issuer, expired):
  ```json
  { "error": "Token verification failed" }
  ```

---

### POST /auth/refresh

Uses the server-side refresh token to get new tokens from Cognito. The refresh token never leaves the server.

**Called by**: `refreshTokens()` in `auth.js`

**Request Headers**: `X-L42-CSRF: 1`

**Request Body**: Empty (or `{}`)

**Backend Logic**:
1. Read `refresh_token` from session
2. Call Cognito `InitiateAuth` with `REFRESH_TOKEN_AUTH` flow:
   ```
   POST https://cognito-idp.{region}.amazonaws.com/
   Content-Type: application/x-amz-json-1.1
   X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth

   {
     "AuthFlow": "REFRESH_TOKEN_AUTH",
     "ClientId": "<cognito-client-id>",
     "AuthParameters": {
       "REFRESH_TOKEN": "<refresh-token-from-session>"
     }
   }
   ```
3. Update session with new tokens (Cognito may or may not return a new refresh token)
4. Return new access + id tokens to browser

**Success Response** (200):
```json
{
  "access_token": "<new JWT>",
  "id_token": "<new JWT>",
  "auth_method": "direct"
}
```

**Error Responses**:
- `401` — No refresh token in session:
  ```json
  { "error": "No refresh token" }
  ```
- `401` — Cognito rejected the refresh (token revoked, expired, etc.):
  ```json
  { "error": "Refresh failed", "message": "<cognito error>" }
  ```
  On refresh failure, **destroy the session** — the user must re-authenticate.

---

### POST /auth/logout

Destroys the server session and clears the session cookie.

**Called by**: `logout()` in `auth.js`

**Request Headers**: `X-L42-CSRF: 1`

**Request Body**: Empty

**Success Response** (200):
```json
{ "success": true }
```

The response **must** also clear the session cookie (e.g., `Set-Cookie` with `Max-Age=0`).

---

### GET /auth/callback

Handles the OAuth redirect from Cognito's Hosted UI. Exchanges an authorization code for tokens and stores them server-side.

**Called by**: Browser redirect from Cognito (not directly by `auth.js`)

**Query Parameters**:
| Param | Description |
|---|---|
| `code` | OAuth authorization code |
| `state` | OAuth state parameter (for CSRF / redirect tracking) |
| `error` | Error code (if Cognito returns an error) |
| `error_description` | Human-readable error message |

**Backend Logic**:
1. If `error` is present, redirect to frontend login page with error
2. Exchange `code` for tokens via Cognito's token endpoint:
   ```
   POST https://{cognitoDomain}/oauth2/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &client_id=<cognito-client-id>
   &code=<authorization-code>
   &redirect_uri=<this-endpoint-url>
   &client_secret=<if-configured>
   ```
3. Store all tokens (including refresh token) in session with `auth_method: "oauth"`
4. Redirect to frontend success page: `{frontendUrl}/auth/success?state={state}`

**Error Handling**: Redirect to `{frontendUrl}/login?error={message}` on any failure.

**Note**: This endpoint does **not** require the CSRF header because it's a browser redirect from Cognito, not an XHR from `auth.js`. The OAuth `state` parameter provides CSRF protection for this flow.

---

### POST /auth/authorize — Cedar Authorization

Evaluates a Cedar authorization policy server-side. This is a core part of the architecture — client-side RBAC checks (like `isAdmin()`) are for UI display only, while `/auth/authorize` provides the actual authorization decision via declarative Cedar policies.

**Called by**: `requireServerAuthorization(action, options)` in `auth.js`

**Request Headers**: `X-L42-CSRF: 1`, `Content-Type: application/json`

**Request Body**:
```json
{
  "action": "admin:delete-user",
  "resource": {
    "id": "doc-123",
    "type": "document",
    "owner": "user-sub-uuid"
  },
  "context": {}
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `action` | string | Yes | The action to authorize (maps to `App::Action` entity) |
| `resource` | object | No | Resource descriptor. Defaults to `{ id: "_application", type: "application" }` |
| `resource.id` | string | No | Resource identifier |
| `resource.type` | string | No | Resource type label |
| `resource.owner` | string | No | Resource owner's `sub` (for ownership policies) |
| `context` | object | No | Additional Cedar context attributes |

**Success Response** (200 if authorized, 403 if denied):
```json
{
  "authorized": true,
  "reason": "policy0",
  "diagnostics": {}
}
```

**Error Responses**:
- `401` — Not authenticated or token expired
- `400` — Missing or invalid `action`
- `503` — Authorization engine not available (fail-closed):
  ```json
  { "error": "Authorization engine not available", "authorized": false }
  ```
- `500` — Policy evaluation error:
  ```json
  { "authorized": false, "error": "Authorization evaluation failed" }
  ```

**Security Invariant**: If the authorization engine is unavailable or errors, the response **must** deny access (fail-closed). Never default to `authorized: true`.

**Policy Engine**: The reference implementations use Cedar (`cedar-policy` crate for Rust, `@cedar-policy/cedar-wasm` for Node.js). The request/response contract is engine-agnostic, so backends could substitute OPA or Casbin, but Cedar is the tested and documented path. See `docs/cedar-integration.md` for schema and policy details.

---

### GET /auth/me

Returns user info from the session's ID token claims.

**Request**: Session cookie only.

**Success Response** (200):
```json
{
  "email": "user@example.com",
  "sub": "cognito-sub-uuid",
  "groups": ["admin", "developers"]
}
```

**Error Responses**:
- `401` — Not authenticated

---

### GET /health

Liveness check.

**Response** (200):
```json
{
  "status": "ok",
  "mode": "token-handler",
  "cedar": "ready | unavailable"
}
```

## Environment Variables

These are the standard configuration variables. Backends may accept them differently (env vars, config files, etc.) but the semantics should match:

| Variable | Required | Description |
|---|---|---|
| `COGNITO_CLIENT_ID` | Yes | Cognito app client ID |
| `COGNITO_CLIENT_SECRET` | No | Cognito app client secret (for confidential clients) |
| `COGNITO_USER_POOL_ID` | Yes | Cognito user pool ID (e.g., `us-west-2_abc123`) |
| `COGNITO_DOMAIN` | Yes | Cognito domain (e.g., `myapp.auth.us-west-2.amazoncognito.com`) |
| `COGNITO_REGION` | No | AWS region (default: `us-west-2`) |
| `SESSION_SECRET` | Yes | Secret for signing session cookies |
| `FRONTEND_URL` | Yes | Frontend origin for CORS and redirects |

## Security Invariants

These invariants **must** hold in any conforming implementation:

1. **Refresh tokens never leave the server.** The `/auth/token` endpoint returns only `access_token` and `id_token`.
2. **Session cookie is HttpOnly.** JavaScript cannot access the session identifier.
3. **CSRF header required on all POST endpoints** (except `/auth/callback` which uses OAuth state).
4. **JWKS verification on `/auth/session`.** Tokens received from the browser must have their signatures verified against Cognito's JWKS before being stored.
5. **Fail-closed authorization.** If `/auth/authorize` cannot evaluate a policy (engine down, error), it denies access.
6. **Session destroyed on refresh failure.** If Cognito rejects a refresh token, the session is invalidated.
7. **CORS restricted to frontend origin.** No wildcard origins when credentials are enabled.

## Reference Implementations

- **Rust** (Recommended): [`rust/`](../rust/) — native Cedar evaluation, 10–50 ms Lambda cold start
- **Express/Node.js**: `examples/backends/express/server.js` — Cedar via WASM
