# Design Decisions & Common Misconfigurations

A deep-dive into why `l42-cognito-passkey` works the way it does, what can go wrong when integrating it, and how to avoid the most common pitfalls. This document is organized by topic, with severity ratings for each issue.

**Intended audience**: Developers integrating `auth.js` into a project, or reviewing its security properties.

**Severity Legend**:
- **HIGH** — Can cause security vulnerabilities or hard-to-debug production failures
- **MEDIUM** — Will cause unexpected behavior in some configurations
- **LOW** — Edge cases or documentation-only concerns

---

## Table of Contents

1. [Token Storage Modes](#1-token-storage-modes)
2. [The `getTokens()` Polymorphism Problem](#2-the-gettokens-polymorphism-problem)
3. [Authentication State Checks](#3-authentication-state-checks)
4. [Cookie Handling](#4-cookie-handling)
5. [OAuth Flow & CSRF Protection](#5-oauth-flow--csrf-protection)
6. [WebAuthn / Passkey Defaults](#6-webauthn--passkey-defaults)
7. [Auto-Refresh & Session Lifecycle](#7-auto-refresh--session-lifecycle)
8. [fetchWithAuth & Retry Behavior](#8-fetchwithauth--retry-behavior)
9. [RBAC & Authorization](#9-rbac--authorization)
10. [Configuration Validation](#10-configuration-validation)
11. [JWT Handling](#11-jwt-handling)
12. [Scope Selection](#12-scope-selection)
13. [OCSF Security Logging](#13-ocsf-security-logging)
14. [Known Limitations](#14-known-limitations)

---

## 1. Token Storage Modes

### Design Decision

The library offers three storage modes, chosen at `configure()` time. **Handler mode is recommended for production.** The other modes are deprecated and will be removed in v1.0.

| Mode | Where tokens live | Persists across reloads? | XSS-accessible? | Requires backend? | Status |
|------|------------------|-------------------------|------------------|--------------------|--------|
| `handler` | Server-side HttpOnly cookies | Yes | No | Yes | **Recommended** |
| `localStorage` | `window.localStorage` | Yes | Yes | No | Deprecated |
| `memory` | JavaScript variable | No | Via `getTokens()` only | No | Deprecated |

**Why did localStorage/memory exist?** They were the original modes before the handler backend existed. A static site on Netlify without a backend required localStorage. Now that the Express backend is available and Cedar authorization requires server-side evaluation, handler mode is the standard deployment path. The deprecated modes remain for backwards compatibility and prototyping only.

### Common Misconfigurations

#### HIGH: Switching storage mode mid-session

```javascript
// WRONG — tokens from the old store are orphaned
configure({ tokenStorage: 'localStorage', ... });
// ... user logs in ...
configure({ tokenStorage: 'handler', ... });
// The localStorage tokens still exist but are now ignored
// isAuthenticated() returns false because the handler cache is empty
```

**Why it breaks**: `configure()` does not migrate tokens between stores. If you reconfigure at runtime, the old tokens remain in their original store, and the new store starts empty. The user appears logged out.

**Fix**: Only call `configure()` once, during page initialization. If you must switch modes, call `logout()` first.

#### MEDIUM: Assuming `memory` mode is immune to XSS

Memory mode keeps tokens out of `localStorage` and cookies, which protects against storage-scanning attacks. However, any XSS that can execute JavaScript can call `getTokens()` and read the tokens directly from the module's internal variable.

**What memory mode actually protects against**: Browser extensions that scan localStorage, other-tab attacks via storage events, and tokens surviving after the tab is closed.

#### LOW: Handler mode without understanding the cache

Handler mode fetches tokens from the server via HTTP and caches them for 30 seconds (configurable via `handlerCacheTtl`). During the cache gap (after TTL expires, before next fetch), `isAuthenticated()` may return `false` even though the user is authenticated server-side. See [Section 3](#3-authentication-state-checks) for details.

---

## 2. The `getTokens()` Polymorphism Problem

**Severity: HIGH**

This is the single most dangerous API in the library.

### The Problem

```javascript
// In localStorage or memory mode:
const tokens = getTokens();        // Returns { id_token, access_token, ... } or null
console.log(tokens.access_token);  // Works fine

// In handler mode:
const tokens = getTokens();        // Returns a Promise!
console.log(tokens.access_token);  // undefined — tokens is a Promise object
if (tokens) { /* always true */ }  // A Promise is always truthy
```

`getTokens()` returns a synchronous object in `localStorage`/`memory` modes but a `Promise` in `handler` mode. The function signature is `@returns {Object|null|Promise<Object|null>}`.

### Why This Exists

The storage abstraction calls the underlying store's `.get()` method. `localStorage.getItem()` is synchronous, but fetching from a server endpoint is inherently async. Rather than making all modes async (which would break the ergonomics of the simple case), the library preserves the sync behavior for the common case.

### Safe Patterns

```javascript
// SAFE — await works on non-Promises (returns the value unchanged)
const tokens = await getTokens();

// SAFE — check auth state first (always sync)
if (isAuthenticated()) {
    const tokens = await getTokens();
}
```

### Unsafe Patterns

```javascript
// UNSAFE — will silently get a truthy Promise in handler mode
const tokens = getTokens();
if (tokens) { doSomething(tokens.access_token); }

// UNSAFE — destructuring a Promise gives undefined
const { access_token } = getTokens();
```

### Migration Advice

If you are switching from `localStorage` to `handler` mode, search your codebase for every call to `getTokens()` and add `await`. The `await` keyword is harmless on non-Promises, so `await getTokens()` works correctly in all modes.

---

## 3. Authentication State Checks

### `isAuthenticated()` vs `isAuthenticatedAsync()`

| Function | Return | Handler mode behavior | When to use |
|----------|--------|-----------------------|-------------|
| `isAuthenticated()` | `boolean` (sync) | Uses cached tokens (may be stale) | UI rendering, route guards |
| `isAuthenticatedAsync()` | `Promise<boolean>` | Fetches fresh tokens from server | Before sensitive operations |

### MEDIUM: The Cache Gap in Handler Mode

In handler mode, `isAuthenticated()` uses a 30-second cache. When the cache expires:

1. `isAuthenticated()` returns `false` (cache is empty)
2. The next `getTokens()` call fetches fresh tokens from the server
3. After the fetch, `isAuthenticated()` returns `true` again

This creates a brief window where a truly authenticated user appears unauthenticated.

**Symptoms**: Login screen flickers momentarily, conditional UI based on `isAuthenticated()` toggles unexpectedly.

**Fix**: For handler mode, use `isAuthenticatedAsync()` when the result matters (e.g., before an API call). Use `isAuthenticated()` only for initial UI rendering where a brief loading state is acceptable.

```javascript
// Handler mode: use async check for important decisions
const authed = await isAuthenticatedAsync();
if (!authed) {
    redirectToLogin();
}
```

---

## 4. Cookie Handling

### Design Decision: Non-HttpOnly Cookie

The library sets an `l42_id_token` cookie containing the full JWT ID token. This cookie is intentionally **not HttpOnly** because it is set via `document.cookie` (client-side JavaScript cannot set HttpOnly flags — only server `Set-Cookie` headers can).

**Why a cookie at all?** The cookie enables server-side validation without an API call. For example, a Lambda@Edge function can read the cookie to gate access to protected CloudFront distributions.

**Trade-offs**:
- The full JWT (potentially 2-4 KB) is sent with every HTTP request to the matching domain
- Any XSS can read the cookie contents
- The Secure flag ensures it's only sent over HTTPS
- SameSite=Lax prevents CSRF via cross-site form submissions

### HIGH: Cookie Size Limits

Cognito ID tokens with many groups/custom claims can exceed 4096 bytes — the per-cookie limit in most browsers. When this happens, `document.cookie` **silently fails** to set the cookie. There is no error thrown.

**Symptoms**: Server-side validation works in development (small tokens) but fails in production (users with many groups).

**Workaround**: If your Cognito users are in many groups, use handler mode instead (server sets a compact session cookie).

### Cookie Domain Auto-Detection

The library handles country-code TLDs (ccTLDs) with a public suffix list:

```
app.example.com     → .example.com      (standard 2-part TLD)
app.example.co.uk   → .example.co.uk    (3-part public suffix)
localhost            → null              (no domain set)
192.168.1.1          → null              (IP addresses)
```

### MEDIUM: Missing Public Suffix

The `PUBLIC_SUFFIXES` list contains 30+ entries but is not exhaustive. If your domain uses a public suffix not in the list (e.g., `.nom.br`, `.co.id`), the library will compute the wrong cookie domain:

```
app.example.co.id → .example.co.id  (CORRECT if co.id were in the list)
app.example.co.id → .co.id          (WRONG — library treats co.id as the registrable domain)
```

**Fix**: Set `cookieDomain` explicitly in your configuration:

```javascript
configure({
    cookieDomain: '.example.co.id',
    // ...
});
```

---

## 5. OAuth Flow & CSRF Protection

### State Parameter

The library generates a random state parameter for every OAuth redirect and stores it in `localStorage`. On callback, it compares the returned state with the stored value.

### MEDIUM: State Is Consumed on Check

```javascript
// Simplified from auth.js
function verifyOAuthState(state) {
    const stored = localStorage.getItem(config.stateKey);
    localStorage.removeItem(config.stateKey);  // Always removes, even if no match
    return stored && stored === state;
}
```

The state is deleted from localStorage **regardless of whether it matches**. This means:

1. If an attacker sends a forged redirect with a bad state, the real state is destroyed
2. The user's legitimate OAuth callback will then also fail (state is gone)
3. This is a denial-of-service vector against the OAuth flow (the user must start login again)

### PKCE Storage

The PKCE code verifier is stored in `localStorage` under the key `l42_pkce_verifier`. This is a well-known, predictable key. In an XSS scenario, an attacker could read the verifier and complete the OAuth flow themselves. However, PKCE alone is not the security boundary — the state parameter must also match.

### Auto-Configuration from `window.L42_AUTH_CONFIG`

If `configure()` has not been called, the library reads from `window.L42_AUTH_CONFIG` on first use:

```html
<script>
window.L42_AUTH_CONFIG = {
    clientId: 'abc123',
    domain: 'myapp.auth.us-west-2.amazoncognito.com'
};
</script>
```

### LOW: Window Config Hijacking

Any script on the page can set `window.L42_AUTH_CONFIG` before the auth library initializes. If a third-party script (analytics, ads) sets this property, it could redirect authentication to an attacker-controlled domain.

**Fix**: Call `configure()` explicitly as early as possible, rather than relying on `window.L42_AUTH_CONFIG`. Once `configure()` has been called, the auto-configuration is skipped.

---

## 6. WebAuthn / Passkey Defaults

### Registration Defaults

When Cognito does not specify `authenticatorSelection` in its credential creation options, the library applies these defaults:

```javascript
authenticatorSelection: {
    authenticatorAttachment: 'platform',      // Only built-in authenticators
    residentKey: 'preferred',                 // Discoverable if possible
    userVerification: 'preferred'             // Biometric/PIN if available
}
```

### MEDIUM: `authenticatorAttachment: 'platform'` Blocks Cross-Device Auth

The `'platform'` setting restricts credential creation to the device's built-in authenticator (Touch ID, Windows Hello, etc.). This prevents:

- Using a USB security key (YubiKey, etc.)
- Cross-device (hybrid) authentication via QR code + Bluetooth
- Using a phone as an authenticator for a desktop browser

**When this matters**: If your users need to sign in from devices without built-in biometrics, or if you want to support security keys for compliance (e.g., FIPS 140-2).

**Override**: Pass `authenticatorSelection` from your Cognito User Pool configuration (set via boto3 or the AWS Console).

### MEDIUM: `residentKey: 'preferred'` May Create Non-Discoverable Credentials

With `'preferred'`, some authenticators will create server-side credentials (non-discoverable) that work for 2FA but do **not** appear in passkey autofill (Conditional UI). For a true "passwordless passkey" experience, use `'required'`.

### About `userVerification: 'preferred'`

The `'preferred'` setting leads to inconsistent behavior across platforms:

| Platform | `'preferred'` behavior |
|----------|----------------------|
| macOS (Touch ID) | Always prompts for biometric |
| Windows (Hello) | Prompts for PIN or biometric |
| Security keys | May prompt for PIN (unexpected for 2FA scenarios) |

**Recommendation**: Use `'required'` for passwordless flows (passkey is sole factor) or `'discouraged'` for 2FA flows (passkey is second factor after password). The `'preferred'` default tries to be a compromise but satisfies neither case perfectly.

---

## 7. Auto-Refresh & Session Lifecycle

### How Auto-Refresh Works

1. On login, `startAutoRefresh()` is called automatically
2. A `setInterval` checks token expiry every 60 seconds (configurable)
3. When the tab is hidden (Page Visibility API), the interval is paused
4. When the tab becomes visible, an immediate check runs
5. If `shouldRefreshToken()` returns true (token nearing expiry), a proactive refresh happens

### Refresh Timing by Auth Method

| Auth method | Refresh before expiry | Cookie max-age |
|-------------|----------------------|----------------|
| `password` | 5 minutes | 1 day |
| `passkey` | 1 hour | 30 days |

**Why the difference?** Passkey sessions are longer-lived (30-day cookies) because the user proved possession of a hardware credential. The longer refresh-before window (1 hour) accounts for users who may leave a tab open for extended periods.

### MEDIUM: `onSessionExpired` Not Firing in All Cases

The `onSessionExpired` callback fires when:
- Token is expired AND refresh fails
- Server returns 401 and refresh fails (handler mode)

It does **not** fire when:
- The user manually clears browser storage
- A different tab calls `logout()`
- The cache TTL expires in handler mode (this is a stale cache, not an expired session)

If you need to detect storage clearing, use the `storage` event listener on `window` to detect when `l42_auth_tokens` is removed by another tab.

### LOW: Visibility Handler Accumulation

If `startAutoRefresh()` is called multiple times without `stopAutoRefresh()`, the previous timer is cleaned up but the visibility event listener is also properly removed (the function calls `stopAutoRefresh()` first). This is correctly handled — mentioning it here because it's a common concern.

---

## 8. `fetchWithAuth` & Retry Behavior

### How It Works

```
1. Get valid tokens (refresh if needed)
2. Make fetch request with Bearer token
3. If 401 response:
   a. Try to refresh tokens
   b. Retry the ENTIRE request with fresh tokens
   c. If refresh fails: clear tokens, fire onSessionExpired, throw
4. Return response
```

### HIGH: Automatic Retry of Non-Idempotent Requests

`fetchWithAuth` retries the full request on 401, including POST/PUT/DELETE bodies. This can cause:

```javascript
// This POST may execute TWICE if the first attempt gets a 401
const res = await fetchWithAuth('/api/orders', {
    method: 'POST',
    body: JSON.stringify({ item: 'widget', qty: 1 })
});
```

**Scenarios where this is dangerous**:
- Payment processing (double charge)
- Order creation (duplicate order)
- Email sending (duplicate email)

**Workaround**: For non-idempotent endpoints, refresh tokens proactively before the request:

```javascript
// SAFE for non-idempotent requests
await ensureValidTokens();
const tokens = await getTokens();
const res = await fetch('/api/orders', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${tokens.access_token}` },
    body: JSON.stringify(order)
});
// Handle 401 yourself (no automatic retry)
```

Or design your API with idempotency keys:

```javascript
const idempotencyKey = crypto.randomUUID();
const res = await fetchWithAuth('/api/orders', {
    method: 'POST',
    headers: { 'X-Idempotency-Key': idempotencyKey },
    body: JSON.stringify(order)
});
```

---

## 9. RBAC & Authorization

### The Most Important Rule

**Client-side RBAC is for UI only.** Every authorization decision must be validated on the server.

```javascript
// This only hides the button — it does NOT prevent the action
if (isAdmin()) {
    showDeleteButton();
}

// The server must independently verify the user's groups
// by validating the JWT access token
```

### `isAdmin()` and `isReadonly()` Mutual Exclusion

These two functions are mutually exclusive by design:

```javascript
function isReadonly(groups) {
    const hasReadonly = /* check readonly/read-only/viewer groups */;
    const hasAdmin = /* check admin/admins/administrators groups */;
    return hasReadonly && !hasAdmin;  // Admin overrides readonly
}
```

A user who is in both `admin` and `readonly` groups will have `isAdmin() === true` and `isReadonly() === false`. Admin always wins.

### `UI_ONLY_hasRole()` Normalization

The `UI_ONLY_hasRole()` function normalizes role names by removing trailing `s`:

```javascript
'admins'  → matches 'admin'
'editors' → matches 'editor'
```

**Caveat**: This naive depluralization breaks for words like `'analysis'` (becomes `'analysi'`) or `'status'` (becomes `'statu'`). Use exact role names when possible.

### `requireServerAuthorization()` Pattern

```javascript
const result = await requireServerAuthorization('admin:delete-user', {
    endpoint: '/api/authorize',  // Default
    context: { targetUserId: '123' }
});

if (!result.authorized) {
    showError(result.reason);
    return;
}
```

This sends a POST to your authorization endpoint with the action and context. Your server should validate the JWT, check the user's groups, and return `{ authorized: true/false, reason?: string }`.

---

## 10. Configuration Validation

### What `configure()` Validates

| Field | Validation | Error if invalid |
|-------|-----------|------------------|
| `clientId` | Non-empty string | `"requires clientId: must be a non-empty string"` |
| `cognitoDomain` | Matches `*.auth.*.amazoncognito.com` OR valid domain format | `"Invalid cognitoDomain format"` |
| `cognitoRegion` | Non-empty string | `"Invalid cognitoRegion"` |
| `tokenKey` | Non-empty string | `"Invalid tokenKey"` |
| `tokenStorage` | One of: `localStorage`, `memory`, `handler` | `"Invalid tokenStorage"` |
| Handler endpoints | All three required when `tokenStorage: 'handler'` | Lists missing endpoints |
| `redirectUri` | Valid URL, HTTPS for non-localhost | `"HTTPS is required for non-localhost URLs"` |
| `redirectUri` domain | Must match `allowedDomains` or current domain | `"Redirect URI domain not allowed"` |

### MEDIUM: `cognitoDomain` Custom Domain Validation Is Permissive

The regex for custom domains (`/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/`) accepts any domain-shaped string. It prevents protocol injection (`://`) and double dots (`..`), but does not restrict to a whitelist.

**Risk scenario**: If an attacker can control the configuration (e.g., XSS modifying `window.L42_AUTH_CONFIG`), they could redirect all auth traffic to a domain they control.

**Mitigation**: Call `configure()` explicitly with hardcoded values rather than reading from DOM or URL parameters.

### LOW: `redirectUri` Validation Requires Absolute URL

The `redirectUri` must be a full URL (including protocol), not a relative path:

```javascript
// WRONG — will fail URL parsing
configure({ redirectUri: '/callback', ... });

// CORRECT
configure({ redirectUri: 'https://myapp.com/callback', ... });

// CORRECT for development
configure({ redirectUri: 'http://localhost:3000/callback', ... });
```

---

## 11. JWT Handling

### `UNSAFE_decodeJwtPayload()`

The `UNSAFE_` prefix is intentional — it signals that this function does **not verify the JWT signature**. The decoded claims are only suitable for display purposes:

```javascript
// SAFE — display only
const claims = UNSAFE_decodeJwtPayload(tokens.id_token);
userDisplay.textContent = claims.email;

// UNSAFE — authorization based on unverified claims
if (UNSAFE_decodeJwtPayload(tokens.id_token).groups.includes('admin')) {
    deleteUser(id);  // NEVER DO THIS
}
```

### What Can Go Wrong

| Input | Behavior |
|-------|----------|
| Valid JWT | Returns parsed payload object |
| `null` / `undefined` | Throws `TypeError` (caught by callers) |
| String without `.` | Throws (no second segment) |
| Valid structure, invalid base64 | Throws from `atob()` |
| Valid base64, invalid JSON | Throws from `JSON.parse()` |

All internal callers wrap this in try/catch, so these errors are handled. If you call it directly, wrap it too.

---

## 12. Scope Selection

### Default Scopes

```javascript
scopes: 'openid email profile aws.cognito.signin.user.admin'
```

### MEDIUM: `aws.cognito.signin.user.admin` Included by Default

This scope grants the client access to Cognito User Pool admin APIs, including:

- `GetUser` — read user attributes
- `UpdateUserAttributes` — modify user attributes
- `ChangePassword` — change password
- `SetUserMFAPreference` — modify MFA settings
- `ListWebAuthnCredentials` — list passkeys
- `StartWebAuthnRegistration` / `CompleteWebAuthnRegistration` — register passkeys
- `DeleteWebAuthnCredential` — delete passkeys

**Why it's the default**: Passkey management (register, list, delete) requires this scope. Without it, `registerPasskey()`, `listPasskeys()`, and `deletePasskey()` will fail.

**When to remove it**: If your application does not use passkeys and does not need to call any Cognito admin APIs, you can reduce the attack surface:

```javascript
configure({
    scopes: 'openid email profile',
    // ...
});
```

**Trade-off**: Removing this scope means `hasAdminScope()` will return false, and all passkey management functions will throw.

---

## 13. OCSF Security Logging

### Configuration

```javascript
configure({
    securityLogger: 'console',        // Logs to console
    // OR
    securityLogger: (event) => {      // Custom handler
        sendToSIEM(event);
    },
    // OR
    securityLogger: null              // Disabled (default)
});
```

### Events Logged

| Event | OCSF Class | When |
|-------|-----------|------|
| Login success | Authentication (3001) | After password or passkey login |
| Login failure | Authentication (3001) | On authentication error |
| Logout | Authentication (3001) | When `logout()` is called |
| Passkey registered | Account Change (3002) | After `registerPasskey()` |
| Passkey deleted | Account Change (3002) | After `deletePasskey()` |

### LOW: Logger Errors Are Silently Caught

If your custom `securityLogger` function throws, the error is caught and logged to `console.error`. The auth flow continues uninterrupted. This is intentional — a logging failure should never break authentication.

---

## 14. Known Limitations

### Client-Side Rate Limiting (v0.12.1+)

`loginWithPassword()`, `loginWithPasskey()`, and `loginWithConditionalUI()` (Mode A) include client-side exponential backoff throttling. After `maxLoginAttemptsBeforeDelay` (default: 3) failures per email, subsequent attempts are delayed with exponential backoff up to `loginBackoffMaxMs` (default: 30s). This is in-memory only and resets on page reload. Cognito also enforces server-side rate limiting.

### Token Validation on Load (v0.12.0+)

When tokens are loaded, `validateTokenClaims()` checks:

- `iss` (issuer) matches the configured Cognito domain
- `aud` / `client_id` matches the configured client ID
- `exp` is not expired

Tokens that fail validation are rejected by `isAuthenticated()`. Note that this is still client-side validation without signature verification — the `UNSAFE_` naming convention signals this. Server-side verification remains authoritative.

### `setTokens()` Is Publicly Exported

Any JavaScript on the page can call `setTokens()` with arbitrary token data. This is necessary for the OAuth callback flow but means XSS can inject forged tokens. The forged tokens will pass `isAuthenticated()` and `isAdmin()` checks (which read unverified claims).

**Mitigation**: In handler mode, `setTokens()` only updates the local cache — the server maintains the authoritative session state.

### Conditional UI and AbortController (v0.12.0+)

`loginWithConditionalUI()` supports passkey autofill with two modes:
- **Mode A** (email-scoped): User types email, then selects passkey from autofill
- **Mode B** (discovery): Browser shows available passkeys without email input

The library manages `_conditionalAbortController` internally — starting a new login or calling `logout()` automatically aborts any in-flight conditional UI ceremony.

---

## Cross-Reference

| Topic | See also |
|-------|---------|
| API function signatures | [docs/api-reference.md](api-reference.md) |
| Handler mode architecture | [docs/handler-mode.md](handler-mode.md) |
| Threat models & CSP | [docs/security-hardening.md](security-hardening.md) |
| Version upgrade notes | [docs/migration.md](migration.md) |
| OCSF event format | [docs/ocsf-logging.md](ocsf-logging.md) |
| Cognito Pool setup | [docs/cognito-setup.md](cognito-setup.md) |
