# Migration Guide

Complete migration guide for l42-cognito-passkey version upgrades.

## Version Summary

| From | To | Key Changes |
|------|-----|-------------|
| v0.3.x | v0.4.0 | `UNSAFE_` prefix for JWT decode, RBAC helpers |
| v0.4.x | v0.5.2 | PKCE, HTTPS enforcement, async `loginWithHostedUI()` |
| v0.5.2 | v0.5.3 | localStorage for OAuth state (Safari/Firefox fix) |
| v0.5.3 | v0.5.4+ | Dist file sync fix, CI safeguards |
| v0.5.6 | v0.5.7 | `onAuthStateChange` no longer fires on token refresh |
| v0.5.7 | v0.6.0 | New `onLogin()` and `onLogout()` event handlers |
| v0.6.0 | v0.7.0 | Memory mode token storage |
| v0.7.0 | v0.8.0 | Token Handler mode (server-side token storage) |
| v0.8.0/v0.9.0 | v0.10.0 | Removed speculative features, trimmed export surface |
| v0.10.0 | v0.11.0 | Debug logging & diagnostics mode |
| v0.11.0 | v0.12.0 | Conditional UI, passkey upgrade, token validation, WebAuthn capabilities |
| v0.12.0 | v0.12.1 | Client-side login rate limiting |
| v0.12.1 | v0.12.2 | Tree-shaking support |
| v0.12.2 | v0.13.0 | Cedar policy authorization (server-side) |

---

## v0.12.2 → v0.13.0 (Cedar Authorization)

### New: Server-Side Cedar Policy Engine

Cedar replaces hardcoded RBAC checks on the server with declarative policy evaluation. This is a **server-side feature** that pairs with Token Handler mode. The client-side API (`requireServerAuthorization()`) is unchanged.

**New server components:**
- `cedar-engine.js` — Cedar WASM wrapper for Express backends
- 9 Cedar policy files covering all RBAC roles
- Cedar JSON schema mapping Cognito groups to Cedar entity types

**Improved `requireServerAuthorization()`:**
- Now supports handler mode (sends session cookies + CSRF header)
- Accepts `resource` parameter for ownership enforcement
- Default endpoint changed from `/api/authorize` to `/auth/authorize`

**No action required if:**
- You only use client-side auth functions
- You don't have a Token Handler backend yet

See [cedar-integration.md](./cedar-integration.md) for the complete setup guide.

---

## v0.12.0 → v0.12.2 (Incremental)

### v0.12.2 — Tree-Shaking + Cedar Plan

No breaking changes. Added ES module tree-shaking support and documented Cedar authorization integration plan.

### v0.12.1 — Client-Side Login Rate Limiting

No breaking changes. New functions for login throttling:

- `checkLoginRateLimit(email)` — applies exponential backoff delay
- `recordLoginFailure(email)` — tracks per-email attempt count
- `resetLoginAttempts(email)` — clears on successful login
- `getLoginAttemptInfo(email)` — returns `{ attemptsRemaining, nextRetryMs, isThrottled }`

Rate limiting is automatically integrated into `loginWithPassword()`, `loginWithPasskey()`, and `loginWithConditionalUI()` (Mode A).

---

## v0.11.0 → v0.12.0 (Conditional UI + Token Validation)

### New Features

**Conditional UI (passkey autofill):**

```javascript
// Mode A: email-scoped
await loginWithConditionalUI({ mode: 'email', email: 'user@example.com' });

// Mode B: discovery (browser picks passkey)
await loginWithConditionalUI({ mode: 'discovery' });
```

**Passkey upgrade after password login:**

```javascript
await upgradeToPasskey({ silent: true });
```

**Token validation on load** — `isAuthenticated()` now validates `iss`, `aud`/`client_id`, and `exp` claims.

**WebAuthn Level 3 capabilities:**

```javascript
const caps = await getPasskeyCapabilities();
// { platformAuthenticator, conditionalMediation, userVerification, ... }
```

### No Action Required If...

- You only use core auth functions — all new features are additive
- `isAuthenticated()` now rejects tokens with wrong issuer/audience (this is more secure, not less)

---

## v0.10.0 → v0.11.0 (Debug Diagnostics)

### New Debug Mode

No breaking changes. Enable with:

```javascript
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx',
    debug: true  // or 'verbose' or function(event)
});

console.table(getDiagnostics());    // Auth state snapshot
console.log(getDebugHistory());      // Last 100 events
clearDebugHistory();                 // Clear buffer
```

---

## v0.9.0 → v0.10.0 (Cleanup)

### Removed Exports

These functions no longer exist. Update your code:

| Removed | Replacement |
|---------|-------------|
| `getTokensAsync()` | `await getTokens()` (works in all modes) |
| `decodeJwtPayload(token)` | `UNSAFE_decodeJwtPayload(token)` |
| `parseJwt(token)` | `UNSAFE_decodeJwtPayload(token)` |
| `createAuthenticatedWebSocket()` | Use `ensureValidTokens()` + manual WebSocket setup |

**Search your codebase:**
```bash
grep -r "getTokensAsync\|decodeJwtPayload\|parseJwt\|createAuthenticatedWebSocket" src/
```

### Removed RBAC Roles

If you imported specific roles from `rbac-roles.js`, the following were removed from `STANDARD_ROLES`:
- Healthcare: `patient`, `nurse`, `doctor`
- Education: `student`, `ta`, `teacher`
- SaaS: `freeTier`, `proTier`, `enterpriseTier`
- API: `apiReader`, `apiWriter`
- Organization: `teamMember`, `teamLead`, `orgAdmin`
- E-commerce: `customer`, `vipCustomer`
- Other: `supportAgent`, `analyst`, `auditor`, `serviceAccount`, `billingAdmin`

**Still available:** `admin`, `readonly`, `user`, `editor`, `reviewer`, `publisher`, `moderator`, `developer`.

Also removed: `CONTENTFUL_ROLE_MAPPING`, `SITE_PATTERNS.healthcare`, `SITE_PATTERNS.education`, `SITE_PATTERNS.saas`.

If you need domain-specific roles, define them in your own project instead of relying on the library's built-in definitions.

### No Action Required If...

- You only use core auth functions (`isAuthenticated`, `getTokens`, `loginWith*`, `logout`)
- You only use core RBAC checks (`isAdmin`, `isReadonly`, `isInCognitoGroup`)
- You weren't using WebSocket auth

---

## v0.7.0 → v0.8.0 (Token Handler Mode)

### New Token Handler Mode

v0.8.0 introduces Token Handler mode, the most secure token storage option. Tokens are stored server-side in HttpOnly session cookies, making them inaccessible to XSS attacks.

**No changes required for existing users.** Token Handler mode is opt-in.

### To Enable Token Handler Mode

1. **Deploy a backend** that implements the Token Handler endpoints (see `examples/backends/express/`)

2. **Update configuration:**

```javascript
import { configure } from './auth.js';

configure({
    clientId: 'your-client-id',
    cognitoDomain: 'your-app.auth.us-west-2.amazoncognito.com',

    // Enable handler mode
    tokenStorage: 'handler',

    // Required endpoints
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',

    // Optional: Backend OAuth callback
    oauthCallbackUrl: '/auth/callback'
});
```

3. **Update code to use `await` with `getTokens()`** (recommended):

```javascript
// Before (still works in localStorage/memory modes)
const tokens = getTokens();

// After (works in ALL modes, required for handler mode)
const tokens = await getTokens();
```

### New Functions

| Function | Description |
|----------|-------------|
| `isAuthenticatedAsync()` | Async auth check (fetches from server if cache stale) |

### Behavioral Changes

| Function | localStorage/memory | handler |
|----------|-------------------|---------|
| `getTokens()` | Sync (returns value) | **Async (returns Promise)** |
| `isAuthenticated()` | Sync | Sync (uses cache) |
| `logout()` | Sync | **Async (calls server)** |
| `refreshTokens()` | Calls Cognito | **Calls backend endpoint** |

**Note:** JavaScript allows `await` on non-Promises, so `await getTokens()` works in all modes.

### Configuration Validation

Handler mode requires all endpoints:

```javascript
// This will throw an error
configure({
    tokenStorage: 'handler'
    // Missing: tokenEndpoint, refreshEndpoint, logoutEndpoint
});
// Error: Token handler mode requires: tokenEndpoint, refreshEndpoint, logoutEndpoint
```

### Security Benefits

| Threat | localStorage | handler |
|--------|-------------|---------|
| XSS stealing tokens | Vulnerable | Protected |
| Refresh token exposure | Client-side | Server-only |
| Token persistence | In browser | HttpOnly session |

See [handler-mode.md](./handler-mode.md) for complete documentation.

---

## v0.5.7 → v0.6.0

### New onLogin and onLogout Event Handlers

v0.6.0 adds explicit event handlers for login and logout, providing clearer semantics than `onAuthStateChange`:

```javascript
import { onLogin, onLogout } from '/auth/auth.js';

// Called on actual login (never on token refresh)
onLogin((tokens, method) => {
    console.log('User logged in via:', method); // 'password', 'passkey', 'oauth'
    window.location.href = '/dashboard';
});

// Called on logout
onLogout(() => {
    showLoginScreen();
});
```

**Benefits:**
- `onLogin` only fires on actual login, never on token refresh
- Callback receives auth method ('password', 'passkey', 'oauth')
- No need to understand `onAuthStateChange` nuances

**Breaking Change:** `exchangeCodeForTokens()` now sets `auth_method: 'oauth'` instead of 'passkey'. This only affects code that checks `getAuthMethod()` after OAuth login.

---

## v0.5.6 → v0.5.7

### onAuthStateChange No Longer Fires on Token Refresh

Previously, `onAuthStateChange` would fire with `true` whenever tokens were refreshed. This caused issues:

```javascript
// BEFORE v0.5.7: This would cause infinite reload loops!
onAuthStateChange((authenticated) => {
    if (authenticated) {
        window.location.reload(); // Token refresh triggers this → loop!
    }
});
```

**v0.5.7 Fix**: `onAuthStateChange` now only fires on:
- New login (password, passkey, OAuth callback)
- Logout

It does **not** fire during token refresh.

**Best Practice**: Use `onAuthStateChange` for logout detection, and handle login success via the Promise return value:

```javascript
// For logout detection
onAuthStateChange((authenticated) => {
    if (!authenticated) {
        showLoginRequired();
    }
});

// For login success - use the Promise
try {
    await loginWithPasskey(email);
    window.location.reload(); // Direct handling
} catch (error) {
    showError(error.message);
}
```

---

## v0.4.x → v0.5.2+ (Security Release)

### loginWithHostedUI() is Now Async

The function now generates a PKCE code challenge before redirecting:

```javascript
// Before (still works - redirect happens before promise resolves)
loginWithHostedUI(email);

// After (recommended for clarity)
await loginWithHostedUI(email);
```

Since the redirect happens immediately, existing synchronous calls will continue to work, but TypeScript/ESLint may flag the unhandled promise.

### New Validations

These may break existing configs if they were misconfigured:

1. **`redirectUri` must use HTTPS** (except localhost for development)
2. **`cognitoDomain` format is validated** to prevent open redirects

```javascript
// Valid
configure({
    redirectUri: 'https://app.example.com/callback',  // HTTPS required
    cognitoDomain: 'myapp.auth.us-west-2.amazoncognito.com'  // Valid format
});

// Invalid - will throw
configure({
    redirectUri: 'http://app.example.com/callback',  // HTTP not allowed
    cognitoDomain: 'https://evil.com'  // Invalid format
});
```

### No Action Required

The following changes are transparent:
- **PKCE** is automatically handled
- **OAuth state** now uses localStorage (fixes Safari ITP / Firefox ETP issues)
- **dist/auth.js** is kept in sync via pre-commit hook

---

## v0.3.x → v0.4.0

### decodeJwtPayload() Renamed

The function has been renamed to `UNSAFE_decodeJwtPayload()` to clearly indicate that it returns **unverified claims**.

```javascript
// Before (still works, emits deprecation warning)
const claims = auth.decodeJwtPayload(token);

// After (recommended)
const claims = auth.UNSAFE_decodeJwtPayload(token);
```

**Why?** This prevents developers from accidentally using JWT claims for authorization decisions. The `UNSAFE_` prefix reminds you that these claims are for display purposes only.

**Search patterns to find usage:**
```bash
grep -r "decodeJwtPayload(" src/
grep -r "parseJwt(" src/
```

### New RBAC Helpers

If using `rbac-roles.js`, update group checks:

```javascript
// Before (fragile - breaks if Cognito group is named 'admins')
if (groups.includes('admin') || groups.includes('admins')) { ... }

// After (handles all aliases)
import { isInCognitoGroup } from './rbac-roles.js';
if (isInCognitoGroup(groups, 'ADMIN')) { ... }
```

### New Security Functions

**Server-Side Authorization Helper:**

```javascript
// For protected actions, enforce server validation
const result = await auth.requireServerAuthorization('admin:delete-user', {
    endpoint: '/api/authorize',
    context: { resourceId: '123' }
});
if (!result.authorized) {
    throw new Error(result.reason);
}
```

**UI-Only Role Check:**

```javascript
// For showing/hiding UI elements (NOT authorization)
if (auth.UI_ONLY_hasRole('admin')) {
    showAdminButton();  // UI only, not security!
}
```

### ccTLD Cookie Fix

Cookies now work correctly for country-code TLDs:
- `.co.uk`, `.com.au`, etc. are properly handled
- No action needed unless you had a workaround

---

## Verification Steps

After upgrading:

1. **Check version:**
   ```javascript
   console.log(auth.VERSION);  // Should show current version
   ```

2. **Test login flow** works end-to-end

3. **Check browser console** for deprecation warnings

4. **Run tests** if you have integration tests:
   ```bash
   pnpm test
   ```

---

## Upgrade Prompt for Claude Code Instances

For a quick upgrade prompt to paste into another Claude Code instance, see [upgrade-prompt.md](./upgrade-prompt.md).
