# API Reference

Complete API documentation for L42 Cognito Passkey (0.19.0).

## Configuration

### configure(options)

Configure the auth module. Must be called before using other functions (unless using `window.L42_AUTH_CONFIG`).

```javascript
configure({
    // Required
    clientId: 'your-client-id',
    cognitoDomain: 'app.auth.us-west-2.amazoncognito.com',

    // Handler endpoints (required)
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    sessionEndpoint: '/auth/session',

    // Optional endpoints
    oauthCallbackUrl: '/auth/callback',
    validateCredentialEndpoint: '/auth/validate-credential',

    // Optional
    cognitoRegion: 'us-west-2',            // default: 'us-west-2'
    redirectUri: '/callback',               // default: origin + '/callback'
    scopes: 'openid email profile aws.cognito.signin.user.admin',
    handlerCacheTtl: 30000,                 // Cache TTL in ms (default: 30000)
    relyingPartyId: 'yourdomain.com',       // WebAuthn relying party
    allowedDomains: ['myapp.com'],          // auto-allows current domain if not set
    autoUpgradeToPasskey: false,            // conditional create after password login

    // Rate limiting
    maxLoginAttemptsBeforeDelay: 3,
    loginBackoffBaseMs: 1000,
    loginBackoffMaxMs: 30000,

    // Logging
    securityLogger: null,                   // 'console', function(event), or null
    debug: false,                           // true, 'verbose', or function(event)
});
```

### window.L42_AUTH_CONFIG

Alternative to `configure()`. Set before importing auth.js:

```html
<script>
window.L42_AUTH_CONFIG = {
    clientId: 'your-client-id',
    domain: 'app.auth.us-west-2.amazoncognito.com',
    region: 'us-west-2',
    redirectUri: window.location.origin + '/callback',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    sessionEndpoint: '/auth/session'
};
</script>
<script type="module">
import { isAuthenticated } from '/auth/auth.js';
</script>
```

### isConfigured()

Returns `boolean` — whether `configure()` has been called.

### VERSION

Library version string (`'0.19.0'`).

## Authentication State

### isAuthenticated()

Synchronous check using cached tokens. Validates token claims (issuer, audience, expiry). Uses a 30-second cache — may briefly return `false` after cache expires. Fine for UI rendering; use `isAuthenticatedAsync()` when the result is critical.

**Returns:** `boolean`

### isAuthenticatedAsync()

Server-verified authentication check. Fetches fresh tokens from the server and validates.

**Returns:** `Promise<boolean>`

### getTokens()

Get stored tokens. Always use `await` — fetches from server if cache has expired.

```javascript
const tokens = await getTokens();
// { access_token, id_token, refresh_token, auth_method }
```

**Returns:** `Promise<Object|null>`

### getAuthMethod()

**Returns:** `'password' | 'passkey' | null`

### getUserEmail()

Email from cached ID token claims.

**Returns:** `string | null`

### getUserGroups()

Cognito groups from cached ID token claims.

**Returns:** `string[]`

### getIdTokenClaims()

All claims from the ID token (unverified — display only).

**Returns:** `Object | null`

### isAdmin()

True if user is in the `admin` group. Mutually exclusive with `isReadonly()`.

**Returns:** `boolean`

### isReadonly()

True if user is in the `readonly` group and NOT in `admin`.

**Returns:** `boolean`

### hasAdminScope()

True if access token has `aws.cognito.signin.user.admin` scope (required for passkey management).

**Returns:** `boolean`

## Login Methods

### loginWithPassword(email, password)

Login with email and password. Rate-limited client-side. Stores session server-side via `sessionEndpoint`.

```javascript
try {
    const tokens = await loginWithPassword('user@example.com', 'password123');
} catch (error) {
    if (error.message.includes('Additional verification')) {
        loginWithHostedUI(email);  // MFA required
    }
}
```

**Returns:** `Promise<Object>` — tokens

### loginWithPasskey(email)

Login with WebAuthn passkey. Response includes `authenticatorMetadata` with parsed flags.

```javascript
try {
    const tokens = await loginWithPasskey('user@example.com');
} catch (error) {
    if (error.name === 'NotAllowedError') {
        console.log('Cancelled by user');
    }
}
```

**Returns:** `Promise<Object>` — tokens

### loginWithConditionalUI(options?)

Passkey autofill login. Requires `<input autocomplete="username webauthn">`.

```javascript
// Discovery mode — browser shows all passkeys for this domain
await loginWithConditionalUI({ mode: 'discovery' });

// Email mode — scoped to one user
await loginWithConditionalUI({ email: 'user@example.com' });

// With abort signal
const controller = new AbortController();
await loginWithConditionalUI({ mode: 'discovery', signal: controller.signal });
```

**Parameters:**
- `options.mode` — `'email'` (default) or `'discovery'`
- `options.email` — Required for email mode
- `options.signal` — Optional AbortSignal

**Returns:** `Promise<Object>` — tokens

### loginWithHostedUI(email?)

Redirect to Cognito Hosted UI with PKCE. Required for getting admin scope.

```javascript
await loginWithHostedUI();
await loginWithHostedUI('user@example.com');  // with email hint
```

**Returns:** `Promise<void>` — redirects browser

### exchangeCodeForTokens(code, state)

Exchange OAuth authorization code for tokens. Call from callback page.

```javascript
const params = new URLSearchParams(window.location.search);
const tokens = await exchangeCodeForTokens(params.get('code'), params.get('state'));
```

**Returns:** `Promise<Object>` — tokens

### logout()

Clear tokens, destroy server session, stop auto-refresh.

```javascript
logout();
```

**Returns:** `void`

## Token Management

### isTokenExpired(tokens)

**Returns:** `boolean`

### shouldRefreshToken(tokens)

True if token is approaching expiry (within 5 minutes).

**Returns:** `boolean`

### refreshTokens()

Refresh tokens via the server (which calls Cognito). Destroys session on failure.

**Returns:** `Promise<Object>` — new tokens

### ensureValidTokens()

Get valid tokens, refreshing if needed. Prefer this over manual refresh for non-idempotent requests (payments, orders).

**Returns:** `Promise<Object|null>`

## Passkey Management

All passkey functions require admin scope (`loginWithHostedUI()`).

### registerPasskey(options?)

Register a new passkey for current user.

```javascript
await registerPasskey();                           // default: no attestation
await registerPasskey({ attestation: 'direct' });  // manufacturer attestation
await registerPasskey({ attestation: 'enterprise' }); // managed device attestation
```

**Parameters:**
- `options.attestation` — `'none'` (default), `'indirect'`, `'direct'`, `'enterprise'`
- `options.authenticatorAttachment` — `'platform'`, `'cross-platform'`, or omit for any
- `options.residentKey` — `'required'` (default), `'preferred'`, `'discouraged'`
- `options.userVerification` — `'preferred'` (default), `'required'`, `'discouraged'`

Response includes `authenticatorMetadata`:
```javascript
// { userPresent, userVerified, backupEligible, backupState,
//   attestedCredentialData, signCount, aaguid }
```

If `validateCredentialEndpoint` is configured, credentials are validated against server policy (AAGUID allowlist, device-bound requirement) before completing registration.

**Returns:** `Promise<Object>`

### upgradeToPasskey(options?)

Silently offer passkey registration after password login (conditional create). Returns `false` if browser doesn't support it or user declines. Does not throw.

```javascript
const registered = await upgradeToPasskey();
```

**Returns:** `Promise<boolean>`

### listPasskeys()

**Returns:** `Promise<Array>` — `[{ CredentialId, FriendlyName, ... }]`

### deletePasskey(credentialId)

**Returns:** `Promise<void>`

## WebAuthn Capabilities

### isPasskeySupported()

Synchronous check for WebAuthn support (secure context + PublicKeyCredential).

**Returns:** `boolean`

### isConditionalMediationAvailable()

Check if browser supports passkey autofill.

**Returns:** `Promise<boolean>`

### isPlatformAuthenticatorAvailable()

Check if Touch ID / Face ID / Windows Hello is available.

**Returns:** `Promise<boolean>`

### getPasskeyCapabilities()

Full capabilities report. Uses WebAuthn Level 3 `getClientCapabilities()` where available, with fallback to individual checks.

```javascript
const caps = await getPasskeyCapabilities();
// { supported, conditionalMediation, conditionalCreate, platformAuthenticator,
//   secureContext, hybridTransport, passkeyPlatformAuthenticator,
//   relatedOrigins, isWebView, source }
```

**Returns:** `Promise<Object>`

## Authorization

### requireServerAuthorization(action, options?)

Send an authorization request to the Cedar policy engine on the server.

```javascript
const result = await requireServerAuthorization('write:own', {
    resource: { id: 'doc-123', type: 'document', owner: ownerSub }
});
if (result.authorized) {
    // proceed
}
```

**Parameters:**
- `action` — Cedar action string (e.g., `'read:content'`, `'admin:delete-user'`)
- `options.resource` — `{ id, type, owner }` (optional)
- `options.context` — Additional context for Cedar (optional)
- `options.endpoint` — Override endpoint (default: `'/auth/authorize'`)

**Returns:** `Promise<{ authorized: boolean, reason?: string }>`

### UI_ONLY_hasRole(requiredRole)

Client-side role check for UI display. **Never use for real authorization.**

```javascript
if (UI_ONLY_hasRole('editor')) {
    showEditButton();  // UI hint only
}
```

**Returns:** `boolean`

## Events

All `on*()` functions return an unsubscribe function.

### onLogin(callback)

Fires on actual login (not token refresh).

```javascript
const unsub = onLogin((tokens, method) => {
    console.log('Logged in via:', method); // 'password', 'passkey', 'oauth'
});
```

### onLogout(callback)

Fires when user logs out or tokens are cleared.

### onAuthStateChange(callback)

Fires on login or logout (not refresh). Prefer `onLogin`/`onLogout` for new code.

```javascript
const unsub = onAuthStateChange((isAuthenticated) => { ... });
```

### onSessionExpired(callback)

Fires when refresh fails permanently and user must re-authenticate.

```javascript
const unsub = onSessionExpired((reason) => {
    window.location.href = '/login';
});
```

## Auto-Refresh

### startAutoRefresh(options?)

Start background token refresh. Called automatically on login.

```javascript
startAutoRefresh({
    intervalMs: 30000,       // default: 60000
    pauseWhenHidden: true    // default: true (visibility API)
});
```

**Returns:** `Function` — stop function

### stopAutoRefresh()

Stop background refresh. Called automatically on logout.

### isAutoRefreshActive()

**Returns:** `boolean`

## Authenticated Fetch

### fetchWithAuth(url, options?)

`fetch()` with automatic Bearer token injection and 401 retry-after-refresh.

```javascript
const res = await fetchWithAuth('/api/data');
const res = await fetchWithAuth('/api/data', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'Hello' })
});
```

**Warning:** On 401, the entire request is retried (including POST body). For non-idempotent requests (payments, order creation), use `ensureValidTokens()` first and handle 401 yourself.

**Returns:** `Promise<Response>`

## Debug & Diagnostics

### getDiagnostics()

Snapshot of current auth state. Works without debug mode.

```javascript
const diag = getDiagnostics();
// { configured, hasTokens, isAuthenticated, tokenExpiry,
//   authMethod, userEmail, userGroups, isAdmin, isReadonly,
//   autoRefreshActive, debug, version }
```

**Returns:** `Object`

### getDebugHistory()

Last 100 debug events (newest last). Empty when debug is disabled.

**Returns:** `Array<{ timestamp, category, message, data?, version }>`

### clearDebugHistory()

Clear the debug event buffer.

## JWT Utilities

### UNSAFE_decodeJwtPayload(token)

Decode JWT payload without signature verification. The `UNSAFE_` prefix is intentional — these claims are **unverified** and must never be used for authorization.

```javascript
const payload = UNSAFE_decodeJwtPayload(tokens.id_token);
// Use ONLY for display: payload.email, payload.exp
```

**Returns:** `Object`
