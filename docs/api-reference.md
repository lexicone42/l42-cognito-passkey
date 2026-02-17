# API Reference

Complete API documentation for l42-cognito-passkey.

## Configuration

### configure(options)

Configure the auth module. Must be called before using other functions (unless using `window.L42_AUTH_CONFIG`).

```javascript
import { configure } from '/auth/auth.js';

configure({
    clientId: 'your-client-id',           // REQUIRED
    cognitoDomain: 'app.auth.us-west-2.amazoncognito.com',  // REQUIRED
    cognitoRegion: 'us-west-2',           // default: 'us-west-2'
    redirectUri: '/callback',              // default: origin + '/callback'
    scopes: 'openid email aws.cognito.signin.user.admin',
    tokenKey: 'l42_auth_tokens',          // storage key
    tokenStorage: 'handler',              // only supported mode
    cookieName: 'l42_id_token',           // cookie name
    allowedDomains: ['myapp.com'],        // auto-allows current domain if not set
    // Handler mode endpoints (required for handler mode)
    tokenEndpoint: '/auth/token',          // GET endpoint returning tokens
    refreshEndpoint: '/auth/refresh',      // POST endpoint to refresh tokens
    logoutEndpoint: '/auth/logout',        // POST endpoint to logout
    oauthCallbackUrl: '/auth/callback',    // Backend OAuth callback URL
    handlerCacheTtl: 30000                 // Cache TTL in ms (default: 30000)
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
    scopes: ['openid', 'email', 'aws.cognito.signin.user.admin']
};
</script>
<script type="module">
import { isAuthenticated } from '/auth/auth.js';
// Auto-configured from window.L42_AUTH_CONFIG
</script>
```

### isConfigured()

Check if the library has been configured.

```javascript
import { isConfigured } from '/auth/auth.js';

if (!isConfigured()) {
    console.log('Need to configure auth');
}
```

### VERSION

Library version string.

```javascript
import { VERSION } from '/auth/auth.js';
console.log(VERSION); // "0.17.0"
```

## Authentication State

### isAuthenticated()

Check if user is logged in with valid (non-expired) tokens.

```javascript
import { isAuthenticated } from '/auth/auth.js';

if (isAuthenticated()) {
    showDashboard();
} else {
    showLogin();
}
```

**Returns:** `boolean`

### getTokens()

Get stored authentication tokens. Always use `await` — required for handler mode, works in all modes.

```javascript
import { getTokens } from '/auth/auth.js';

const tokens = await getTokens();
// { access_token, id_token, refresh_token, auth_method }
```

**Returns:** `Promise<Object|null>` — Fetches tokens from the server if cache has expired. Use `await getTokens()`.

### getAuthMethod()

Get the authentication method used for current session.

```javascript
import { getAuthMethod } from '/auth/auth.js';

const method = getAuthMethod();
// 'password' or 'passkey' or null
```

**Returns:** `'password' | 'passkey' | null`

### getUserEmail()

Get user's email from ID token claims.

```javascript
import { getUserEmail } from '/auth/auth.js';

const email = getUserEmail();
```

**Returns:** `string | null`

### getIdTokenClaims()

Get all claims from the ID token (unverified - display only).

```javascript
import { getIdTokenClaims } from '/auth/auth.js';

const claims = getIdTokenClaims();
// { sub, email, cognito:groups, ... }
```

**Returns:** `Object | null`

### getUserGroups()

Get user's Cognito groups.

```javascript
import { getUserGroups } from '/auth/auth.js';

const groups = getUserGroups();
// ['admin', 'readonly']
```

**Returns:** `string[]`

### isAdmin()

Check if user is in the 'admin' group.

```javascript
import { isAdmin } from '/auth/auth.js';

if (isAdmin()) {
    showAdminPanel();
}
```

**Returns:** `boolean`

### isReadonly()

Check if user is in 'readonly' group (and NOT admin).

```javascript
import { isReadonly } from '/auth/auth.js';

if (isReadonly()) {
    disableEditButtons();
}
```

**Returns:** `boolean`

### hasAdminScope()

Check if access token has `aws.cognito.signin.user.admin` scope (required for passkey management).

```javascript
import { hasAdminScope } from '/auth/auth.js';

if (!hasAdminScope()) {
    // Need to re-login via hosted UI to get admin scope
    loginWithHostedUI();
}
```

**Returns:** `boolean`

## Login Methods

### loginWithPassword(email, password)

Login with email and password.

```javascript
import { loginWithPassword } from '/auth/auth.js';

try {
    const tokens = await loginWithPassword('user@example.com', 'password123');
    console.log('Logged in!');
} catch (error) {
    if (error.message.includes('Additional verification')) {
        // MFA required - redirect to hosted UI
        loginWithHostedUI(email);
    } else {
        console.error('Login failed:', error.message);
    }
}
```

**Returns:** `Promise<Object>` - tokens

### loginWithPasskey(email)

Login with WebAuthn passkey.

```javascript
import { loginWithPasskey } from '/auth/auth.js';

try {
    const tokens = await loginWithPasskey('user@example.com');
    console.log('Logged in with passkey!');
} catch (error) {
    if (error.name === 'NotAllowedError') {
        console.log('Passkey authentication cancelled');
    } else {
        console.error('Passkey login failed:', error.message);
    }
}
```

**Returns:** `Promise<Object>` - tokens

### loginWithHostedUI(email?)

Redirect to Cognito Hosted UI for OAuth login. Required for getting admin scope.

Uses **PKCE** (Proof Key for Code Exchange) for enhanced security. The function generates a cryptographic code challenge before redirecting.

```javascript
import { loginWithHostedUI } from '/auth/auth.js';

// Store redirect destination before redirecting
sessionStorage.setItem('l42_redirect_after_login', window.location.pathname);

// Function is async (generates PKCE challenge)
await loginWithHostedUI();
// or with email hint:
await loginWithHostedUI('user@example.com');
```

**Returns:** `Promise<void>` (redirects browser after generating PKCE challenge)

> **Note (v0.5.2+):** This function is now async. The redirect happens before the promise resolves, so existing synchronous calls still work, but `await` is recommended for clarity.

### exchangeCodeForTokens(code, state)

Exchange OAuth authorization code for tokens. Call from callback page.

```javascript
import { exchangeCodeForTokens } from '/auth/auth.js';

const params = new URLSearchParams(window.location.search);
const code = params.get('code');
const state = params.get('state');

try {
    const tokens = await exchangeCodeForTokens(code, state);
    window.location.href = '/';
} catch (error) {
    console.error('Token exchange failed:', error.message);
}
```

**Returns:** `Promise<Object>` - tokens

### logout()

Clear tokens and session.

```javascript
import { logout } from '/auth/auth.js';

logout();
window.location.href = '/login';
```

**Returns:** `void`

## Token Management

### isTokenExpired(tokens)

Check if token is expired.

```javascript
import { isTokenExpired, getTokens } from '/auth/auth.js';

const tokens = getTokens();
if (isTokenExpired(tokens)) {
    console.log('Token expired');
}
```

**Returns:** `boolean`

### shouldRefreshToken(tokens)

Check if token should be proactively refreshed (approaching expiry).

```javascript
import { shouldRefreshToken, getTokens } from '/auth/auth.js';

const tokens = getTokens();
if (shouldRefreshToken(tokens)) {
    await refreshTokens();
}
```

**Returns:** `boolean`

### refreshTokens()

Refresh tokens using refresh token.

```javascript
import { refreshTokens } from '/auth/auth.js';

try {
    const newTokens = await refreshTokens();
    console.log('Tokens refreshed');
} catch (error) {
    console.error('Refresh failed:', error.message);
    logout();
}
```

**Returns:** `Promise<Object>` - new tokens

### ensureValidTokens()

Get valid tokens, refreshing if needed. **Call this before API requests.**

```javascript
import { ensureValidTokens } from '/auth/auth.js';

async function fetchWithAuth(url) {
    const tokens = await ensureValidTokens();
    if (!tokens) {
        throw new Error('Not authenticated');
    }

    return fetch(url, {
        headers: {
            'Authorization': `Bearer ${tokens.id_token}`
        }
    });
}
```

**Returns:** `Promise<Object | null>`

## Passkey Management

All passkey management functions require admin scope. User must have logged in via `loginWithHostedUI()`.

### listPasskeys()

List registered passkeys for current user.

```javascript
import { listPasskeys } from '/auth/auth.js';

try {
    const passkeys = await listPasskeys();
    passkeys.forEach(pk => {
        console.log(pk.CredentialId, pk.FriendlyName);
    });
} catch (error) {
    console.error('Failed to list passkeys:', error.message);
}
```

**Returns:** `Promise<Array>`

### registerPasskey()

Register a new passkey for current user.

```javascript
import { registerPasskey } from '/auth/auth.js';

try {
    await registerPasskey();
    console.log('Passkey registered!');
} catch (error) {
    console.error('Registration failed:', error.message);
}
```

**Returns:** `Promise<void>`

### deletePasskey(credentialId)

Delete a registered passkey.

```javascript
import { deletePasskey } from '/auth/auth.js';

try {
    await deletePasskey('credential-id-here');
    console.log('Passkey deleted');
} catch (error) {
    console.error('Delete failed:', error.message);
}
```

**Returns:** `Promise<void>`

## Events

### onLogin(callback)

Subscribe to login events. Only fires on actual login, never on token refresh. **(v0.6.0+)**

```javascript
import { onLogin } from '/auth/auth.js';

const unsubscribe = onLogin((tokens, method) => {
    console.log('User logged in via:', method); // 'password', 'passkey', or 'oauth'
    window.location.href = '/dashboard';
});

// Later: unsubscribe();
```

**Parameters:**
- `callback(tokens, method)` - Called with tokens object and auth method string

**Returns:** `Function` - unsubscribe function

### onLogout(callback)

Subscribe to logout events. Fires when user logs out or tokens are cleared. **(v0.6.0+)**

```javascript
import { onLogout } from '/auth/auth.js';

const unsubscribe = onLogout(() => {
    showLoginScreen();
});

// Later: unsubscribe();
```

**Returns:** `Function` - unsubscribe function

### onAuthStateChange(callback)

Subscribe to authentication state changes. For new code, prefer `onLogin()` and `onLogout()`.

```javascript
import { onAuthStateChange } from '/auth/auth.js';

const unsubscribe = onAuthStateChange((isAuthenticated) => {
    if (isAuthenticated) {
        showDashboard();
    } else {
        showLogin();
    }
});

// Later: unsubscribe();
```

**Returns:** `Function` - unsubscribe function

> **Note (v0.5.7+):** This is not called during token refresh, preventing reload loops.
> For clearer semantics, use `onLogin()` and `onLogout()` instead.

### onSessionExpired(callback) (v0.9.0+)

Subscribe to unrecoverable session expiry events. Fires when refresh fails and the user must re-authenticate.

```javascript
import { onSessionExpired } from '/auth/auth.js';

const unsubscribe = onSessionExpired((reason) => {
    alert('Your session has expired. Please log in again.');
    window.location.href = '/login';
});
```

**Parameters:**
- `callback(reason)` - Called with a string describing why the session expired

**Returns:** `Function` - unsubscribe function

## Auto-Refresh (v0.9.0+)

### startAutoRefresh(options?)

Start automatic background token refresh. Called automatically on login.

```javascript
import { startAutoRefresh } from '/auth/auth.js';

// Custom options
startAutoRefresh({
    intervalMs: 30000,       // Check every 30s (default: 60000)
    pauseWhenHidden: true    // Pause when tab hidden (default: true)
});
```

**Parameters:**
- `options.intervalMs` - Check interval in milliseconds (default: 60000)
- `options.pauseWhenHidden` - Pause refresh checks when tab is hidden (default: true)

**Returns:** `Function` - stop function (same as `stopAutoRefresh`)

### stopAutoRefresh()

Stop automatic token refresh. Called automatically on logout.

```javascript
import { stopAutoRefresh } from '/auth/auth.js';

stopAutoRefresh();
```

### isAutoRefreshActive()

Check if auto-refresh is currently running.

```javascript
import { isAutoRefreshActive } from '/auth/auth.js';

console.log(isAutoRefreshActive()); // true or false
```

**Returns:** `boolean`

## Authenticated Fetch (v0.9.0+)

### fetchWithAuth(url, options?)

Make an authenticated fetch request. Automatically injects Bearer token, handles 401 with retry-after-refresh.

```javascript
import { fetchWithAuth } from '/auth/auth.js';

// GET
const res = await fetchWithAuth('/api/data');
const data = await res.json();

// POST with body
const res = await fetchWithAuth('/api/data', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'Hello' })
});
```

**Parameters:**
- `url` - URL to fetch
- `options` - Standard `fetch()` options

**Returns:** `Promise<Response>`

**Throws:** `Error` if not authenticated or session expired after retry

**Behavior on 401:**
1. Attempts `refreshTokens()`
2. Retries the request with fresh tokens
3. If refresh fails: clears tokens, fires `onSessionExpired`, throws

## Debug & Diagnostics (v0.11.0+)

### configure({ debug })

Enable debug logging to diagnose auth issues.

```javascript
import { configure } from '/auth/auth.js';

// Console output with [l42-auth] prefix
configure({ clientId: '...', cognitoDomain: '...', debug: true });

// Verbose mode — includes data payloads
configure({ clientId: '...', cognitoDomain: '...', debug: 'verbose' });

// Custom callback (e.g., send to Datadog, Sentry)
configure({
    clientId: '...', cognitoDomain: '...',
    debug: (event) => {
        myLogger.debug(event.category, event.message, event.data);
    }
});
```

### getDiagnostics()

Get a snapshot of current auth state. Works regardless of whether debug mode is enabled.

```javascript
import { getDiagnostics } from '/auth/auth.js';

const diag = getDiagnostics();
// {
//   configured: true,
//   tokenStorage: 'localStorage',
//   hasTokens: true,
//   isAuthenticated: true,
//   tokenExpiry: Date,
//   authMethod: 'password',
//   userEmail: 'user@example.com',
//   userGroups: ['admin'],
//   isAdmin: true,
//   isReadonly: false,
//   autoRefreshActive: true,
//   debug: true,
//   version: '0.11.0'
// }
```

**Returns:** `DiagnosticsInfo`

### getDebugHistory()

Get a copy of the last 100 debug events (newest last). Returns empty array when debug is disabled.

```javascript
import { getDebugHistory } from '/auth/auth.js';

const events = getDebugHistory();
events.forEach(e => {
    console.log(`[${new Date(e.timestamp).toISOString()}] ${e.category}: ${e.message}`, e.data);
});
```

**Returns:** `DebugEvent[]`

Each event has: `{ timestamp, category, message, data?, version }`

### clearDebugHistory()

Clear the debug event buffer.

```javascript
import { clearDebugHistory } from '/auth/auth.js';

clearDebugHistory();
```

**Returns:** `void`

## JWT Utilities

### UNSAFE_decodeJwtPayload(token)

Decode JWT payload. **Does NOT verify signature - use for display only.**

The `UNSAFE_` prefix reminds you that these claims are **unverified** and should never be used for authorization decisions.

```javascript
import { UNSAFE_decodeJwtPayload } from '/auth/auth.js';

const payload = UNSAFE_decodeJwtPayload(tokens.id_token);
// Use ONLY for display purposes
console.log(payload.email, payload.exp);
```

**Returns:** `Object`
