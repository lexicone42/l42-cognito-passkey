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
    tokenKey: 'l42_auth_tokens',          // localStorage key
    cookieName: 'l42_id_token',           // cookie name
    cookieDomain: '.myapp.com',           // auto-detected if not set
    allowedDomains: ['myapp.com']         // auto-allows current domain if not set
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
console.log(VERSION); // "0.6.0"
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

Get stored authentication tokens.

```javascript
import { getTokens } from '/auth/auth.js';

const tokens = getTokens();
// { access_token, id_token, refresh_token, auth_method }
```

**Returns:** `Object | null`

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

### decodeJwtPayload(token) [DEPRECATED]

Alias for `UNSAFE_decodeJwtPayload`. Emits deprecation warning. Will be removed in v1.0.

### parseJwt(token) [DEPRECATED]

Alias for `UNSAFE_decodeJwtPayload`. Will be removed in v1.0.
