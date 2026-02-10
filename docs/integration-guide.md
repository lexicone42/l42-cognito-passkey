# Integration Guide

How to integrate l42-cognito-passkey into your project, with advice for Claude Code sessions.

## Quick Start

### 1. Install

```bash
# From GitHub
pnpm add github:lexicone42/l42-cognito-passkey
```

Or copy directly:

```bash
cp node_modules/l42-cognito-passkey/src/auth.js ./public/auth/auth.js
```

### 2. Configure

```javascript
import { configure, isAuthenticated, loginWithHostedUI, logout } from './auth.js';

configure({
    clientId: 'your-cognito-client-id',
    cognitoDomain: 'your-app.auth.us-west-2.amazoncognito.com',
    cognitoRegion: 'us-west-2'
});
```

### 3. Use

```javascript
if (isAuthenticated()) {
    const email = getUserEmail();
    showDashboard(email);
} else {
    await loginWithHostedUI();
}
```

## Token Storage Mode

**Handler mode is the only supported token storage mode** (since v0.15.0). It stores tokens server-side in HttpOnly cookies, making them invisible to JavaScript.

### Handler mode setup

Handler mode requires a backend. See `examples/backends/express/` for a reference implementation.

```javascript
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout'
});
```

Your backend must implement these endpoints:

| Endpoint | Method | Purpose | CSRF Header Required |
|----------|--------|---------|---------------------|
| `/auth/token` | GET | Return `{access_token, id_token}` from session | No (GET) |
| `/auth/refresh` | POST | Refresh tokens, return new tokens | Yes (`X-L42-CSRF: 1`) |
| `/auth/logout` | POST | Destroy session | Yes (`X-L42-CSRF: 1`) |
| `/auth/callback` | GET | OAuth callback (exchange code for tokens) | No (GET) |

## Site Architecture Patterns

### Static Site with Protected Areas

```
site.com/              → Public (CDN-cached)
site.com/auth/         → Protected (requires login)
site.com/admin/        → Admin area (requires admin group)
```

```javascript
import { isAuthenticated, isAdmin, onSessionExpired } from './auth.js';

// Redirect unauthenticated users
if (!isAuthenticated() && window.location.pathname.startsWith('/auth/')) {
    window.location.href = '/login';
}

// Redirect non-admins from admin area
if (window.location.pathname.startsWith('/admin/') && !isAdmin()) {
    window.location.href = '/auth/';
}

// Handle session expiry gracefully
onSessionExpired((reason) => {
    window.location.href = '/login?expired=true';
});
```

### SPA with API Backend

```javascript
import { configure, fetchWithAuth, onSessionExpired } from './auth.js';

configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout'
});

// Use fetchWithAuth for all API calls
async function loadContent() {
    const res = await fetchWithAuth('/api/content');
    return res.json();
}

// Auto-refresh handles token lifecycle
// onSessionExpired fires if the session can't be recovered
onSessionExpired(() => router.navigate('/login'));
```

### Multi-Site Deployment

For multiple sites sharing a Cognito user pool:

```javascript
// Site A: admin.myapp.com
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    cookieDomain: '.myapp.com',  // Shared cookie domain
    tokenStorage: 'handler',
    tokenEndpoint: 'https://api.myapp.com/auth/token',
    refreshEndpoint: 'https://api.myapp.com/auth/refresh',
    logoutEndpoint: 'https://api.myapp.com/auth/logout'
});

// Site B: app.myapp.com
configure({
    clientId: 'xxx',  // Same or different client ID
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    cookieDomain: '.myapp.com',  // Same shared cookie domain
    tokenStorage: 'handler',
    tokenEndpoint: 'https://api.myapp.com/auth/token',
    refreshEndpoint: 'https://api.myapp.com/auth/refresh',
    logoutEndpoint: 'https://api.myapp.com/auth/logout'
});
```

## RBAC Integration

### Client-Side (UI Only)

```javascript
import { isAdmin, isReadonly, getUserGroups } from './auth.js';
import { hasPermission, isInCognitoGroup } from './rbac-roles.js';

// Built-in checks (with alias support)
if (isAdmin()) showAdminPanel();      // Checks: admin, admins, administrators
if (isReadonly()) disableEditing();    // Checks: readonly, read-only, viewer, viewers

// Fine-grained permissions
if (hasPermission('editor', 'publish:content')) {
    showPublishButton();
}

// Direct group checking with aliases
const groups = getUserGroups();
if (isInCognitoGroup(groups, 'PUBLISHER')) {
    showPublishingTools();
}
```

### Server-Side (Required for Real Authorization)

```javascript
import { requireServerAuthorization } from './auth.js';

// Always validate on the server
const result = await requireServerAuthorization('admin:delete-user', {
    context: { targetUserId: userId }
});
if (result.authorized) {
    await deleteUser(userId);
}
```

## Auto-Refresh and Session Lifecycle

Auto-refresh starts automatically on login. The default setup works for most apps:

```javascript
import { onSessionExpired } from './auth.js';

// Just handle the failure case
onSessionExpired((reason) => {
    // Redirect to login, show modal, etc.
    window.location.href = '/login?reason=expired';
});
```

To customize the refresh interval:

```javascript
import { startAutoRefresh } from './auth.js';

// Check every 30 seconds instead of default 60
startAutoRefresh({ intervalMs: 30000 });

// Disable pause-on-hidden for critical apps
startAutoRefresh({ pauseWhenHidden: false });
```

## Content Security Policy

Since auth.js is self-hosted, the CSP is straightforward:

```
script-src: 'self'
connect-src: 'self' https://cognito-idp.{region}.amazonaws.com https://*.amazoncognito.com
form-action: 'self' https://{cognitoDomain}
```

No external script sources needed. For stronger CSP, use nonce-based policies — see `docs/security-hardening.md`.

## Cognito Setup Checklist

Before integration, ensure your Cognito user pool is configured:

- [ ] App client created with `ALLOW_USER_PASSWORD_AUTH`, `ALLOW_USER_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`
- [ ] OAuth scopes: `openid`, `email`, `aws.cognito.signin.user.admin`
- [ ] Callback URLs configured (your domain + `/callback`)
- [ ] WebAuthn enabled via boto3 (not CDK — CDK doesn't support it yet)
- [ ] Cognito groups created for your RBAC needs (`admin`, `readonly`, etc.)

See `docs/cognito-setup.md` for step-by-step instructions.

---

## Claude Code Integration Guide

This section is for Claude Code instances integrating this library into projects.

### Installation

```bash
# Recommended: install from GitHub
pnpm add github:lexicone42/l42-cognito-passkey

# Then copy auth.js to your project's static files
cp node_modules/l42-cognito-passkey/src/auth.js ./public/auth/auth.js
```

### What to Configure

When helping a user set up auth, you need these values from them:

1. **`clientId`** — Cognito app client ID (found in AWS Console → Cognito → User Pools → App clients)
2. **`cognitoDomain`** — The Cognito domain prefix (e.g., `myapp.auth.us-west-2.amazoncognito.com`)
3. **`cognitoRegion`** — AWS region (default: `us-west-2`)

For handler mode, also need:
4. The backend URL for token/refresh/logout endpoints

### Generating the Configuration

```javascript
// Minimal configuration (localStorage mode)
configure({
    clientId: '${CLIENT_ID}',
    cognitoDomain: '${COGNITO_DOMAIN}'
});

// Production configuration (handler mode)
configure({
    clientId: '${CLIENT_ID}',
    cognitoDomain: '${COGNITO_DOMAIN}',
    cognitoRegion: '${REGION}',
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout'
});
```

### Creating the OAuth Callback Page

If using OAuth/Hosted UI, create a `callback.html`:

```html
<!DOCTYPE html>
<html>
<head><title>Authenticating...</title></head>
<body>
<p>Completing login...</p>
<script type="module">
import { exchangeCodeForTokens, configure } from './auth.js';

configure({
    clientId: 'your-client-id',
    cognitoDomain: 'your-app.auth.region.amazoncognito.com'
});

const params = new URLSearchParams(window.location.search);
const code = params.get('code');
const state = params.get('state');

if (code) {
    try {
        await exchangeCodeForTokens(code, state);
        const redirect = sessionStorage.getItem('l42_redirect_after_login') || '/';
        window.location.href = redirect;
    } catch (e) {
        document.body.textContent = 'Login failed: ' + e.message;
    }
}
</script>
</body>
</html>
```

### Common Patterns to Implement

**Login page:**
```javascript
import { loginWithPassword, loginWithPasskey, loginWithHostedUI } from './auth.js';

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        await loginWithPassword(email, password);
        window.location.href = '/dashboard';
    } catch (error) {
        document.getElementById('error').textContent = error.message;
    }
});

document.getElementById('passkey-btn').addEventListener('click', async () => {
    const email = document.getElementById('email').value;
    try {
        await loginWithPasskey(email);
        window.location.href = '/dashboard';
    } catch (error) {
        document.getElementById('error').textContent = error.message;
    }
});
```

**Auth guard for protected pages:**
```javascript
import { isAuthenticated, onSessionExpired } from './auth.js';

if (!isAuthenticated()) {
    window.location.href = '/login';
}

onSessionExpired(() => {
    window.location.href = '/login?expired=true';
});
```

**API calls from protected pages:**
```javascript
import { fetchWithAuth } from './auth.js';

const res = await fetchWithAuth('/api/resource');
if (res.ok) {
    const data = await res.json();
    // render data
}
```

### Testing the Integration

After integrating, run the library's test suite to verify nothing is broken:

```bash
cd node_modules/l42-cognito-passkey && pnpm test
```

### Key Gotchas

1. **`await getTokens()`** — Always use `await` on `getTokens()`. It's sync in localStorage/memory mode but async in handler mode. Using `await` is safe in all modes.

2. **`isAuthenticated()` is sync** — It uses cached tokens, so it works without `await`. But the cache may be stale in handler mode. Use `isAuthenticatedAsync()` if you need a server-verified check.

3. **WebAuthn requires HTTPS** — Passkey registration/login won't work on `http://` (except `localhost`).

4. **Admin scope requires Hosted UI** — `loginWithPassword()` doesn't grant `aws.cognito.signin.user.admin` scope. Users must go through `loginWithHostedUI()` at least once for passkey management.

5. **CDK doesn't support WebAuthn** — Use boto3 to configure WebAuthn on the Cognito user pool. See `docs/cognito-setup.md`.

6. **CSRF header on handler POSTs** — The library sends `X-L42-CSRF: 1` on handler mode POST requests. Your backend must check for this header.

### Reporting Integration Issues

```bash
gh issue create --repo lexicone42/l42-cognito-passkey \
  --title "integration: Brief description" \
  --label "integration-feedback"
```

Include: framework/platform, storage mode used, error messages, and which functions were called.
