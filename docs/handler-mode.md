# Token Handler Mode (Recommended)

Token Handler mode is the **recommended production deployment**. It stores tokens server-side in HttpOnly session cookies, making them completely inaccessible to JavaScript and providing strong protection against XSS attacks.

> **Note:** `localStorage` and `memory` token storage modes are deprecated as of v0.14.0 and will be removed in v1.0. All production deployments should use handler mode.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                       Token Handler Flow                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Login via Hosted UI                                          │
│     ┌──────────┐    redirect    ┌──────────┐                    │
│     │ Frontend │ ─────────────► │ Cognito  │                    │
│     └──────────┘                └────┬─────┘                    │
│                                      │ code                      │
│                                      ▼                           │
│     ┌──────────┐    tokens     ┌──────────┐                    │
│     │ Frontend │ ◄──────────── │ Backend  │                    │
│     └──────────┘   (cached)    └──────────┘                    │
│                                      │                           │
│                           stores in HttpOnly session             │
│                                                                  │
│  2. Get Tokens                                                   │
│     ┌──────────┐   /auth/token  ┌──────────┐                    │
│     │ Frontend │ ─────────────► │ Backend  │                    │
│     └──────────┘                └────┬─────┘                    │
│          ▲                           │                           │
│          │    {access_token,         │ reads from session       │
│          └──── id_token}        ─────┘                          │
│                                                                  │
│  3. Refresh (automatic)                                          │
│     ┌──────────┐  /auth/refresh ┌──────────┐   refresh   ┌─────┐│
│     │ Frontend │ ─────────────► │ Backend  │ ──────────► │ Cog ││
│     └──────────┘                └──────────┘   tokens    └─────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Security Benefits

| Threat | localStorage | memory | handler |
|--------|-------------|--------|---------|
| XSS stealing tokens from storage | ❌ Vulnerable | ✅ Protected | ✅ Protected |
| XSS reading tokens via API | ❌ Vulnerable | ❌ Vulnerable | ⚠️ Limited* |
| Refresh token exposure | ❌ In browser | ❌ In browser | ✅ Server-only |
| Persistence across reloads | ✅ Yes | ❌ No | ✅ Yes (session) |

*In handler mode, tokens are briefly cached in memory. XSS could theoretically call `getTokens()`, but can't steal the refresh token.

## Configuration

### Frontend

```javascript
import { configure, loginWithHostedUI, logout } from './auth.js';

configure({
    clientId: 'your-cognito-client-id',
    cognitoDomain: 'your-app.auth.us-west-2.amazoncognito.com',

    // Enable handler mode
    tokenStorage: 'handler',

    // Required endpoints (your backend)
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',

    // Optional: Backend OAuth callback
    oauthCallbackUrl: '/auth/callback',

    // Optional: Cache TTL in ms (default: 30000)
    handlerCacheTtl: 30000
});
```

### Backend Requirements

Your backend must implement these endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/token` | GET | Return `{access_token, id_token}` from session |
| `/auth/refresh` | POST | Refresh tokens, return new `{access_token, id_token}` |
| `/auth/logout` | POST | Destroy session |
| `/auth/callback` | GET | (Optional) OAuth callback handler |
| `/auth/authorize` | POST | (Optional) Cedar policy authorization (v0.13.0+) |

See `examples/backends/express/` for a complete implementation.

## API Changes

### Async `getTokens()`

In handler mode, `getTokens()` returns a Promise:

```javascript
// Works in ALL modes (await is safe on non-Promises)
const tokens = await getTokens();
```

### Sync `isAuthenticated()`

`isAuthenticated()` remains synchronous by checking cached tokens:

```javascript
// Sync check (uses cache in handler mode)
if (isAuthenticated()) {
    showDashboard();
}

// Async check (fetches from server if cache is stale)
if (await isAuthenticatedAsync()) {
    showDashboard();
}
```

### Async `logout()`

In handler mode, `logout()` returns a Promise (calls server endpoint):

```javascript
// Works in all modes (fire-and-forget is fine)
logout();

// OR await for confirmation
await logout();
```

## Migration Guide

### From localStorage mode

1. **Deploy a backend** (Express, Lambda, or Workers)
2. **Update configuration**:

```javascript
// Before (v0.7.0)
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    tokenStorage: 'localStorage'  // or omitted (default)
});

// After (v0.8.0)
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout'
});
```

3. **Update code to use `await`** (optional but recommended):

```javascript
// Before
const tokens = getTokens();

// After (works in all modes)
const tokens = await getTokens();
```

### No changes required for:

- `loginWithPassword()` - Still calls Cognito directly
- `loginWithPasskey()` - Still calls Cognito directly
- `loginWithHostedUI()` - Redirects to backend callback in handler mode
- `isAuthenticated()` - Still synchronous (uses cache)
- `getUserEmail()`, `getUserGroups()` - Still synchronous (uses cache)

## Backend Implementations

### Express (Node.js)

See `examples/backends/express/` for a complete example.

Key features:
- `express-session` for session management
- HttpOnly cookies
- Refresh token stored server-side

## Cedar Policy Authorization (v0.13.0+)

Token Handler mode pairs naturally with Cedar because the authorization engine runs server-side where the session tokens already live.

```javascript
// Client: request authorization (works in all modes)
const result = await requireServerAuthorization('write:own', {
    resource: { id: 'doc-123', type: 'document', owner: ownerSub }
});

if (!result.authorized) {
    showError(result.reason);
}
```

The backend evaluates the request against Cedar `.cedar` policy files:

```
Client                              Server
──────                              ──────
requireServerAuthorization()   ──►  POST /auth/authorize
                                      │ session cookie (HttpOnly)
                                      │ X-L42-CSRF header
                                      ▼
                                    Cedar engine evaluates policies
                                      │
                               ◄──  { authorized: true/false, reason }
```

Key points:
- Cedar runs server-side only (~4 MB WASM, not suitable for client)
- Existing client-side helpers (`isAdmin()`, `isReadonly()`) still work for UI hints
- If Cedar fails to initialize, `/auth/authorize` returns 503 (fail-closed)
- See `docs/cedar-integration.md` for full setup guide

## FAQ

### Why not just use HttpOnly cookies directly?

Setting HttpOnly cookies requires a server-side response header. The auth library is client-side JavaScript, so it can't set HttpOnly cookies directly. The Token Handler pattern works around this by having the backend manage tokens.

### Can XSS still steal tokens?

In handler mode, XSS cannot:
- Read tokens from localStorage/sessionStorage (nothing stored there)
- Read the refresh token (never sent to client)
- Steal tokens from cookies (HttpOnly prevents JavaScript access)

XSS CAN:
- Call `getTokens()` to get cached tokens
- Make authenticated requests while the user is on the page

This is a significant improvement over localStorage mode where tokens can be exfiltrated.

### What about CSRF?

Defense-in-depth with two layers:

1. **SameSite=Lax cookies** — Browsers block cross-origin POST cookies
2. **Custom header check (v0.9.0+)** — The client sends `X-L42-CSRF: 1` on all handler POST requests. Cross-origin requests can't add custom headers without a CORS preflight, which your backend rejects for unknown origins.

The reference Express backend enforces the `X-L42-CSRF` header via `requireCsrfHeader` middleware. If you build your own backend, implement the same check on state-changing endpoints (`/auth/refresh`, `/auth/logout`).

```javascript
// Your backend: reject POSTs without the CSRF header
function requireCsrfHeader(req, res, next) {
    if (req.headers['x-l42-csrf'] !== '1') {
        return res.status(403).json({ error: 'CSRF validation failed' });
    }
    next();
}
app.post('/auth/refresh', requireCsrfHeader, refreshHandler);
app.post('/auth/logout', requireCsrfHeader, logoutHandler);
```

### Is the cache a security risk?

The cache holds tokens briefly (30 seconds by default) to avoid repeated server calls. This is the same risk as memory mode - tokens are in JavaScript memory. The key improvement is:

1. Tokens aren't persisted in storage
2. Refresh token is never exposed
3. Cache clears when page is closed

### Can I use handler mode without OAuth?

Yes! Direct login methods (`loginWithPassword`, `loginWithPasskey`) still work. After login, tokens are sent to your backend via a separate endpoint you implement. However, OAuth is recommended for the cleanest flow.

## Background Token Refresh (v0.9.0+)

Auto-refresh starts automatically on login and stops on logout. It periodically checks token expiry and refreshes proactively before tokens expire.

```javascript
import { startAutoRefresh, stopAutoRefresh, isAutoRefreshActive } from './auth.js';

// Auto-starts on login — no action needed for defaults.

// Custom interval (default: 60 seconds):
startAutoRefresh({ intervalMs: 30000 });

// Pauses when tab is hidden, checks immediately when tab becomes visible
startAutoRefresh({ pauseWhenHidden: true }); // default

// Check status
console.log(isAutoRefreshActive()); // true

// Manual stop (also called automatically on logout)
stopAutoRefresh();
```

### How it works

1. Every `intervalMs`, calls `getTokens()` and checks `shouldRefreshToken()`
2. If approaching expiry, calls `refreshTokens()` proactively
3. If already expired, attempts refresh; on failure fires `onSessionExpired`
4. When the tab is hidden (`document.visibilityState === 'hidden'`), the timer continues but no action is taken until the tab becomes visible
5. On tab visibility restore, checks immediately

## Session Expiry Handling (v0.9.0+)

When a session becomes unrecoverable (refresh token expired, server session destroyed), the library fires `onSessionExpired`:

```javascript
import { onSessionExpired } from './auth.js';

const unsubscribe = onSessionExpired((reason) => {
    console.warn('Session expired:', reason);
    window.location.href = '/login?expired=true';
});
```

This fires when:
- Auto-refresh discovers the token is expired and refresh fails
- Handler mode server returns 401 on a refresh attempt
- `fetchWithAuth()` gets a 401 and the retry-refresh also fails

## fetchWithAuth() Helper (v0.9.0+)

Convenience wrapper that injects the Bearer token and handles 401 with retry-after-refresh:

```javascript
import { fetchWithAuth } from './auth.js';

// GET
const res = await fetchWithAuth('/api/content');
const data = await res.json();

// POST
const res = await fetchWithAuth('/api/content', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'New Post' })
});

// If the server returns 401:
// 1. Attempts token refresh
// 2. Retries the request with fresh tokens
// 3. If refresh fails: clears tokens, fires onSessionExpired, throws
```
