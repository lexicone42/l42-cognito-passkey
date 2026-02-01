# Token Handler Mode (v0.8.0)

Token Handler mode is the most secure token storage option, storing tokens server-side in HttpOnly session cookies. This makes tokens completely inaccessible to JavaScript, providing strong protection against XSS attacks.

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

See `examples/backends/express/` for a complete implementation.

## API Changes

### Async `getTokens()`

In handler mode, `getTokens()` returns a Promise:

```javascript
// Works in ALL modes (await is safe on non-Promises)
const tokens = await getTokens();

// OR use the explicit async version
const tokens = await getTokensAsync();
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

### AWS Lambda + API Gateway

Coming in v0.8.1. Will use DynamoDB for session storage.

### Cloudflare Workers

Coming in v0.8.1. Will use Workers KV for session storage.

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

Session cookies use `SameSite=Lax`, which prevents CSRF for state-changing requests (POST). Combined with your existing CORS configuration, this provides strong CSRF protection.

### Is the cache a security risk?

The cache holds tokens briefly (30 seconds by default) to avoid repeated server calls. This is the same risk as memory mode - tokens are in JavaScript memory. The key improvement is:

1. Tokens aren't persisted in storage
2. Refresh token is never exposed
3. Cache clears when page is closed

### Can I use handler mode without OAuth?

Yes! Direct login methods (`loginWithPassword`, `loginWithPasskey`) still work. After login, tokens are sent to your backend via a separate endpoint you implement. However, OAuth is recommended for the cleanest flow.
