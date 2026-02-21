# Security

Threat model, hardening guidance, and security logging for L42 Cognito Passkey.

## Trust Boundaries

```
┌─────────────────────────────────┐
│  UNTRUSTED: Browser             │
│                                 │
│  JWT claims (can be forged)     │
│  Client RBAC (UI hints only)    │
│  Rate limiting (can be bypassed)│
│  resource.owner (caller-sent)   │
└──────────────┬──────────────────┘
               │
    ═══════════╪═══════════  Trust Boundary
               │
┌──────────────▼──────────────────┐
│  TRUSTED: Server                │
│                                 │
│  Session cookies (HttpOnly)     │
│  Cedar policy evaluation        │
│  Token refresh (refresh_token   │
│    never leaves server)         │
│  JWKS signature verification    │
│  Cognito API calls              │
└─────────────────────────────────┘
```

### What's Verified Where

| Check | Client | Server |
|-------|--------|--------|
| Token not expired | `isTokenExpired()` | Session TTL |
| Token issuer correct | `validateTokenClaims()` | JWKS verification |
| Token audience correct | `validateTokenClaims()` | JWKS verification |
| User has role | `isAdmin()` (untrusted) | Cedar policy |
| User owns resource | N/A | Cedar `forbid` policy |
| CSRF on mutations | N/A | `X-L42-CSRF` header |
| PKCE on OAuth | `code_verifier` stored client-side | Cognito verifies |
| Rate limiting | `checkLoginRateLimit()` (bypassable) | Cognito account lockout |

## Token Handler Security

Tokens stored in HttpOnly session cookies are inaccessible to JavaScript. XSS cannot:
- Read tokens from storage (nothing in localStorage)
- Read the refresh token (never sent to browser)
- Read cookies (HttpOnly prevents JS access)

XSS **can** call `getTokens()` to get cached tokens and make authenticated requests while the user is on the page. This is a significant improvement over localStorage, where tokens can be exfiltrated.

### `/auth/session` Token Verification

After passkey/password login, tokens pass through the browser briefly before being stored server-side via `/auth/session`. The backend **must verify the `id_token` signature** against Cognito's JWKS to prevent XSS from forging JWTs with arbitrary claims (e.g., admin groups).

Verification checks:
- RSA signature against `https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json`
- Issuer (`iss`) matches expected pool
- Audience (`aud`) matches client ID
- Token not expired (`exp`)

## Content Security Policy

```
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  script-src-attr 'none';
  style-src 'nonce-{RANDOM}';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self'
    https://*.amazoncognito.com
    https://cognito-idp.{REGION}.amazonaws.com;
  form-action 'self';
  frame-ancestors 'none';
  object-src 'none';
  base-uri 'none';
  upgrade-insecure-requests
```

Use nonce-based CSP. `script-src 'self'` alone can be bypassed via JSONP endpoints, CDN gadgets, or base tag injection.

### Server Implementation

```javascript
app.use((req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;
    res.setHeader('Content-Security-Policy', `
        script-src 'nonce-${nonce}' 'strict-dynamic';
        style-src 'nonce-${nonce}';
        default-src 'none';
        connect-src 'self' https://*.amazoncognito.com
            https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com;
        img-src 'self' data:;
        base-uri 'none'; object-src 'none';
    `.replace(/\s+/g, ' ').trim());
    next();
});
```

```html
<script nonce="<%= nonce %>" type="module" src="/auth/auth.js"></script>
```

## Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
```

## Passkey Attack Vectors

### AiTM / Authentication Downgrade

Phishing proxies (Evilginx, Mamba 2FA, Tycoon 2FA) sit between the user and the login page, hide the passkey prompt, and show a password form. Once the password is entered, the proxy captures the session.

**Mitigation**: Disable password auth in Cognito for passkey-only deployments. Remove `ALLOW_USER_PASSWORD_AUTH` and `ALLOW_USER_SRP_AUTH` from the User Pool Client. This is the single highest-impact security hardening.

### Cloud Account Compromise (Synced Passkeys)

Synced passkeys (iCloud Keychain, Google Password Manager) replicate across devices. Compromising the cloud account grants access to all synced passkeys.

**Mitigation**: For high-assurance deployments, set `REQUIRE_DEVICE_BOUND=true` in the Rust backend to reject synced passkeys at registration. Use `AAGUID_ALLOWLIST` to restrict to specific hardware keys.

### Browser Extension Hijacking

Chrome's `webAuthenticationProxy` API allows extensions to intercept `navigator.credentials.create()` and `.get()`. CSP doesn't help — extensions run in a separate context.

**Mitigation**: Enterprise deployments should enforce browser extension allowlists. Cannot be mitigated in library code.

### Session Token Theft (Post-Auth)

After valid passkey authentication, session cookies could be stolen via XSS or malware.

**Mitigation**: HttpOnly cookies prevent JS access. CSRF tokens prevent cross-origin abuse. Application-level XSS prevention remains essential.

## Device Attestation

### Authenticator Data Flags

Byte 32 of `authenticatorData` contains flags available without attestation:

| BE | BS | Meaning |
|----|-----|---------|
| 0 | 0 | Device-bound, single-device (e.g., YubiKey) |
| 1 | 0 | Eligible for sync but not yet synced |
| 1 | 1 | Synced/multi-device (e.g., iCloud Keychain) |

These flags are parsed by `parseAuthenticatorData()` and included in credential responses and OCSF events.

### Registration Attestation

```javascript
await registerPasskey();                           // default: no attestation
await registerPasskey({ attestation: 'direct' });  // manufacturer attestation
await registerPasskey({ attestation: 'enterprise' }); // managed device attestation
```

The Rust backend can enforce policies on the attestation data:
- `AAGUID_ALLOWLIST` — comma-separated allowed authenticator UUIDs
- `REQUIRE_DEVICE_BOUND` — rejects passkeys where BE=1

### Cognito Limitation

Cognito does not process attestation server-side. It stores credentials but doesn't validate attestation statements. Policy enforcement happens in the Token Handler backend via `/auth/validate-credential`.

## Known Limitations

| # | Finding | Severity | Notes |
|---|---------|----------|-------|
| S1 | `resource.owner` is caller-controlled | HIGH | Client can lie about ownership. Use EntityProvider for production. |
| S2 | `validateTokenClaims` requires `aud`/`client_id` and `exp` | Fixed | Missing claims now cause validation failure. |
| S3 | Rate limiting is client-side only | LOW | Cognito enforces server-side lockout. |
| S5 | Context from request body passed unvalidated to Cedar | MEDIUM | Server should build context, not forward client input. |
| — | `fetchWithAuth` retries non-idempotent requests | MEDIUM | Use `ensureValidTokens()` for payments/orders. |
| — | `window.L42_AUTH_CONFIG` can be hijacked by other scripts | LOW | Call `configure()` explicitly to prevent. |
| — | Sessions survive Cognito password changes | LOW | AWS Cognito limitation. |

## OCSF Security Logging

### Client-Side (auth.js)

Enable OCSF logging with `securityLogger`:

```javascript
configure({
    securityLogger: 'console',              // development
    // or
    securityLogger: (event) => {            // production
        fetch('/api/security-logs', {
            method: 'POST',
            body: JSON.stringify(event)
        });
    }
});
```

Events follow OCSF v1.0 schema:

| Function | OCSF Class | Activity |
|----------|-----------|----------|
| `loginWithPassword()` | Authentication (3001) | Logon |
| `loginWithPasskey()` | Authentication (3001) | Logon |
| `exchangeCodeForTokens()` | Authentication (3001) | Authentication Ticket |
| `refreshTokens()` | Authentication (3001) | Service Ticket |
| `logout()` | Authentication (3001) | Logoff |
| `registerPasskey()` | Account Change (3002) | Create |
| `deletePasskey()` | Account Change (3002) | Delete |

Severity levels: Informational (success), Low (cancelled), Medium (auth failure), High (CSRF failure), Critical (account lockout).

### Server-Side (Rust Backend)

OCSF events emitted via `tracing::info!(target: "ocsf", ...)` as JSON strings:

| Route | Event | Severity |
|-------|-------|----------|
| `POST /auth/session` | Session created / verification failed | Info / Medium |
| `GET /auth/callback` | OAuth exchange success / failure | Info / High |
| `POST /auth/refresh` | Refresh success / failure | Info / Medium |
| `POST /auth/logout` | User logged out | Info |
| `POST /auth/authorize` | Cedar permit / deny / error | Info / Medium / High |

Filter in CloudWatch Logs Insights:
```sql
fields @timestamp, @message
| filter @message like /ocsf/
| sort @timestamp desc
```

### SIEM Integration

Events are already OCSF-formatted. For AWS Security Lake, send to a Kinesis Data Firehose. For Splunk, POST to HEC with `sourcetype: 'ocsf:authentication'`. For CloudWatch, log as structured JSON.

Logger errors are silently caught — a logging failure never breaks authentication.

## Hardening Checklist

### All Deployments
- HTTPS everywhere
- Nonce-based CSP
- Security headers (see above)
- Short token expiry (15-30 min access tokens)
- OCSF logging enabled

### Public Applications
- Remove unnecessary third-party scripts
- Token usage monitoring
- Regular dependency audits

### High-Assurance (Healthcare/Finance)
- Passkey-only (disable password fallback)
- `REQUIRE_DEVICE_BOUND=true`
- `AAGUID_ALLOWLIST` restricted to approved hardware
- Full API proxy (beyond Token Handler)
- Regular penetration testing
