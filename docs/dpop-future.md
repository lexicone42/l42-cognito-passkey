# DPoP Integration Plan

**Status:** Waiting for AWS Cognito support
**Last Updated:** January 2026

---

## What is DPoP?

**DPoP (Demonstrating Proof-of-Possession)** is an OAuth 2.0 extension (RFC 9449) that binds access tokens to a client's cryptographic keypair. Even if a token is stolen, it cannot be used without the corresponding private key.

---

## Why We're Not Using DPoP Yet

**AWS Cognito does not support DPoP as of January 2026.**

We've verified this through:
- AWS Cognito documentation review
- OAuth2/token endpoint testing
- AWS feature request tracking

When Cognito adds DPoP support, this library will implement it as the **most secure** token protection option.

---

## How DPoP Works

### Without DPoP (Current)

```
Attacker steals token → Attacker uses token → Access granted ❌
```

### With DPoP (Future)

```
1. Client generates keypair (public + private)
2. Client sends public key to authorization server
3. Token is bound to that public key
4. Every request includes a DPoP proof (signed with private key)
5. Server verifies: token + proof signature

Attacker steals token → Attacker cannot generate proof → Access denied ✓
```

### Technical Flow

```
┌────────────────────────────────────────────────────────────────┐
│                        DPoP Authentication                      │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Client generates keypair                                    │
│     const keypair = await crypto.subtle.generateKey(...)        │
│                                                                 │
│  2. Token request includes DPoP proof                           │
│     POST /oauth2/token                                          │
│     DPoP: eyJ... (JWT signed with private key)                  │
│                                                                 │
│  3. Server binds token to public key                            │
│     { "cnf": { "jkt": "sha256-thumbprint-of-public-key" } }     │
│                                                                 │
│  4. API requests include proof                                  │
│     GET /api/resource                                           │
│     Authorization: DPoP eyJ...access_token...                   │
│     DPoP: eyJ... (new proof for this request)                   │
│                                                                 │
│  5. Server validates                                            │
│     - Token's jkt matches proof's public key                    │
│     - Proof is signed correctly                                 │
│     - Proof matches request (method, URI, timestamp)            │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

---

## Integration Plan When Available

### Phase 1: Detection

When Cognito announces DPoP support, we'll verify by testing:

```javascript
// Test if Cognito accepts DPoP proofs
const response = await fetch(`https://${domain}/oauth2/token`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'DPoP': dpopProof
    },
    body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: authCode,
        dpop_jkt: publicKeyThumbprint
    })
});
```

### Phase 2: Implementation

Add to auth.js:

```javascript
// New config option
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    useDPoP: true  // Enable DPoP when available
});

// Internal: Generate and store keypair
async function initDPoP() {
    const keypair = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,  // not extractable (security)
        ['sign', 'verify']
    );

    // Store in IndexedDB (more secure than localStorage for keys)
    await storeKeyPair(keypair);
    return keypair;
}

// Internal: Create DPoP proof for each request
async function createDPoPProof(method, uri) {
    const keypair = await getKeyPair();

    const header = {
        typ: 'dpop+jwt',
        alg: 'RS256',
        jwk: await exportPublicKey(keypair.publicKey)
    };

    const payload = {
        jti: crypto.randomUUID(),
        htm: method,
        htu: uri,
        iat: Math.floor(Date.now() / 1000)
    };

    return signJWT(header, payload, keypair.privateKey);
}

// Modified: Token exchange with DPoP
async function exchangeCodeForTokens(code, state) {
    // ... existing validation ...

    const dpopProof = await createDPoPProof('POST', tokenEndpoint);

    const res = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'DPoP': dpopProof
        },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: config.clientId,
            code,
            redirect_uri: getRedirectUri(),
            code_verifier: codeVerifier
        })
    });

    // Token will be DPoP-bound
    // ...
}

// New: Make API calls with DPoP proof
export async function fetchWithDPoP(url, options = {}) {
    const tokens = await ensureValidTokens();
    const proof = await createDPoPProof(options.method || 'GET', url);

    return fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `DPoP ${tokens.access_token}`,
            'DPoP': proof
        }
    });
}
```

### Phase 3: Key Management

```javascript
// Store keypair securely in IndexedDB
async function storeKeyPair(keypair) {
    const db = await openDB('l42-auth-keys', 1, {
        upgrade(db) {
            db.createObjectStore('keys');
        }
    });

    await db.put('keys', keypair, 'dpop-keypair');
}

// Retrieve keypair
async function getKeyPair() {
    const db = await openDB('l42-auth-keys', 1);
    return db.get('keys', 'dpop-keypair');
}

// Key rotation (recommended every 24 hours)
async function rotateKeyPair() {
    const newKeypair = await initDPoP();
    // Next token refresh will use new key
    // Old tokens remain valid until expiry
}
```

---

## Security Benefits

| Attack | Without DPoP | With DPoP |
|--------|--------------|-----------|
| Token theft via XSS | Token usable | Token unusable (no private key) |
| Token theft via network | Token usable | Token unusable |
| Token replay | Works | Fails (proof tied to request) |
| Session hijacking | Possible | Prevented |

---

## Compatibility Matrix

| Provider | DPoP Support | Status |
|----------|--------------|--------|
| AWS Cognito | ❌ No | Waiting |
| Okta | ✅ Yes | Available |
| Auth0 | ✅ Yes | Available |
| Azure AD | ✅ Yes | Available |
| Keycloak | ✅ Yes | Available |

---

## Monitoring for Cognito DPoP Support

Check these sources for updates:

1. **AWS What's New**: https://aws.amazon.com/new/
2. **Cognito Release Notes**: https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-release-notes.html
3. **AWS Re:Invent announcements**: Annual (November/December)
4. **GitHub Issues**: Track feature requests

---

## Interim Recommendation

Until DPoP is available:

1. **Use Token Handler mode** (see `v1-token-storage-proposal.md`)
   - [#4 - v0.7.0: Memory mode](https://github.com/lexicone42/l42-cognito-passkey/issues/4)
   - [#5 - v0.8.0: Handler mode](https://github.com/lexicone42/l42-cognito-passkey/issues/5)
   - [#6 - v0.9.0: Production ready](https://github.com/lexicone42/l42-cognito-passkey/issues/6)
2. **Implement strict CSP** with nonces
3. **Enable OCSF logging** for token usage monitoring
4. **Use short token expiry** (15-30 minutes)

These provide defense-in-depth while we wait for DPoP support.

---

## References

- [RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession](https://datatracker.ietf.org/doc/html/rfc9449)
- [DPoP Explained (Okta)](https://developer.okta.com/blog/2024/09/05/dpop-oauth)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
