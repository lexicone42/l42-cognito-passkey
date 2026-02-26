# Releases & Migration

Release process and version upgrade guide.

## Current Version

**0.20.0** — 733 vitest + 157 cargo tests

## Release Process

### Commands

```bash
pnpm release:patch    # Bug fix:  0.20.0 → 0.20.1
pnpm release:minor    # Feature:  0.20.0 → 0.21.0
pnpm release:major    # Breaking: 0.20.0 → 1.0.0
```

### What Happens

1. **`preversion`** — Runs tests, checks dist sync, validates docs
2. **`version`** — `sync-version.js` updates 11 files, `sync-test-counts.js` updates 4 files, copies dist
3. **`postversion`** — Pushes tags, creates GitHub release from CHANGELOG.md

### Before Releasing

1. Update `CHANGELOG.md`
2. `pnpm test`
3. `pnpm sync-counts`
4. `pnpm validate-docs`

### Version Sync

`scripts/sync-version.js` updates: `src/auth.js`, `dist/auth.js`, `plugin/plugin.json`, `plugin/CLAUDE.md`, `CLAUDE.md`, `docs/api-reference.md`, `docs/architecture.md`, `README.md`.

`scripts/sync-test-counts.js` updates per-file and total counts in `CLAUDE.md`, `plugin/CLAUDE.md`, `docs/architecture.md`, `docs/release.md`.

### Manual Release

If automation fails:

```bash
# Edit package.json version
node scripts/sync-version.js
cp src/auth.js dist/auth.js && cp src/auth.d.ts dist/auth.d.ts
git add -A && git commit -m "v0.20.0" && git tag -a v0.20.0 -m "v0.20.0"
git push origin main --tags
node scripts/create-release.js
```

## Migration Guide

### Upgrading to Handler Mode (from pre-0.15.0)

Handler mode is the only supported token storage. If upgrading from an older version:

1. Deploy a backend (Rust recommended, Express alternative)
2. Update configuration:
   ```javascript
   configure({
       clientId: 'xxx',
       cognitoDomain: 'xxx.auth.region.amazoncognito.com',
       tokenEndpoint: '/auth/token',
       refreshEndpoint: '/auth/refresh',
       logoutEndpoint: '/auth/logout',
       sessionEndpoint: '/auth/session'
   });
   ```
3. Add `await` to all `getTokens()` calls
4. Test end-to-end

### Breaking Changes by Version

**v0.15.0** — `localStorage` and `memory` storage modes removed. `tokenStorage: 'handler'` is the only option. `sessionEndpoint` config added for passkey/password session persistence.

**v0.14.0** — `localStorage` and `memory` modes deprecated with console warnings.

**v0.13.0** — Cedar authorization added. `requireServerAuthorization()` default endpoint changed from `/api/authorize` to `/auth/authorize`. Server-side only; no client code changes needed unless you used a custom endpoint.

**v0.10.0** — Removed exports: `getTokensAsync()` → use `await getTokens()`. `decodeJwtPayload()` → `UNSAFE_decodeJwtPayload()`. `parseJwt()` → `UNSAFE_decodeJwtPayload()`. `createAuthenticatedWebSocket()` removed. Domain-specific RBAC roles removed from `rbac-roles.js` (healthcare, education, SaaS, etc.).

**v0.6.0** — `exchangeCodeForTokens()` sets `auth_method: 'oauth'` instead of `'passkey'`.

**v0.5.7** — `onAuthStateChange` no longer fires on token refresh (prevents reload loops).

**v0.5.2** — `loginWithHostedUI()` became async (PKCE). `redirectUri` requires HTTPS. `cognitoDomain` format validated.

**v0.4.0** — `decodeJwtPayload()` renamed to `UNSAFE_decodeJwtPayload()`.

### Verification After Upgrade

```bash
pnpm test
```

```javascript
console.log(auth.VERSION);  // Check version
```

## v1.0 Readiness

The v1.0 security hardening (completed in v0.19.0) addressed:

- **S2 fixed**: `validateTokenClaims()` now requires `aud`/`client_id` and `exp`
- **SESSION_SECRET required**: Rust backend fails startup without it
- **clientDataJSON origin validation** in credential verification
- **Refresh token rotation**: Rust backend preserves rotated tokens
- **OCSF coverage**: Events on all server routes
- **PKCE property tests**: 10 tests for code verifier/challenge invariants
- **Credential property tests**: 13 tests for AAGUID/device-bound validation
- **Cedar forbid composition tests**: 3 property tests
- **CALLBACK_ALLOWED_ORIGINS**: Validates `X-Forwarded-Host` when multi-origin enabled
- **Startup security warnings**: HTTPS_ONLY mismatch detection

### Remaining for v1.0

- TypeScript definitions sync (`auth.d.ts`)
- Final documentation consolidation

### Post-v1.0 Roadmap

- EntityProvider for trusted ownership (closes S1 gap)
- FIDO MDS integration (AAGUID → authenticator metadata)
- Semgrep rules for integration feedback
- CDK stack for Rust Lambda deployment
