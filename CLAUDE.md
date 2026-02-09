# L42 Cognito Passkey - Claude Code Integration Guide

## Project Overview

L42 Cognito Passkey is a **self-hosted JavaScript authentication library** for AWS Cognito with WebAuthn/Passkey support. It's designed to be copied into projects (no CDN dependency) and used as an ES module.

**Current Version**: 0.13.0
**License**: Apache-2.0
**Tests**: ~649 (including 53 property-based tests + 33 token storage tests + 50 handler mode tests + 35 auto-refresh tests + 34 debug diagnostics tests + 32 conditional UI tests + 23 conditional create tests + 31 token validation tests + 22 WebAuthn capabilities tests + 40 login rate limiting tests + 101 Cedar authorization tests)

## Quick Start for Claude Instances

### Installing in a Project

```bash
# From GitHub (recommended for now)
pnpm add github:lexicone42/l42-cognito-passkey

# Or copy directly
cp /path/to/l42cognitopasskey/src/auth.js ./public/auth/auth.js
```

### Key Commands

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run specific test file
pnpm test -- plugin/templates/rbac-roles.property.test.js

# Check version consistency
pnpm test -- plugin/templates/version-consistency.test.js
```

### Release Commands (Maintainers)

```bash
pnpm release:patch    # Bug fixes: 0.5.1 → 0.5.2
pnpm release:minor    # New features: 0.5.1 → 0.6.0
pnpm release:major    # Breaking changes: 0.5.1 → 1.0.0
```

## Key Files

| File | Purpose |
|------|---------|
| `src/auth.js` | Main authentication library (~1400 lines) |
| `plugin/templates/rbac-roles.js` | RBAC role definitions and permission helpers |
| `plugin/templates/static-site-pattern.html` | Static site integration template |
| `plugin/templates/admin-panel-pattern.html` | Admin panel template |
| `plugin/templates/handler-token-store.test.js` | Token Handler mode tests |
| `examples/backends/express/` | Token Handler Express backend |
| `docs/handler-mode.md` | Token Handler mode documentation |
| `scripts/sync-version.js` | Syncs version across all files |
| `docs/RELEASING.md` | Release process documentation |
| `plugin/templates/debug-diagnostics.test.js` | Debug logging & diagnostics tests |
| `plugin/templates/conditional-ui.test.js` | Conditional UI / passkey autofill tests |
| `plugin/templates/conditional-create.test.js` | Conditional create / passkey upgrade tests |
| `plugin/templates/token-validation.test.js` | Token validation on load tests |
| `plugin/templates/webauthn-capabilities.test.js` | WebAuthn Level 3 capabilities tests |
| `plugin/templates/login-rate-limiting.test.js` | Login rate limiting tests |
| `plugin/templates/cedar-authorization.test.js` | Cedar policy authorization tests |
| `examples/backends/express/cedar-engine.js` | Cedar WASM engine wrapper |
| `examples/backends/express/cedar/` | Cedar schema and policy files |
| `docs/cedar-integration.md` | Cedar integration documentation |

## Security Patterns (CRITICAL)

### Client-Side RBAC is for UI ONLY

```javascript
// WRONG - Client-side check for authorization
if (auth.isAdmin()) {
    deleteUser(userId);  // NEVER DO THIS
}

// CORRECT - Server validates authorization
const result = await auth.requireServerAuthorization('admin:delete-user', {
    context: { targetUserId: userId }
});
if (result.authorized) {
    deleteUser(userId);
}
```

### JWT Claims are UNTRUSTED

```javascript
// The UNSAFE_ prefix reminds developers this data is untrusted
const claims = auth.UNSAFE_decodeJwtPayload(token);
// Use ONLY for display purposes, never for authorization
userNameDisplay.textContent = claims.email;
```

### XSS Prevention

```javascript
// SAFE - always use textContent
element.textContent = userInput;

// DANGEROUS - never use dynamic HTML with user data
```

## Token Storage Modes (v0.8.0)

Three storage modes are available:

| Mode | Security | Persistence | Use Case |
|------|----------|-------------|----------|
| `localStorage` | XSS-accessible | Yes | Default, simple apps |
| `memory` | Not in storage | No | Session-only use |
| `handler` | HttpOnly session | Yes | Maximum security |

### Token Handler Mode (Recommended for Production)

Handler mode stores tokens server-side in HttpOnly cookies, making them inaccessible to XSS:

```javascript
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    oauthCallbackUrl: '/auth/callback'  // Optional
});

// In handler mode, getTokens() returns a Promise
const tokens = await getTokens();
```

**Key points:**
- Requires a backend (see `examples/backends/express/`)
- `await getTokens()` works in ALL modes (safe migration)
- `isAuthenticated()` stays sync (uses cache)
- `logout()` calls server endpoint

See `docs/handler-mode.md` for complete documentation.

## RBAC System

### Cognito Group Checking

Use `isInCognitoGroup()` for consistent group checking with alias support:

```javascript
import { isInCognitoGroup, isInAnyCognitoGroup } from './rbac-roles.js';

const groups = auth.getUserGroups();

// Handles aliases: 'admin', 'admins', 'administrators'
if (isInCognitoGroup(groups, 'ADMIN')) {
    // User is admin
}

// Check multiple groups
if (isInAnyCognitoGroup(groups, ['ADMIN', 'EDITOR', 'PUBLISHER'])) {
    // User has content management access
}
```

### Available Group Keys

```javascript
COGNITO_GROUPS = {
    ADMIN, READONLY, USER, EDITOR, REVIEWER, PUBLISHER,
    MODERATOR, DEVELOPER
}
```

### Permission Format

- `read:content` - Read content
- `write:own` - Write own resources
- `api:*` - All API permissions
- `*` - Admin wildcard (all permissions)

## Integration Patterns

### Static Site Pattern
```
site.domain/           → Public (CDN-cached)
site.domain/auth/      → Protected (requires login)
site.domain/admin/     → Admin (editor/publisher roles)
```

## Adding a New Role

1. Add to `STANDARD_ROLES` in `rbac-roles.js`:
```javascript
newRole: {
    name: 'new_role',
    displayName: 'New Role',
    description: 'Description here',
    level: 35,  // Between existing levels
    permissions: ['read:content', 'write:own'],
    cognitoGroup: 'new-roles',
    pattern: 'your-pattern'
}
```

2. Add alias mapping in `COGNITO_GROUPS`:
```javascript
NEW_ROLE: { canonical: 'new-roles', aliases: ['new-role', 'new-roles'] }
```

3. Create Cognito User Pool Group with the canonical name.

## Cookie Domain Handling

The library handles ccTLDs (country-code TLDs) correctly:
- `app.example.com` → `.example.com`
- `app.example.co.uk` → `.example.co.uk` (3-part domain preserved)

For custom domain handling:
```javascript
configure({
    cookieDomain: '.yourdomain.com'
});
```

## Debug & Diagnostics (v0.11.0)

Enable debug logging to diagnose auth issues:

```javascript
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    debug: true  // or 'verbose' or function(event)
});

// Get current auth state snapshot (works even without debug mode)
console.table(getDiagnostics());

// View last 100 debug events
console.log(getDebugHistory());

// Clear debug buffer
clearDebugHistory();
```

## Troubleshooting

### "Auth not configured" Error
```javascript
// Option 1: Explicit configure
configure({ clientId: 'xxx', cognitoDomain: 'xxx.auth.region.amazoncognito.com' });

// Option 2: Global config
window.L42_AUTH_CONFIG = { clientId: 'xxx', domain: 'xxx' };
```

### Group Check Failing
```javascript
// May fail if Cognito uses 'admins' but you check 'admin'
groups.includes('admin')

// Handles all aliases - use this instead
isInCognitoGroup(groups, 'ADMIN')
```

## Development Workflow

### Before Committing
1. Run tests: `pnpm test`
2. Check version consistency: `pnpm test -- version-consistency`
3. Review security patterns in templates

### Property-Based Tests
The RBAC system has 22 property-based tests using fast-check:
- Role hierarchy transitivity
- Admin supremacy
- Permission inheritance
- Cognito group alias consistency

## Upgrade Notes

### v0.5.4 (Dist Sync)

**If you're using dist/auth.js, update now** - v0.5.3's dist file was not synced with src.

v0.5.4 includes all fixes from v0.5.2 and v0.5.3 in both src/ and dist/.

### v0.5.3 (Bug Fix)

**OAuth state now uses localStorage instead of sessionStorage**

This fixes the "Invalid OAuth state - possible CSRF attack" error that occurred with Safari ITP and Firefox ETP during cross-domain OAuth redirects.

No code changes required - this is a transparent fix. If you previously implemented workarounds, you can remove them.

### v0.5.2 (Security Release)

**`loginWithHostedUI()` is now async**

```javascript
// Before (still works - redirect happens before promise resolves)
loginWithHostedUI(email);

// After (recommended for clarity)
await loginWithHostedUI(email);
```

The function now generates a PKCE code challenge before redirecting. Since the redirect happens immediately, existing synchronous calls will continue to work, but TypeScript/ESLint may flag the unhandled promise.

**New validations that may break existing configs:**
- `redirectUri` must use HTTPS (except localhost)
- `cognitoDomain` format is now validated

### v0.10.0 (Cleanup)

**Removed exports:** `getTokensAsync()`, `decodeJwtPayload()`, `parseJwt()`, `createAuthenticatedWebSocket()`.

**Trimmed RBAC:** Healthcare, Education, SaaS, E-commerce, API, Org roles removed from `rbac-roles.js`.

See `docs/migration.md` for the complete migration guide covering all versions.

## Cedar Authorization (v0.13.0)

Server-side Cedar policy authorization for handler mode. Replaces manual role checks with declarative `.cedar` policy evaluation.

```javascript
// Server-side: cedar-engine.js wraps @cedar-policy/cedar-wasm
import { initCedarEngine, authorize } from './cedar-engine.js';
await initCedarEngine({
    schemaPath: './cedar/schema.cedarschema.json',
    policyDir: './cedar/policies/'
});

// Per-request evaluation (<0.1ms with pre-parsed policies)
const result = await authorize({
    session: req.session,
    action: 'admin:delete-user',
    resource: { id: 'doc-123', owner: 'user-sub' }
});
```

Key features:
- 9 policy files mapping all RBAC roles to Cedar policies
- Ownership enforcement via `forbid` policies
- Cognito group alias resolution (mirrors `rbac-roles.js`)
- EntityProvider interface for future persistent entity stores
- Fail-closed: returns 503 if Cedar unavailable

See `docs/cedar-integration.md` for complete documentation.

## Future Plans

- **Semgrep Rules** - Security scanning (post-1.0)
- **Persistent Entity Store** - DynamoDB/Redis entity provider for Cedar (post-1.0)

## Submitting Feedback

If integrating this library into a project and encountering issues:

1. Open a GitHub issue using the "Integration Feedback" template
2. Include: what worked, what didn't, error messages
3. Tag with `integration-feedback`

See `docs/integration-feedback.md` for the quick checklist.

## Claude-to-Claude Workflow

For Claude Code instances integrating this library:

**Reporting Issues:**
```bash
gh issue create --repo lexicone42/l42-cognito-passkey \
  --title "bug: Brief description" \
  --label "bug"
```

**Processing Issues (Maintainers):**
```bash
pnpm process-issue <number>
cat .claude/issues/issue-<number>.md
```

See `docs/claude-workflow.md` for the complete workflow.
