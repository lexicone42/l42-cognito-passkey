# Migration Guide

Complete migration guide for l42-cognito-passkey version upgrades.

## Version Summary

| From | To | Key Changes |
|------|-----|-------------|
| v0.3.x | v0.4.0 | `UNSAFE_` prefix for JWT decode, RBAC helpers |
| v0.4.x | v0.5.2 | PKCE, HTTPS enforcement, async `loginWithHostedUI()` |
| v0.5.2 | v0.5.3 | localStorage for OAuth state (Safari/Firefox fix) |
| v0.5.3 | v0.5.4+ | Dist file sync fix, CI safeguards |

---

## v0.4.x → v0.5.2+ (Security Release)

### loginWithHostedUI() is Now Async

The function now generates a PKCE code challenge before redirecting:

```javascript
// Before (still works - redirect happens before promise resolves)
loginWithHostedUI(email);

// After (recommended for clarity)
await loginWithHostedUI(email);
```

Since the redirect happens immediately, existing synchronous calls will continue to work, but TypeScript/ESLint may flag the unhandled promise.

### New Validations

These may break existing configs if they were misconfigured:

1. **`redirectUri` must use HTTPS** (except localhost for development)
2. **`cognitoDomain` format is validated** to prevent open redirects

```javascript
// Valid
configure({
    redirectUri: 'https://app.example.com/callback',  // HTTPS required
    cognitoDomain: 'myapp.auth.us-west-2.amazoncognito.com'  // Valid format
});

// Invalid - will throw
configure({
    redirectUri: 'http://app.example.com/callback',  // HTTP not allowed
    cognitoDomain: 'https://evil.com'  // Invalid format
});
```

### No Action Required

The following changes are transparent:
- **PKCE** is automatically handled
- **OAuth state** now uses localStorage (fixes Safari ITP / Firefox ETP issues)
- **dist/auth.js** is kept in sync via pre-commit hook

---

## v0.3.x → v0.4.0

### decodeJwtPayload() Renamed

The function has been renamed to `UNSAFE_decodeJwtPayload()` to clearly indicate that it returns **unverified claims**.

```javascript
// Before (still works, emits deprecation warning)
const claims = auth.decodeJwtPayload(token);

// After (recommended)
const claims = auth.UNSAFE_decodeJwtPayload(token);
```

**Why?** This prevents developers from accidentally using JWT claims for authorization decisions. The `UNSAFE_` prefix reminds you that these claims are for display purposes only.

**Search patterns to find usage:**
```bash
grep -r "decodeJwtPayload(" src/
grep -r "parseJwt(" src/
```

### New RBAC Helpers

If using `rbac-roles.js`, update group checks:

```javascript
// Before (fragile - breaks if Cognito group is named 'admins')
if (groups.includes('admin') || groups.includes('admins')) { ... }

// After (handles all aliases)
import { isInCognitoGroup } from './rbac-roles.js';
if (isInCognitoGroup(groups, 'ADMIN')) { ... }
```

### New Security Functions

**Server-Side Authorization Helper:**

```javascript
// For protected actions, enforce server validation
const result = await auth.requireServerAuthorization('admin:delete-user', {
    endpoint: '/api/authorize',
    context: { resourceId: '123' }
});
if (!result.authorized) {
    throw new Error(result.reason);
}
```

**UI-Only Role Check:**

```javascript
// For showing/hiding UI elements (NOT authorization)
if (auth.UI_ONLY_hasRole('admin')) {
    showAdminButton();  // UI only, not security!
}
```

### ccTLD Cookie Fix

Cookies now work correctly for country-code TLDs:
- `.co.uk`, `.com.au`, etc. are properly handled
- No action needed unless you had a workaround

---

## Verification Steps

After upgrading:

1. **Check version:**
   ```javascript
   console.log(auth.VERSION);  // Should show current version
   ```

2. **Test login flow** works end-to-end

3. **Check browser console** for deprecation warnings

4. **Run tests** if you have integration tests:
   ```bash
   pnpm test
   ```

---

## Upgrade Prompt for Claude Code Instances

For a quick upgrade prompt to paste into another Claude Code instance, see [upgrade-prompt.md](./upgrade-prompt.md).
