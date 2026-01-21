# Upgrade Prompt for Claude Code

Copy and paste this prompt to another Claude Code instance to help upgrade a site to l42-cognito-passkey v0.4.0.

---

## Prompt

```
Upgrade this site to l42-cognito-passkey v0.4.0. Here are the breaking changes and new features:

## Files to Replace

Download from: https://github.com/lexicone42/l42-cognito-passkey

Replace:
- `auth.js` → your auth directory (VERSION should show '0.4.0')
- `rbac-roles.js` → if using RBAC features

## Breaking Changes

### 1. decodeJwtPayload → UNSAFE_decodeJwtPayload

OLD (still works but warns):
```javascript
const claims = auth.decodeJwtPayload(token);
```

NEW:
```javascript
const claims = auth.UNSAFE_decodeJwtPayload(token);
```

Search for: `decodeJwtPayload` and `parseJwt` - both deprecated.

### 2. Role Checks Should Use New Helpers

If using rbac-roles.js, update group checks:

OLD:
```javascript
if (groups.includes('admin') || groups.includes('admins')) { ... }
```

NEW:
```javascript
import { isInCognitoGroup } from './rbac-roles.js';
if (isInCognitoGroup(groups, 'ADMIN')) { ... }  // handles aliases
```

## New Security Features (Optional but Recommended)

### Server-Side Authorization Helper

For protected actions, add server validation:
```javascript
const result = await auth.requireServerAuthorization('action-name', {
    endpoint: '/api/authorize',  // your auth endpoint
    context: { resourceId: '123' }
});
if (!result.authorized) {
    throw new Error(result.reason);
}
```

### UI-Only Role Check

For showing/hiding UI elements (NOT authorization):
```javascript
if (auth.UI_ONLY_hasRole('admin')) {
    showAdminButton();  // UI only, not security!
}
```

## Verification Steps

1. Check version: `console.log(auth.VERSION)` → should be '0.4.0'
2. Test login flow works
3. Check browser console for deprecation warnings
4. Fix any `decodeJwtPayload` or `parseJwt` calls
5. Test role-based UI still works

## ccTLD Cookie Fix

If your domain is `.co.uk`, `.com.au`, etc., cookies now work correctly.
Previously broken, now auto-detected. No action needed unless you had a workaround.

---

Search the codebase for these patterns and update:
- `decodeJwtPayload(`
- `parseJwt(`
- `.includes('admin')` or similar role checks
- Any hardcoded Cognito group name checks

Report what you find and I'll help update each occurrence.
```

---

## Even Shorter Version

```
Upgrade to l42-cognito-passkey v0.4.0:

1. Replace auth.js (VERSION='0.4.0')
2. Search/replace: `decodeJwtPayload(` → `UNSAFE_decodeJwtPayload(`
3. Search/replace: `parseJwt(` → `UNSAFE_decodeJwtPayload(`
4. If using rbac-roles.js, replace it and use `isInCognitoGroup(groups, 'ADMIN')` instead of `groups.includes('admin')`

New optional features:
- `requireServerAuthorization()` - enforced server-side auth checks
- `UI_ONLY_hasRole()` - explicit UI-only role checks

Verify: `console.log(auth.VERSION)` should show '0.4.0'
Test login flow works. Check console for deprecation warnings.
```
