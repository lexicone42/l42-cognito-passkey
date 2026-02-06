# Upgrade Prompt for Claude Code

Copy and paste this prompt to another Claude Code instance to help upgrade a site to l42-cognito-passkey v0.10.0.

---

## Prompt

```
Upgrade this site to l42-cognito-passkey v0.10.0. Here are the breaking changes and new features:

## Files to Replace

Download from: https://github.com/lexicone42/l42-cognito-passkey

Replace:
- `auth.js` → your auth directory (VERSION should show '0.10.0')
- `rbac-roles.js` → if using RBAC features

## Breaking Changes

### 1. Removed Functions

These functions no longer exist:

| Removed | Use Instead |
|---------|-------------|
| `getTokensAsync()` | `await getTokens()` |
| `decodeJwtPayload(token)` | `UNSAFE_decodeJwtPayload(token)` |
| `parseJwt(token)` | `UNSAFE_decodeJwtPayload(token)` |
| `createAuthenticatedWebSocket()` | `ensureValidTokens()` + manual WebSocket |

### 2. Trimmed RBAC Roles

Healthcare, Education, SaaS, E-commerce, API, and Org roles removed from rbac-roles.js.
Still available: admin, readonly, user, editor, reviewer, publisher, moderator, developer.

### 3. Role Checks Should Use Helpers

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
    endpoint: '/api/authorize',
    context: { resourceId: '123' }
});
if (!result.authorized) {
    throw new Error(result.reason);
}
```

## Verification Steps

1. Check version: `console.log(auth.VERSION)` → should be '0.10.0'
2. Test login flow works
3. Search for removed function calls (see table above)
4. Test role-based UI still works

---

Search the codebase for these patterns and update:
- `getTokensAsync(`
- `decodeJwtPayload(`
- `parseJwt(`
- `createAuthenticatedWebSocket(`
- `.includes('admin')` or similar role checks
- Any hardcoded Cognito group name checks

Report what you find and I'll help update each occurrence.
```

---

## Even Shorter Version

```
Upgrade to l42-cognito-passkey v0.10.0:

1. Replace auth.js (VERSION='0.10.0')
2. Search/replace: `decodeJwtPayload(` → `UNSAFE_decodeJwtPayload(`
3. Search/replace: `parseJwt(` → `UNSAFE_decodeJwtPayload(`
4. Replace: `getTokensAsync()` → `await getTokens()`
5. Remove: any `createAuthenticatedWebSocket` usage
6. If using rbac-roles.js, replace it and use `isInCognitoGroup(groups, 'ADMIN')` instead of `groups.includes('admin')`

Verify: `console.log(auth.VERSION)` should show '0.10.0'
Test login flow works.
```
