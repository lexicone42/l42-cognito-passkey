# L42 Cognito Passkey - Claude Code Integration Guide

## Project Overview

L42 Cognito Passkey is a **self-hosted JavaScript authentication library** for AWS Cognito with WebAuthn/Passkey support. It's designed to be copied into projects (no CDN dependency) and used as an ES module.

**Version**: 0.4.0  
**License**: Apache-2.0

## Quick Reference

### Key Files

| File | Purpose |
|------|---------|
| `src/auth.js` | Main authentication library (~900 lines) |
| `plugin/templates/rbac-roles.js` | RBAC role definitions and permission helpers |
| `plugin/templates/static-site-pattern.html` | Static site integration template |
| `plugin/templates/wasm-multiuser-pattern.html` | Multi-user WASM app template |

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run specific test file
npx vitest run plugin/templates/rbac-roles.property.test.js
```

## Security Considerations

### ⚠️ Critical Security Patterns

1. **NEVER use client-side RBAC for authorization**
   ```javascript
   // ❌ WRONG - Client-side check only
   if (auth.isAdmin()) {
       deleteUser(userId);
   }
   
   // ✅ CORRECT - Server-side validation
   const result = await auth.requireServerAuthorization('admin:delete-user', {
       context: { targetUserId: userId }
   });
   if (result.authorized) {
       deleteUser(userId);
   }
   ```

2. **Use UNSAFE_decodeJwtPayload() name to acknowledge untrusted data**
   ```javascript
   // The UNSAFE_ prefix reminds developers this is untrusted
   const claims = auth.UNSAFE_decodeJwtPayload(token);
   // Use ONLY for display purposes, never for authorization
   ```

3. **XSS Prevention - Always use textContent**
   ```javascript
   // ✅ SAFE
   element.textContent = userInput;
   
   // ❌ DANGEROUS
   element.innerHTML = userInput;
   ```

### Cookie Domain Handling

The library handles ccTLDs (country-code TLDs) correctly:
- `app.example.com` → `.example.com`
- `app.example.co.uk` → `.example.co.uk` (3-part domain)

If you need custom domain handling, configure explicitly:
```javascript
configure({
    cookieDomain: '.yourdomain.com'
});
```

## RBAC System

### Cognito Group Names

Use `isInCognitoGroup()` for consistent group checking with alias support:

```javascript
import { isInCognitoGroup, COGNITO_GROUPS } from './rbac-roles.js';

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
    PLAYER, DM, MODERATOR, DEVELOPER, ANALYST, AUDITOR,
    SUPPORT, BILLING
}
```

### Permission Format

Permissions follow `action:resource` format:
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

### Multi-User WASM Pattern

```
Role Hierarchy:
player (10) < moderator (30) < dm (50) < admin (100)
```

## Common Tasks

### Adding a New Role

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

### Implementing Server-Side Authorization

Your server endpoint at `/api/authorize` should:

```javascript
// Express example
app.post('/api/authorize', async (req, res) => {
    const { action, context } = req.body;
    const token = req.headers.authorization?.split(' ')[1];
    
    // Verify JWT with AWS Cognito
    const claims = await verifyCognitoToken(token);
    if (!claims) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    // Check permissions based on groups
    const groups = claims['cognito:groups'] || [];
    const authorized = checkPermission(groups, action, context);
    
    res.json({ authorized, reason: authorized ? null : 'Insufficient permissions' });
});
```

## Development Workflow

### Before Committing

1. Run tests: `npm test`
2. Check for security issues in templates (XSS, innerHTML usage)
3. Ensure Cognito group constants are synchronized

### Property-Based Tests

The RBAC system has property-based tests in `rbac-roles.property.test.js`:
- Role hierarchy transitivity
- Admin supremacy
- Permission inheritance
- Cognito group alias consistency

Install fast-check if needed:
```bash
npm install --save-dev fast-check
```

## AWS Cedar Integration (Future)

Cedar is AWS's policy language for fine-grained authorization. Potential integration:

```cedar
// Example Cedar policy
permit(
    principal in Group::"editors",
    action == Action::"publish",
    resource in Folder::"content"
);
```

See `docs/cedar-integration.md` for future plans.

## Troubleshooting

### "Auth not configured" Error

```javascript
// Option 1: Explicit configure
configure({ clientId: 'xxx', cognitoDomain: 'xxx.auth.region.amazoncognito.com' });

// Option 2: Global config
window.L42_AUTH_CONFIG = { clientId: 'xxx', domain: 'xxx' };
```

### Cookie Not Set for ccTLD

For domains like `.co.uk`, `.com.au`:
```javascript
configure({ cookieDomain: '.yoursite.co.uk' });
```

### Group Check Failing

Use `isInCognitoGroup()` instead of direct array includes to handle aliases:
```javascript
// ❌ May fail if Cognito uses 'admins' but you check 'admin'
groups.includes('admin')

// ✅ Handles all aliases
isInCognitoGroup(groups, 'ADMIN')
```
