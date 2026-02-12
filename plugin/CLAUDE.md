# L42 Cognito Passkey Plugin

This plugin provides quick setup for AWS Cognito authentication with WebAuthn passkey support.

**Plugin Name**: `l42-cognito-passkey`
**Current Version**: 0.16.0
**Tests**: 658 passing

## Overview

The l42-cognito-passkey system provides:
- **Password + Passkey authentication** via AWS Cognito
- **OAuth2 CSRF protection** with state parameter
- **RBAC** using Cognito groups (admin, readonly, etc.)
- **Token management** with automatic refresh
- **Self-hosted** - copy auth.js to your project (no CDN dependency)

## Self-Hosted Design

**This library is designed to be self-hosted.** Copy `src/auth.js` to your project's static files.

```bash
# Example: Copy to your project
cp /path/to/l42cognitopasskey/src/auth.js ./public/auth/auth.js
```

Then import locally:
```javascript
import { configure, isAuthenticated } from '/auth/auth.js';

configure({
    clientId: 'your-client-id',
    cognitoDomain: 'your-app.auth.us-west-2.amazoncognito.com'
});
```

## Available Commands

### /setup-auth
Guided workflow to integrate l42-cognito-passkey into a project:
1. Copy auth.js to project
2. Configure Cognito pool details
3. Generate auth configuration
4. Create callback.html for OAuth flow
5. Provide Cognito setup guidance (CDK + boto3)

## Available Agents

### auth-setup
Interactive agent for complex auth integration scenarios that require:
- Custom RBAC configurations
- Multi-tenant setups
- Integration with existing auth systems

## Key Functions Exported

```javascript
// Configuration (REQUIRED before using other functions)
configure(options)    // Configure auth module
isConfigured()        // Check if configured

// Configuration Options:
// {
//   clientId: 'xxx',           // REQUIRED: Cognito app client ID
//   cognitoDomain: 'xxx',      // REQUIRED: e.g., 'myapp.auth.us-west-2.amazoncognito.com'
//   cognitoRegion: 'us-west-2', // AWS region (default: us-west-2)
//   redirectUri: '/callback',   // OAuth callback URL
//   allowedDomains: ['myapp.com'], // Allowed redirect domains (auto-allows current)
//   scopes: 'openid email profile aws.cognito.signin.user.admin'
// }

// Authentication state
isAuthenticated()     // Check if user is logged in (returns boolean)
getTokens()           // Get current tokens
getAuthMethod()       // Get auth method ('password' or 'passkey')
getUserEmail()        // Get user's email from claims
getUserGroups()       // Get user's Cognito groups
isAdmin()             // Check if user is in admin group (UI only!)
isReadonly()          // Check if user is in readonly group
hasAdminScope()       // Check if token has admin scope

// Token management
isTokenExpired(tokens)      // Check if token is expired
shouldRefreshToken(tokens)  // Check if should refresh proactively
refreshTokens()             // Refresh tokens using refresh token
ensureValidTokens()         // Get valid tokens, refreshing if needed

// JWT utilities (UNVERIFIED - display only!)
UNSAFE_decodeJwtPayload(token)  // Decode JWT payload (no signature verification)

// Server-side authorization (REQUIRED for real authorization)
requireServerAuthorization(action, options)  // Call server to validate permissions
UI_ONLY_hasRole(role)  // Explicitly named for UI-only checks

// Login methods
loginWithPassword(email, password)  // Standard login (1-day cookie)
loginWithPasskey(email)             // WebAuthn passkey login (30-day cookie)
loginWithHostedUI(email?)           // Redirect to Cognito hosted UI

// Logout
logout()                            // Clear tokens and session

// Passkey management (requires admin scope)
listPasskeys()                      // List user's registered passkeys
registerPasskey()                   // Register new passkey
deletePasskey(credentialId)         // Remove a passkey

// Event handling
onAuthStateChange(callback)         // Subscribe to auth state changes
```

## Auto-Configuration

The library can auto-read configuration from `window.L42_AUTH_CONFIG`:

```html
<script>
window.L42_AUTH_CONFIG = {
    clientId: 'your-client-id',
    domain: 'your-app.auth.us-west-2.amazoncognito.com',
    region: 'us-west-2',
    redirectUri: window.location.origin + '/callback',
    scopes: ['openid', 'email', 'aws.cognito.signin.user.admin']
};
</script>
<script type="module">
import { isAuthenticated } from '/auth/auth.js';
// Works without explicit configure() call
</script>
```

## Cognito Setup Requirements

### User Pool Client (CDK/CloudFormation)

**OAuth Scopes:**
- openid
- email
- aws.cognito.signin.user.admin (for passkey management)

**Explicit Auth Flows:**
- ALLOW_USER_PASSWORD_AUTH
- ALLOW_USER_AUTH (for passkey login)
- ALLOW_REFRESH_TOKEN_AUTH

### User Pool Settings (boto3 only)

WebAuthn requires boto3 or Console - CDK/CloudFormation don't support it yet:

```python
import boto3
client = boto3.client('cognito-idp', region_name='us-west-2')

# Enable WEB_AUTHN in sign-in policy
client.update_user_pool(
    UserPoolId='YOUR_POOL_ID',
    Policies={
        'SignInPolicy': {
            'AllowedFirstAuthFactors': ['PASSWORD', 'WEB_AUTHN']
        }
    }
)

# Configure WebAuthn relying party
client.set_user_pool_mfa_config(
    UserPoolId='YOUR_POOL_ID',
    WebAuthnConfiguration={
        'RelyingPartyId': 'your-domain.com',  # MUST match your production domain
        'UserVerification': 'preferred'
    },
    MfaConfiguration='OPTIONAL'
)
```

See `docs/cognito-setup.md` for complete instructions.

## Content Security Policy

When integrating, your CSP must allow:

```
script-src: 'nonce-{RANDOM}' 'strict-dynamic'
style-src: 'nonce-{RANDOM}'
connect-src: 'self' https://cognito-idp.{region}.amazonaws.com https://*.amazoncognito.com
form-action: 'self' https://{cognitoDomain}
```

> **Note:** Use nonce-based CSP (requires server-side nonce generation). For static files without a server, `script-src 'self'` is acceptable. Avoid `'unsafe-inline'` in production. See `docs/security-hardening.md`.

## Token Storage

Tokens are stored server-side in HttpOnly session cookies via the Token Handler pattern (the only supported mode as of v0.15.0). The `sessionEndpoint` config option enables automatic session persistence after direct login methods (passkey/password).

## Version

Check library version:
```javascript
import { VERSION } from '/auth/auth.js';
console.log(VERSION); // "0.16.0"
```

## Site Architecture Patterns

This plugin supports three primary site architecture patterns. See `plugin/templates/` for full implementations.

### 1. Static Site Pattern (`static-site-pattern.html`)

Architecture for content-focused sites:
- `site.domain/` → Public static content (CDN-cached)
- `site.domain/auth/` → Protected area requiring login
- `site.domain/admin/` → Admin area for editors/publishers

**Roles**: `readonly`, `user`, `editor`, `reviewer`, `publisher`, `admin`

### 2. Admin Panel Pattern (`admin-panel-pattern.html`)

Architecture for user management interfaces:
- Admin-only access (Cognito `admin` group required)
- User CRUD via Cognito AdminUser* APIs
- Requires backend Lambda + API Gateway

**Required Backend**:
```javascript
// API Gateway endpoints (Cognito authorizer)
GET  /admin/users          // List users
POST /admin/users          // Create user (invite)
PUT  /admin/users/:id      // Update user
PUT  /admin/users/:id/status  // Enable/disable
POST /admin/users/:id/reset   // Reset password
GET  /admin/audit          // Audit logs
```

## RBAC System

See `plugin/templates/rbac-roles.js` for the complete role definitions.

### Core Roles (Always Required)

| Role | Level | Description |
|------|-------|-------------|
| `admin` | 100 | Full system access with user management |
| `readonly` | 10 | View-only access to all resources |
| `user` | 20 | Standard authenticated user |

### Cognito Group Checking

Use `isInCognitoGroup()` for consistent group checking with alias support:

```javascript
import { isInCognitoGroup, COGNITO_GROUPS } from './rbac-roles.js';

const groups = auth.getUserGroups();

// Handles aliases: 'admin', 'admins', 'administrators'
if (isInCognitoGroup(groups, 'ADMIN')) {
    // User is admin
}
```

### Permission Checking

```javascript
import { hasPermission, hasRoleLevel, canManageRole } from './rbac-roles.js';

// Check specific permission
if (hasPermission('editor', 'publish:content')) {
    // Allow publishing
}

// Check role hierarchy
if (hasRoleLevel('developer', 'moderator')) {
    // Developer has at least moderator level
}
```

## Security Notes

### XSS Prevention
All templates use `textContent` for user-controlled data to prevent XSS:

```javascript
// SAFE - always use textContent for user data
userEmail.textContent = auth.getUserEmail();
roleBadge.textContent = userRole;
```

### Client-Side RBAC is UI Only
Always use `requireServerAuthorization()` for real authorization:

```javascript
// WRONG - client-side only
if (auth.isAdmin()) { deleteUser(id); }

// CORRECT - server validates
const result = await auth.requireServerAuthorization('admin:delete-user');
if (result.authorized) { deleteUser(id); }
```

## Testing

Each template has an accompanying test file:
- `plugin/templates/static-site-pattern.test.js`
- `plugin/templates/admin-panel-pattern.test.js`
- `plugin/templates/rbac-roles.property.test.js` (22 property-based tests)
- `plugin/templates/version-consistency.test.js`
- `plugin/templates/token-storage.test.js` (15 token storage tests)
- `plugin/templates/auto-refresh.test.js` (35 auto-refresh, fetchWithAuth, CSRF tests)
- `plugin/templates/auth-properties.test.js` (41 auth property-based tests)
- `plugin/templates/debug-diagnostics.test.js` (34 debug logging & diagnostics tests)
- `plugin/templates/conditional-ui.test.js` (32 conditional UI / passkey autofill tests)
- `plugin/templates/conditional-create.test.js` (23 conditional create / passkey upgrade tests)
- `plugin/templates/token-validation.test.js` (31 token validation on load tests)
- `plugin/templates/webauthn-capabilities.test.js` (22 WebAuthn Level 3 capabilities tests)
- `plugin/templates/login-rate-limiting.test.js` (40 login rate limiting tests)
- `plugin/templates/cedar-authorization.test.js` (132 Cedar policy authorization tests)

**Total: 658 tests**

Run tests with:
```bash
pnpm test
```

## Release Process

```bash
pnpm release:patch    # Bug fixes
pnpm release:minor    # New features
pnpm release:major    # Breaking changes
```

See `docs/RELEASING.md` for complete release process.
