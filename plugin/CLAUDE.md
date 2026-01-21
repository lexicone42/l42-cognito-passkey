# L42 Cognito Passkey Plugin

This plugin provides quick setup for AWS Cognito authentication with WebAuthn passkey support.

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
//   cookieDomain: '.myapp.com',    // Cookie domain (auto-detected if not set)
//   scopes: 'openid email profile aws.cognito.signin.user.admin'
// }

// Authentication state
isAuthenticated()     // Check if user is logged in (returns boolean)
getTokens()           // Get current tokens
getAuthMethod()       // Get auth method ('password' or 'passkey')
getUserEmail()        // Get user's email from claims
getUserGroups()       // Get user's Cognito groups
isAdmin()             // Check if user is in admin group
isReadonly()          // Check if user is in readonly group
hasAdminScope()       // Check if token has admin scope

// Token management
isTokenExpired(tokens)      // Check if token is expired
shouldRefreshToken(tokens)  // Check if should refresh proactively
refreshTokens()             // Refresh tokens using refresh token
ensureValidTokens()         // Get valid tokens, refreshing if needed

// JWT utilities (UNVERIFIED - display only!)
decodeJwtPayload(token)     // Decode JWT payload (no signature verification)

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
script-src: 'self' 'unsafe-inline'
style-src: 'self' 'unsafe-inline'
connect-src: 'self' https://cognito-idp.{region}.amazonaws.com https://*.amazoncognito.com https://{cognitoDomain}
form-action: 'self' https://{cognitoDomain}
```

Note: Since auth.js is self-hosted, you don't need external script sources.

## Token Storage

- **localStorage**: `l42_auth_tokens`
- **Cookie**: `l42_id_token` (for server-side validation)

Cookie domain is auto-detected based on current hostname, or can be explicitly configured.

## Version

Check library version:
```javascript
import { VERSION } from '/auth/auth.js';
console.log(VERSION); // "0.4.0"
```

## Site Architecture Patterns

This plugin supports two primary site architecture patterns. See `plugin/templates/` for full implementations.

### 1. Static Site Pattern (`static-site-pattern.html`)

Architecture for content-focused sites:
- `site.domain/` → Public static content (CDN-cached)
- `site.domain/auth/` → Protected area requiring login
- `site.domain/admin/` → Admin area for editors/publishers

**Roles**: `readonly`, `user`, `editor`, `reviewer`, `publisher`, `admin`

**Flow**:
1. Anonymous users browse static site freely
2. Login redirects to protected content
3. Editors/Publishers push changes that rebuild static site

### 2. Multi-User WASM Pattern (`wasm-multiuser-pattern.html`)

Architecture for real-time collaborative applications:
- WebSocket connections for player synchronization
- WASM modules for game logic (client-side)
- Session-based gameplay with DM control

**Roles**: `player`, `moderator`, `dm`, `admin`

**Hierarchy**:
- **Player** (level 10): Basic participant, chat, move character
- **Moderator** (level 30): Mute/kick players
- **DM** (level 50): Full session control, spawn NPCs, reveal areas
- **Admin** (level 100): System administration

### 3. Admin Panel Pattern (`admin-panel-pattern.html`)

Architecture for user management interfaces:
- Admin-only access (Cognito `admin` group required)
- User CRUD via Cognito AdminUser* APIs
- Requires backend Lambda + API Gateway

**Features**:
- User listing with search/filter
- Email invitations with role assignment
- User enable/disable
- Password reset initiation
- Audit logging

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

### Top 20 Standard Roles

The RBAC system includes skeleton definitions for common roles:

**Content/CMS**: `editor`, `reviewer`, `publisher`
**Gaming/WASM**: `player`, `dm`, `moderator`
**API/Developer**: `api_reader`, `api_writer`, `developer`
**Organization**: `team_member`, `team_lead`, `org_admin`
**E-commerce**: `customer`, `vip_customer`, `support_agent`
**Analytics**: `analyst`, `auditor`
**System**: `service_account`, `billing_admin`

### Permission Checking

```javascript
import { hasPermission, hasRoleLevel, canManageRole } from './rbac-roles.js';

// Check specific permission
if (hasPermission('editor', 'publish:content')) {
    // Allow publishing
}

// Check role hierarchy
if (hasRoleLevel('dm', 'moderator')) {
    // DM has at least moderator level
}

// Check if user can manage another user's role
if (canManageRole('admin', 'editor')) {
    // Admin can manage editors
}
```

### Cognito Group Mapping

```javascript
import { getCognitoGroupConfig } from './rbac-roles.js';

// Generate Cognito group configuration for CDK
const groups = getCognitoGroupConfig(['admin', 'editor', 'readonly']);
// Returns: [{ groupName: 'admin', description: '...', precedence: 0 }, ...]
```

## Security Notes

### XSS Prevention
All templates use `textContent` for user-controlled data to prevent XSS:

```javascript
// SAFE - always use textContent for user data
userEmail.textContent = auth.getUserEmail();
roleBadge.textContent = userRole;

// For dynamic element creation, use DOM methods
const span = document.createElement('span');
span.textContent = untrustedData;  // Safe
parent.appendChild(span);
```

Never inject user-controlled strings directly into HTML. See templates for safe patterns.

## Testing

Each template has an accompanying test file:
- `plugin/templates/static-site-pattern.test.js` (27 tests)
- `plugin/templates/wasm-multiuser-pattern.test.js` (29 tests)
- `plugin/templates/admin-panel-pattern.test.js` (41 tests)
- `plugin/templates/rbac-roles.js` (includes `hasPermission`, `getRoleHierarchy`, etc.)

**Total: 97 tests**

Run tests with:
```bash
npm test
# or
npx vitest run plugin/templates/
```

## Backlog

See `BACKLOG.md` in the project root for planned features:
- Contentful CMS integration
- Additional RBAC role templates
- Multi-tenant support
- Distributed development coordination
