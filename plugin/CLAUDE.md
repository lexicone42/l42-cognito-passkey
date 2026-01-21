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
console.log(VERSION); // "2.0.0"
```
