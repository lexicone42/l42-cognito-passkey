# L42 Cognito Passkey

[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)
[![CI](https://github.com/lexicone42/l42-cognito-passkey/actions/workflows/ci.yml/badge.svg)](https://github.com/lexicone42/l42-cognito-passkey/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.5.1-blue)](https://github.com/lexicone42/l42-cognito-passkey/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-130%20passing-success)](https://github.com/lexicone42/l42-cognito-passkey/actions)

AWS Cognito authentication with WebAuthn/Passkey support. Self-hosted, configurable, no build step required.

## Features

- Password + Passkey authentication via AWS Cognito
- OAuth2 with CSRF protection
- Automatic token refresh
- Role-based access control (RBAC) via Cognito groups
- Self-hosted - copy to your project, no CDN dependency
- ES module - zero build step required

## Quick Start

### 1. Copy auth.js to your project

```bash
cp src/auth.js /path/to/your/project/public/auth/auth.js
```

### 2. Configure and use

```html
<script>
window.L42_AUTH_CONFIG = {
    clientId: 'your-cognito-client-id',
    domain: 'your-app.auth.us-west-2.amazoncognito.com',
    region: 'us-west-2',
    redirectUri: window.location.origin + '/callback',
    scopes: ['openid', 'email', 'aws.cognito.signin.user.admin']
};
</script>

<script type="module">
import { isAuthenticated, getUserEmail, loginWithHostedUI, logout } from '/auth/auth.js';

if (isAuthenticated()) {
    console.log('Logged in as:', getUserEmail());
} else {
    loginWithHostedUI();
}
</script>
```

### 3. Create callback.html

Copy `plugin/templates/callback.html` to your project and update the configuration.

### 4. Configure Cognito

See [Cognito Setup Guide](docs/cognito-setup.md) for required AWS configuration.

## API Reference

See [API Reference](docs/api-reference.md) for complete documentation.

### Core Functions

```javascript
// Configuration
configure(options)    // Configure the library (or use window.L42_AUTH_CONFIG)
isConfigured()        // Check if configured

// Authentication state
isAuthenticated()     // Check if logged in
getTokens()           // Get current tokens
getUserEmail()        // Get user's email
getUserGroups()       // Get Cognito groups
isAdmin()             // Check admin group membership
isReadonly()          // Check readonly group membership

// Login methods
loginWithPassword(email, password)  // Password login
loginWithPasskey(email)             // WebAuthn passkey login
loginWithHostedUI(email?)           // Cognito hosted UI

// Logout
logout()              // Clear session

// Token management
ensureValidTokens()   // Auto-refresh if needed (call before API requests)

// Passkey management (requires admin scope)
listPasskeys()        // List registered passkeys
registerPasskey()     // Register new passkey
deletePasskey(id)     // Delete passkey

// Events
onAuthStateChange(callback)  // Subscribe to auth changes
```

## Cognito Requirements

### User Pool Client

- OAuth scopes: `openid`, `email`, `aws.cognito.signin.user.admin`
- Auth flows: `ALLOW_USER_PASSWORD_AUTH`, `ALLOW_USER_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`

### User Pool (WebAuthn - requires boto3)

```python
import boto3
client = boto3.client('cognito-idp', region_name='us-west-2')

# Enable WebAuthn
client.update_user_pool(
    UserPoolId='your-pool-id',
    Policies={'SignInPolicy': {'AllowedFirstAuthFactors': ['PASSWORD', 'WEB_AUTHN']}}
)

# Configure relying party
client.set_user_pool_mfa_config(
    UserPoolId='your-pool-id',
    WebAuthnConfiguration={
        'RelyingPartyId': 'your-domain.com',
        'UserVerification': 'preferred'
    },
    MfaConfiguration='OPTIONAL'
)
```

**Note:** CDK/CloudFormation don't support WebAuthn configuration yet. Use boto3 or AWS Console.

## Claude Code Integration

This project was built with [Claude Code](https://claude.ai/code) and includes a plugin for guided setup.

### For Claude Code Instances

See [`CLAUDE.md`](CLAUDE.md) for integration guidelines, security patterns, and RBAC documentation.

### Plugin Commands

```bash
# Add the plugin directory to your Claude Code config
# Then use /setup-auth in your project
```

### Development with Claude Code

```bash
pnpm test                 # Run all 130 tests
pnpm validate-docs        # Check documentation consistency
pnpm release:patch        # Bump version (0.5.1 → 0.5.2)
```

## Version

```javascript
import { VERSION } from '/auth/auth.js';
console.log(VERSION); // "0.5.1"
```

## Migration Guide

### v0.3.x → v0.4.0

**`decodeJwtPayload()` Renamed**

The function `decodeJwtPayload()` has been renamed to `UNSAFE_decodeJwtPayload()` to clearly indicate that it returns **unverified claims**. The old name still works but emits a deprecation warning.

```javascript
// Before (still works, but warns)
const claims = auth.decodeJwtPayload(token);

// After (recommended)
const claims = auth.UNSAFE_decodeJwtPayload(token);
```

**Why?** This prevents developers from accidentally using JWT claims for authorization decisions. The `UNSAFE_` prefix reminds you that these claims are for display purposes only.

**New Security Helpers**

Use `requireServerAuthorization()` for protected actions:

```javascript
// Enforces server-side validation
const result = await auth.requireServerAuthorization('admin:delete-user');
if (!result.authorized) {
    throw new Error(result.reason);
}
```

## License

Apache-2.0
