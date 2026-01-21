# L42 Cognito Passkey

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

## Claude Code Plugin

This repo includes a Claude Code plugin for guided setup:

```bash
# Add the plugin directory to your Claude Code config
# Then use /setup-auth in your project
```

## Version

```javascript
import { VERSION } from '/auth/auth.js';
console.log(VERSION); // "0.3.0"
```

## License

Apache-2.0
