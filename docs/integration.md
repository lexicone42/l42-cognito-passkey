# Integration Guide

How to set up L42 Cognito Passkey in your project.

## Quick Start

### 1. Copy auth.js

```bash
cp src/auth.js your-project/public/auth/auth.js
cp src/auth.d.ts your-project/public/auth/auth.d.ts  # TypeScript
```

### 2. Deploy a backend

```bash
# Rust (recommended)
cp -r rust/ your-project/backend/
cd your-project/backend && cp .env.example .env
cargo run  # local dev on :3001

# Express (alternative)
cp -r examples/backends/express/ your-project/backend/
cd your-project/backend && npm install && node server.js
```

### 3. Configure

```html
<script>
window.L42_AUTH_CONFIG = {
    clientId: 'your-cognito-client-id',
    domain: 'your-app.auth.us-west-2.amazoncognito.com',
    region: 'us-west-2',
    redirectUri: window.location.origin + '/callback',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    sessionEndpoint: '/auth/session'
};
</script>

<script type="module">
import { isAuthenticated, getUserEmail, loginWithHostedUI,
         requireServerAuthorization } from '/auth/auth.js';

if (isAuthenticated()) {
    const result = await requireServerAuthorization('read:content');
    if (result.authorized) loadContent();
} else {
    loginWithHostedUI();
}
</script>
```

### 4. Create callback page

Copy `plugin/templates/callback.html` to your project at `/callback.html` and update the config values.

## Cognito Setup

### User Pool Client (CDK)

```typescript
const userPool = new cognito.UserPool(this, 'UserPool', {
    selfSignUpEnabled: true,
    signInAliases: { email: true },
});

const client = new cognito.UserPoolClient(this, 'Client', {
    userPool,
    generateSecret: false,
    oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
            cognito.OAuthScope.OPENID,
            cognito.OAuthScope.EMAIL,
            cognito.OAuthScope.COGNITO_ADMIN  // required for passkey management
        ],
        callbackUrls: ['https://your-domain.com/callback', 'http://localhost:3000/callback'],
        logoutUrls: ['https://your-domain.com/', 'http://localhost:3000/']
    }
});

// CDK escape hatch for ALLOW_USER_AUTH
const cfnClient = client.node.defaultChild as cognito.CfnUserPoolClient;
cfnClient.addPropertyOverride('ExplicitAuthFlows', [
    'ALLOW_USER_PASSWORD_AUTH', 'ALLOW_USER_SRP_AUTH',
    'ALLOW_CUSTOM_AUTH', 'ALLOW_USER_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH'
]);

userPool.addDomain('CognitoDomain', {
    cognitoDomain: { domainPrefix: 'my-app-auth' }
});
```

### User Pool Client (CloudFormation)

```yaml
UserPoolClient:
  Type: AWS::Cognito::UserPoolClient
  Properties:
    UserPoolId: !Ref UserPool
    GenerateSecret: false
    ExplicitAuthFlows:
      - ALLOW_USER_PASSWORD_AUTH
      - ALLOW_USER_SRP_AUTH
      - ALLOW_CUSTOM_AUTH
      - ALLOW_USER_AUTH
      - ALLOW_REFRESH_TOKEN_AUTH
    AllowedOAuthFlows: [code]
    AllowedOAuthScopes: [openid, email, aws.cognito.signin.user.admin]
    AllowedOAuthFlowsUserPoolClient: true
    CallbackURLs:
      - https://your-domain.com/callback
    LogoutURLs:
      - https://your-domain.com/
```

### WebAuthn Configuration (boto3)

CDK and CloudFormation do not support WebAuthn configuration. Use boto3:

```python
import boto3

client = boto3.client('cognito-idp', region_name='us-west-2')

# Enable passkeys in sign-in policy
client.update_user_pool(
    UserPoolId='us-west-2_xxxxxxxxx',
    Policies={'SignInPolicy': {'AllowedFirstAuthFactors': ['PASSWORD', 'WEB_AUTHN']}}
)

# Configure WebAuthn relying party
client.set_user_pool_mfa_config(
    UserPoolId='us-west-2_xxxxxxxxx',
    WebAuthnConfiguration={
        'RelyingPartyId': 'your-domain.com',
        'UserVerification': 'preferred'
    },
    MfaConfiguration='OPTIONAL'
)
```

Passkeys are domain-bound. A passkey registered on `example.com` won't work on `localhost`. For local development, use password auth or create a separate User Pool.

### Passkey-Only Deployment

To disable passwords entirely (highest-impact security hardening):

```python
# boto3 — remove PASSWORD from sign-in policy
client.update_user_pool(
    UserPoolId='us-west-2_xxxxxxxxx',
    Policies={'SignInPolicy': {'AllowedFirstAuthFactors': ['WEB_AUTHN']}}
)
```

Remove `ALLOW_USER_PASSWORD_AUTH` and `ALLOW_USER_SRP_AUTH` from the User Pool Client. `loginWithPassword()` will throw a Cognito error — this is intentional.

Account recovery without passwords: register multiple passkeys per user, or implement a recovery code flow via `CUSTOM_AUTH`.

### Verify Configuration

```bash
# Check auth flows
aws cognito-idp describe-user-pool-client \
    --user-pool-id us-west-2_xxxxxxxxx --client-id your-client-id \
    --query 'UserPoolClient.{Scopes:AllowedOAuthScopes,Flows:ExplicitAuthFlows}'

# Check WebAuthn
aws cognito-idp get-user-pool-mfa-config \
    --user-pool-id us-west-2_xxxxxxxxx --query 'WebAuthnConfiguration'
```

## Site Architecture Patterns

### Static Site with Protected Areas

```
site.com/          → Public (CDN-cached)
site.com/auth/     → Protected (requires login)
site.com/admin/    → Admin area (requires admin group)
```

```javascript
import { isAuthenticated, isAdmin, onSessionExpired } from './auth.js';

if (!isAuthenticated() && location.pathname.startsWith('/auth/')) {
    location.href = '/login';
}
if (location.pathname.startsWith('/admin/') && !isAdmin()) {
    location.href = '/auth/';
}
onSessionExpired(() => { location.href = '/login?expired=true'; });
```

### SPA with API Backend

```javascript
import { fetchWithAuth, onSessionExpired } from './auth.js';

async function loadContent() {
    const res = await fetchWithAuth('/api/content');
    return res.json();
}

onSessionExpired(() => router.navigate('/login'));
```

### Multi-Site (Cross-Subdomain SSO)

```javascript
// Both admin.myapp.com and app.myapp.com share one backend
configure({
    tokenEndpoint: 'https://api.myapp.com/auth/token',
    refreshEndpoint: 'https://api.myapp.com/auth/refresh',
    logoutEndpoint: 'https://api.myapp.com/auth/logout',
    sessionEndpoint: 'https://api.myapp.com/auth/session'
});
```

Backend config:
```bash
COOKIE_DOMAIN=.myapp.com
CALLBACK_USE_ORIGIN=true
CALLBACK_ALLOWED_ORIGINS=https://admin.myapp.com,https://app.myapp.com
```

## RBAC

### Client-Side (UI Only)

```javascript
import { isAdmin, isReadonly, getUserGroups } from './auth.js';
import { isInCognitoGroup } from './rbac-roles.js';

if (isAdmin()) showAdminPanel();
if (isReadonly()) disableEditing();

const groups = getUserGroups();
if (isInCognitoGroup(groups, 'PUBLISHER')) showPublishingTools();
```

### Server-Side (Required for Real Authorization)

```javascript
import { requireServerAuthorization } from './auth.js';

const result = await requireServerAuthorization('admin:delete-user', {
    resource: { id: userId, type: 'user' }
});
if (result.authorized) await deleteUser(userId);
```

## Accessibility

### Login Form Pattern

```html
<form aria-labelledby="login-heading">
    <h2 id="login-heading">Sign In</h2>
    <div role="alert" aria-live="assertive" id="login-errors"></div>

    <label for="email">Email address</label>
    <input type="email" id="email" autocomplete="email" required>

    <label for="password">Password</label>
    <input type="password" id="password" autocomplete="current-password" required>

    <button type="submit">Sign In</button>
    <button type="button" id="passkey-login" aria-describedby="passkey-hint">
        Sign in with Passkey
    </button>
    <span id="passkey-hint" class="visually-hidden">
        Uses biometric or security key authentication
    </span>
</form>
```

WebAuthn browser prompts (Touch ID, Windows Hello) have built-in accessibility. Always provide a password fallback when passkey fails or isn't available. Announce auth state changes to screen readers via `aria-live` regions.

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| "Auth not configured" | Config script missing or after auth.js import | Set `window.L42_AUTH_CONFIG` before importing |
| Callback not working | URL mismatch | Callback URL must exactly match Cognito app client setting |
| Session cookies not set | Cookie domain wrong | Set `COOKIE_DOMAIN` in backend `.env` |
| Groups not appearing | User not in Cognito groups | Add user to groups in Cognito Console |
| "USER_AUTH flow not enabled" | Missing auth flow | Add `ALLOW_USER_AUTH` to User Pool Client |
| "WebAuthn not enabled" | Not configured via boto3 | Run the boto3 script above |
| "Admin scope required" | Logged in via password, not hosted UI | `aws.cognito.signin.user.admin` scope requires `loginWithHostedUI()` |
| Passkey won't work on localhost | Domain mismatch | Passkeys are domain-bound; use password auth for local dev |

## Core API Quick Reference

Full documentation in [api-reference.md](api-reference.md).

```javascript
// Configuration
configure(options)              // Configure the library
isConfigured()                  // Check if configured

// Auth state
isAuthenticated()               // Sync (cached)
isAuthenticatedAsync()          // Async (server check)
getTokens()                     // Always use await
getUserEmail()                  // From cached token
getUserGroups()                 // From cached token

// Login
loginWithPassword(email, pass)
loginWithPasskey(email)
loginWithHostedUI(email?)
loginWithConditionalUI(opts)    // Passkey autofill
exchangeCodeForTokens(code, state)

// Session
logout()
ensureValidTokens()             // Refresh if needed
startAutoRefresh(opts?)         // Auto-starts on login
onSessionExpired(cb)

// Requests
fetchWithAuth(url, opts)        // fetch() + Bearer + 401 retry

// Passkeys
registerPasskey(opts?)
listPasskeys()
deletePasskey(id)
isPasskeySupported()
getPasskeyCapabilities()

// Authorization
requireServerAuthorization(action, opts)
UI_ONLY_hasRole(role)           // Display only

// Debug
getDiagnostics()
getDebugHistory()
```
