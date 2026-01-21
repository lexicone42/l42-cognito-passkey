---
description: Set up AWS Cognito + WebAuthn authentication in your project
---

# /setup-auth

Set up l42-cognito-passkey authentication in your project with AWS Cognito and WebAuthn passkey support.

## What This Command Does

1. **Copies auth.js** - Copy the library to your project's static files
2. **Collects Configuration** - Prompts for Cognito User Pool details
3. **Generates Auth Config** - Creates properly configured auth setup
4. **Creates Callback Page** - Generates OAuth callback.html
5. **Provides Cognito Setup Guidance** - CDK + boto3 instructions for WebAuthn

## Usage

Run `/setup-auth` in any web project directory.

## Workflow

### Step 1: Copy auth.js to Project

First, copy the auth library to the project's static files:

```bash
# Determine the static files location (e.g., public/, static/, dist/)
# Copy auth.js there
cp /path/to/l42cognitopasskey/src/auth.js ./public/auth/auth.js
```

Ask the user where their static files are located.

### Step 2: Gather Cognito Configuration

Use AskUserQuestion to collect:

**Required:**
- Client ID (e.g., `1234567890abcdefghijk`)
- Cognito Domain (e.g., `myapp.auth.us-west-2.amazoncognito.com`)
- AWS Region (default: `us-west-2`)

**Optional:**
- Custom redirect URI (defaults to current origin + `/callback`)
- RBAC groups to configure (admin, readonly, etc.)

### Step 3: Generate Auth Configuration

Create the configuration code for the user's HTML:

```html
<script>
// Configuration for l42-cognito-passkey
window.L42_AUTH_CONFIG = {
    clientId: '{CLIENT_ID}',
    domain: '{COGNITO_DOMAIN}',
    region: '{REGION}',
    redirectUri: window.location.origin + '/callback',
    scopes: ['openid', 'email', 'aws.cognito.signin.user.admin']
};
</script>

<script type="module">
import {
    configure,
    isAuthenticated,
    getTokens,
    getUserEmail,
    getUserGroups,
    isAdmin,
    loginWithPassword,
    loginWithPasskey,
    loginWithHostedUI,
    logout,
    onAuthStateChange
} from '/auth/auth.js';

// Initialize auth state listener
onAuthStateChange((isAuth) => {
    if (isAuth) {
        console.log('Logged in as:', getUserEmail());
        // showDashboard();
    } else {
        console.log('Not authenticated');
        // showLogin();
    }
});

// Check initial auth state
if (isAuthenticated()) {
    console.log('Already authenticated');
} else {
    console.log('Need to log in');
}
</script>
```

### Step 4: Create Callback Page

Generate `callback.html` for OAuth flow completion:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="
        default-src 'self';
        script-src 'self' 'unsafe-inline';
        style-src 'self' 'unsafe-inline';
        connect-src 'self' https://cognito-idp.{REGION}.amazonaws.com https://*.amazoncognito.com https://{COGNITO_DOMAIN};
    ">
    <meta name="robots" content="noindex,nofollow">
    <title>Authentication Callback</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #1a1a2e;
            color: #eee;
        }
        .loading { text-align: center; }
        .spinner {
            width: 40px; height: 40px;
            border: 3px solid #333;
            border-top-color: #e94560;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .error { color: #f87171; }
    </style>
</head>
<body>
    <div class="loading">
        <div class="spinner"></div>
        <p id="status">Completing authentication...</p>
    </div>

    <script>
    window.L42_AUTH_CONFIG = {
        clientId: '{CLIENT_ID}',
        domain: '{COGNITO_DOMAIN}',
        region: '{REGION}',
        redirectUri: window.location.origin + '/callback',
        scopes: ['openid', 'email', 'aws.cognito.signin.user.admin']
    };
    </script>

    <script type="module">
        import { exchangeCodeForTokens } from '/auth/auth.js';

        const status = document.getElementById('status');

        try {
            const params = new URLSearchParams(window.location.search);
            const code = params.get('code');
            const state = params.get('state');
            const error = params.get('error');

            if (error) {
                throw new Error(params.get('error_description') || error);
            }

            if (code) {
                await exchangeCodeForTokens(code, state);
            }

            status.textContent = 'Success! Redirecting...';

            const redirectTo = sessionStorage.getItem('l42_redirect_after_login') || '/';
            sessionStorage.removeItem('l42_redirect_after_login');

            setTimeout(() => window.location.href = redirectTo, 500);
        } catch (error) {
            console.error('Auth callback error:', error);
            status.textContent = error.message || 'Authentication failed';
            status.classList.add('error');
            setTimeout(() => window.location.href = '/', 3000);
        }
    </script>
</body>
</html>
```

### Step 5: Provide Cognito Setup Guidance

Explain the Cognito configuration needed:

```
## Cognito Setup Required

### 1. User Pool Client (CDK/CloudFormation)

Ensure your Cognito client has:

**OAuth Scopes:**
- openid
- email
- aws.cognito.signin.user.admin (required for passkey management)

**Explicit Auth Flows:**
- ALLOW_USER_PASSWORD_AUTH
- ALLOW_USER_AUTH (required for passkey login)
- ALLOW_REFRESH_TOKEN_AUTH

### 2. WebAuthn Configuration (boto3 only)

CDK/CloudFormation don't support WebAuthn yet. Use boto3:

```python
import boto3
client = boto3.client('cognito-idp', region_name='{REGION}')

# Step 1: Enable WEB_AUTHN in sign-in policy
client.update_user_pool(
    UserPoolId='{USER_POOL_ID}',
    Policies={
        'SignInPolicy': {
            'AllowedFirstAuthFactors': ['PASSWORD', 'WEB_AUTHN']
        }
    }
)

# Step 2: Configure WebAuthn relying party
client.set_user_pool_mfa_config(
    UserPoolId='{USER_POOL_ID}',
    WebAuthnConfiguration={
        'RelyingPartyId': '{YOUR_DOMAIN}',  # e.g., 'myapp.com'
        'UserVerification': 'preferred'
    },
    MfaConfiguration='OPTIONAL'
)
```

**IMPORTANT:** The RelyingPartyId must match your production domain.
Passkeys registered on `myapp.com` won't work from `localhost`.
```

## Example Output

After running `/setup-auth`, the user should have:

1. `auth.js` copied to their static files
2. Configuration code for their HTML
3. New `callback.html` file
4. Understanding of Cognito requirements
5. boto3 script for WebAuthn setup

## Notes

- The auth module is self-hosted (no external CDN)
- Tokens are stored in localStorage under `l42_auth_tokens`
- Cookie is set for server-side validation (domain auto-detected)
- The module handles token refresh automatically
