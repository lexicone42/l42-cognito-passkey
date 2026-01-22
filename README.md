# L42 Cognito Passkey

[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)
[![CI](https://github.com/lexicone42/l42-cognito-passkey/actions/workflows/ci.yml/badge.svg)](https://github.com/lexicone42/l42-cognito-passkey/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.7.0-blue)](https://github.com/lexicone42/l42-cognito-passkey/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-207%20passing-success)](https://github.com/lexicone42/l42-cognito-passkey/actions)

AWS Cognito authentication with WebAuthn/Passkey support. Self-hosted, configurable, no build step required.

## Features

- Password + Passkey authentication via AWS Cognito
- OAuth2 with PKCE and CSRF protection
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

## API Reference

See [docs/api-reference.md](docs/api-reference.md) for complete documentation.

### Core Functions

```javascript
// Configuration
configure(options)        // Configure the library
isConfigured()           // Check if configured

// Authentication
isAuthenticated()        // Check if logged in
getTokens()              // Get current tokens
getUserEmail()           // Get user's email
getUserGroups()          // Get Cognito groups

// Login
loginWithPassword(email, password)
loginWithPasskey(email)
loginWithHostedUI(email?)

// Session
logout()
ensureValidTokens()      // Auto-refresh if needed

// Passkey management
listPasskeys()
registerPasskey()
deletePasskey(id)

// Events
onAuthStateChange(callback)
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Cognito Setup](docs/cognito-setup.md) | AWS Cognito configuration (CDK, CloudFormation, boto3) |
| [API Reference](docs/api-reference.md) | Complete function documentation |
| [Migration Guide](docs/migration.md) | Upgrading between versions |
| [Accessibility](docs/accessibility.md) | ARIA patterns, keyboard navigation, screen readers |
| [Security Hardening](docs/security-hardening.md) | CSP, BFF pattern, token lifecycle, threat models |
| [Token Storage Proposal](docs/v1-token-storage-proposal.md) | v0.9 Token Handler roadmap |
| [DPoP Future](docs/dpop-future.md) | v1.0 DPoP integration plan |
| [OCSF Logging](docs/ocsf-logging.md) | AWS Security Lake / SIEM integration |
| [Claude Workflow](docs/claude-workflow.md) | Claude-to-Claude collaboration via GitHub |
| [Releasing](docs/RELEASING.md) | Release process for maintainers |

## Security

- **PKCE** - Proof Key for Code Exchange prevents authorization code interception
- **CSRF Protection** - State parameter validated on every OAuth callback
- **HTTPS Enforcement** - Redirect URIs must use HTTPS (except localhost)
- **Domain Validation** - Cognito domain format validated to prevent open redirects

## Version

```javascript
import { VERSION } from '/auth/auth.js';
console.log(VERSION); // "0.7.0"
```

## Claude Code Integration

This project was built with [Claude Code](https://claude.ai/code). See [`CLAUDE.md`](CLAUDE.md) for integration guidelines, security patterns, and RBAC documentation.

```bash
pnpm test            # Run all 207 tests
pnpm release:patch   # Bump version (0.6.0 → 0.6.1)
```

## License

Apache-2.0
