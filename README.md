# L42 Cognito Passkey

[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)
[![CI](https://github.com/lexicone42/l42-cognito-passkey/actions/workflows/ci.yml/badge.svg)](https://github.com/lexicone42/l42-cognito-passkey/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.13.0-blue)](https://github.com/lexicone42/l42-cognito-passkey/blob/main/CHANGELOG.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-649-success)](https://github.com/lexicone42/l42-cognito-passkey/actions)
[![TypeScript](https://img.shields.io/badge/types-included-blue?logo=typescript&logoColor=white)](src/auth.d.ts)

AWS Cognito authentication with WebAuthn/Passkey support. Self-hosted, configurable, no build step required.

## Features

- Password + Passkey authentication via AWS Cognito
- Passkey autofill (Conditional UI) with email-scoped and discovery modes
- OAuth2 with PKCE and CSRF protection
- Automatic background token refresh with visibility API
- Token Handler mode for server-side token storage (XSS protection)
- Cedar policy authorization for server-side access control
- Role-based access control (RBAC) via Cognito groups
- Client-side login rate limiting with exponential backoff
- Debug logging and diagnostics mode
- TypeScript type declarations included
- Self-hosted - copy to your project, no CDN dependency
- ES module with tree-shaking support - zero build step required

## Quick Start

### 1. Copy auth.js to your project

```bash
cp src/auth.js /path/to/your/project/public/auth/auth.js
# TypeScript projects: also copy the declarations
cp src/auth.d.ts /path/to/your/project/public/auth/auth.d.ts
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
isAuthenticated()        // Check if logged in (sync)
isAuthenticatedAsync()   // Check if logged in (async, for handler mode)
getTokens()              // Get current tokens
getUserEmail()           // Get user's email
getUserGroups()          // Get Cognito groups
isAdmin()                // Check admin role (with aliases)
isReadonly()             // Check readonly role

// Login
loginWithPassword(email, password)
loginWithPasskey(email)
loginWithHostedUI(email?)
exchangeCodeForTokens(code, state)

// Session Management
logout()
ensureValidTokens()      // Auto-refresh if needed
startAutoRefresh()       // Background token refresh
stopAutoRefresh()
onSessionExpired(cb)     // Session recovery failed

// Authenticated Requests
fetchWithAuth(url, opts) // fetch() with Bearer token + 401 retry

// Passkey Management
listPasskeys()
registerPasskey()
deletePasskey(id)
isPasskeySupported()
getPasskeyCapabilities()

// Authorization
requireServerAuthorization(action, opts)  // Server-side auth check
UI_ONLY_hasRole(role)                     // UI display only (UNTRUSTED)

// Events
onAuthStateChange(callback)
onLogin(callback)
onLogout(callback)
```

## TypeScript

Type declarations are shipped with the library (`auth.d.ts`). For TypeScript projects using the self-hosted pattern:

```typescript
// Option 1: Copy both files
import { configure, isAuthenticated, TokenSet } from './auth/auth.js';

// Option 2: Declare module for CDN-style imports
declare module '/auth/auth.js' {
    export * from 'l42-cognito-passkey';
}
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Architecture](docs/architecture.md) | How the library works internally |
| [Cognito Setup](docs/cognito-setup.md) | AWS Cognito configuration (CDK, CloudFormation, boto3) |
| [API Reference](docs/api-reference.md) | Complete function documentation |
| [Migration Guide](docs/migration.md) | Upgrading between versions |
| [Handler Mode](docs/handler-mode.md) | Server-side token storage setup |
| [Cedar Authorization](docs/cedar-integration.md) | Server-side Cedar policy authorization |
| [Integration Guide](docs/integration-guide.md) | Integration advice for Claude Code |
| [Accessibility](docs/accessibility.md) | ARIA patterns, keyboard navigation, screen readers |
| [Design Decisions](docs/design-decisions.md) | Code choices, trade-offs, and common misconfigurations |
| [Security Hardening](docs/security-hardening.md) | CSP, BFF pattern, token lifecycle, threat models |
| [OCSF Logging](docs/ocsf-logging.md) | AWS Security Lake / SIEM integration |
| [Claude Workflow](docs/claude-workflow.md) | Claude-to-Claude collaboration via GitHub |
| [Releasing](docs/RELEASING.md) | Release process for maintainers |

## Security

- **PKCE** - Proof Key for Code Exchange prevents authorization code interception
- **CSRF Protection** - State parameter validated on every OAuth callback
- **HTTPS Enforcement** - Redirect URIs must use HTTPS (except localhost)
- **Domain Validation** - Cognito domain format validated to prevent open redirects
- **Token Handler Mode** - Server-side token storage immune to XSS storage scanning

## Version

```javascript
import { VERSION } from '/auth/auth.js';
console.log(VERSION); // "0.13.0"
```

## Claude Code Integration

This project was built with [Claude Code](https://claude.ai/code). See [`CLAUDE.md`](CLAUDE.md) for integration guidelines, security patterns, and RBAC documentation.

```bash
pnpm test            # Run all 350 tests
pnpm release:patch   # Bump version (0.10.0 -> 0.10.1)
```

## License

Apache-2.0
