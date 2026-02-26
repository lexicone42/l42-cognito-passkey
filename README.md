# L42 Cognito Passkey

[![CI](https://github.com/lexicone42/l42-cognito-passkey/actions/workflows/ci.yml/badge.svg)](https://github.com/lexicone42/l42-cognito-passkey/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.20.1-blue)](https://github.com/lexicone42/l42-cognito-passkey/blob/main/CHANGELOG.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-890-success)](https://github.com/lexicone42/l42-cognito-passkey/actions)
[![Rust 2024](https://img.shields.io/badge/Rust-2024_edition-orange)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![Built with Claude Code](https://img.shields.io/badge/Built_with-Claude_Code-blue)](https://claude.ai/claude-code)

Self-hosted authentication for AWS Cognito with passkey support. Copy `auth.js` into your project — no build step, no CDN dependency.

## How It Works

Two pieces: a client library (`src/auth.js`) and a backend that stores tokens server-side in HttpOnly cookies.

```
Browser                          Your Backend                 Cognito
  │                                  │                           │
  │── loginWithPasskey() ───────────>│                           │
  │                                  │── token exchange ────────>│
  │                                  │<── tokens ────────────────│
  │                                  │  (stored in HttpOnly cookie)
  │<── session cookie ───────────────│                           │
  │                                  │                           │
  │── requireServerAuthorization() ─>│                           │
  │                                  │── Cedar policy eval       │
  │<── { authorized: true } ─────────│                           │
```

The client never touches raw tokens. Authorization decisions happen server-side via [Cedar policies](docs/rust-backend.md#cedar-policies).

## Quick Start

### 1. Copy the files

```bash
# Client
cp src/auth.js your-project/public/auth/auth.js

# Backend (Rust — recommended)
cp -r rust/ your-project/backend/
cd your-project/backend && cp .env.example .env  # fill in Cognito values
cargo run  # local dev on :3001
```

An Express backend is also available in `examples/backends/express/` if you prefer Node.js.

### 2. Configure

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
    if (result.authorized) {
        loadContent();
    }
} else {
    loginWithHostedUI();
}
</script>
```

### 3. Set up the callback page

Copy `plugin/templates/callback.html` to your project and update the config values.

## What's Included

**Client (`auth.js`)** — Password, passkey, and OAuth login. PKCE + CSRF protection. Automatic background token refresh. Conditional UI (passkey autofill). Login rate limiting. RBAC group checks for UI hints. Debug diagnostics. TypeScript declarations.

**Rust Backend (`rust/`)** — Token Handler (HttpOnly session cookies). Cedar policy authorization. Ownership enforcement. OCSF security event logging. Runs as Lambda or standalone server.

## Documentation

| Guide | Description |
|-------|-------------|
| [API Reference](docs/api-reference.md) | Complete function documentation |
| [Architecture](docs/architecture.md) | Token Handler pattern, auth flows, design decisions |
| [Security](docs/security.md) | Threat model, CSP, passkey attacks, OCSF logging |
| [Integration](docs/integration.md) | Cognito setup, site patterns, troubleshooting |
| [Rust Backend](docs/rust-backend.md) | Deployment, Cedar policies, configuration |
| [Release](docs/release.md) | Versioning, migration guide, v1.0 roadmap |

## Development

```bash
pnpm test           # 733 JS tests
cd rust && cargo test  # 157 Rust tests
```

See [CLAUDE.md](CLAUDE.md) for contributor guidelines and [release.md](docs/release.md) for the release process.

## License

Apache-2.0
