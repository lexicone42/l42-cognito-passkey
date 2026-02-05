# L42 Cognito Passkey - Backlog

Planned features and integrations for future development.

## Current Focus: v1.0 Release

### Real-World Site Integration
**Status**: In Progress
**Goal**: Validate library with actual production sites before 1.0 release.

See `docs/integration-feedback.md` for:
- Minimal integration checklist
- Structured feedback template
- Common issues and solutions

---

## Priority: High

### Conditional UI / Passkey Autofill
**Status**: Not started
**Description**: Implement `loginWithConditionalUI()` for passkey autofill UX.
- Use `mediation: 'conditional'` with empty `allowCredentials`
- Add AbortController management (abort pending conditional request before modal flow)
- Accept `signal` parameter for cancellation
- This is the expected passkey UX in 2025/2026

### Conditional Create / Passkey Upgrade
**Status**: Not started
**Description**: Silent passkey upgrade after password login.
- `upgradeToPasskey()` using `navigator.credentials.create()` with `mediation: 'conditional'`
- Chrome 136+ and Safari 18+ support
- Auto-invoke after successful password login

### Token Validation on Load
**Status**: Not started
**Description**: Validate stored tokens against config on load.
- Verify `iss` claim matches configured Cognito domain
- Verify `aud`/`client_id` matches configured client ID
- Reject tokens with unreasonable `exp` claims

## Priority: Medium

### Contentful CMS Integration
**Status**: Backlog (role mapping defined)
**Description**: Integrate with Contentful for headless CMS workflows.

**Role Mapping** (tentative):
| l42 Role | Contentful Role |
|----------|-----------------|
| editor | Editor |
| reviewer | Content Reviewer |
| publisher | Publisher |
| admin | Admin |

### Multi-Tenant Support
**Status**: Backlog
**Description**: Support multiple organizations/tenants in single deployment.
- Tenant-scoped Cognito groups
- Custom attributes for tenant ID
- Cross-tenant admin roles
- Tenant isolation in RBAC checks

### Published npm Package
**Status**: Backlog
**Description**: Publish auth module to npm for easier integration.
- TypeScript definitions
- Tree-shaking support

### Client-Side Login Rate Limiting
**Status**: Not started
**Description**: Exponential backoff on failed login attempts.
- Configurable `maxLoginAttemptsBeforeDelay` and `loginBackoffMs`
- OCSF logging for threshold breaches
- Surface Cognito account lockout errors

## Priority: Low

### WebAuthn `getClientCapabilities()` Support
**Status**: Not started
**Description**: Use WebAuthn Level 3 `getClientCapabilities()` in `getPasskeyCapabilities()`.
- Check for method first, fall back to individual checks
- Add `isWebView` detection for mobile compatibility

### `registerPasskey()` Default Improvements
**Status**: Not started
**Description**: Better defaults for broader passkey support.
- Change `residentKey` to `'required'` (discoverable credentials)
- Remove `authenticatorAttachment: 'platform'` default (allow cross-device)
- Make authenticator selection configurable
- Document `userVerification` trade-offs

## Post-1.0: Advanced Authorization

### AWS Cedar Integration
**Status**: Design complete, implementation post-1.0
**Description**: Externalized authorization via Amazon Verified Permissions.

Benefits:
- Formal policy verification
- Externalized policies (update without deploy)
- Native Cognito token support
- ABAC beyond simple role checks

### Semgrep Security Rules
**Status**: Post-1.0
**Description**: Custom Semgrep rules for security patterns.
- XSS prevention (innerHTML vs textContent)
- Auth check enforcement
- Token handling patterns

---

## Completed

### v0.9.0 (Current)
- [x] Auto-refresh with visibility API integration
- [x] `fetchWithAuth()` with 401 retry
- [x] `onSessionExpired()` callback
- [x] CSRF protection for handler mode (X-L42-CSRF header)
- [x] WebAuthn feature detection (`isPasskeySupported`, `getPasskeyCapabilities`)
- [x] `isPasskeySupported()` checks `window.isSecureContext`
- [x] ~~WebSocket auth helper~~ (removed in cleanup — speculative, untested)
- [x] ~~Healthcare, Education, SaaS RBAC role templates~~ (removed — speculative)
- [x] 31 auth property-based tests (token expiry, cookie domain, mutual exclusion)
- [x] Sharp-edges security analysis (18 findings documented)
- [x] 379 total tests

### v0.8.0
- [x] Token Handler mode (server-side HttpOnly session storage)
- [x] Memory mode token storage
- [x] Handler sync/async contamination fixes
- [x] `isAdmin()`/`isReadonly()` alias support
- [x] 52 handler sync API tests

### v0.5.x
- [x] OAuth state uses localStorage (Safari ITP fix)
- [x] PKCE code challenge support
- [x] HTTPS enforcement for redirect URIs
- [x] Cognito domain validation
- [x] Dist file sync

### v0.4.0
- [x] `UNSAFE_decodeJwtPayload()` rename for security clarity
- [x] `requireServerAuthorization()` helper
- [x] ccTLD cookie domain fix (30+ public suffixes)
- [x] `COGNITO_GROUPS` with alias support
- [x] 22 property-based tests for RBAC
- [x] CLAUDE.md integration guide
- [x] Cedar integration design doc

### v0.3.0
- [x] RBAC role system with 20 standard roles
- [x] Static site pattern template
- [x] Multi-user WASM pattern template
- [x] Admin panel pattern template
- [x] 97 unit tests for all templates
- [x] XSS-safe DOM manipulation patterns

### v0.2.0
- [x] Password authentication
- [x] WebAuthn passkey support
- [x] OAuth2 CSRF protection
- [x] Basic token management
- [x] Admin/readonly role checks

---

## Contributing

To add items to this backlog:
1. Add under appropriate priority section
2. Include status, description, and implementation notes
3. Link related issues if applicable

## Notes for Claude Code

When working on backlog items:
1. Check CLAUDE.md for existing patterns
2. Add tests for new features (see `templates/*.test.js`)
3. Update CLAUDE.md documentation
4. Use `textContent` for user data (XSS prevention)
5. Follow existing code style in templates
