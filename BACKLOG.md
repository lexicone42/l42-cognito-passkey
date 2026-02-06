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
- ~~Tree-shaking support~~ → Bundler hints added in v0.12.2 (`sideEffects: false`, `/*#__PURE__*/`)

### ~~Client-Side Login Rate Limiting~~ → Completed in v0.12.1

## Post-1.0: Advanced Authorization

### Cedar Policy Authorization
**Status**: Design complete, implementation post-1.0
**Description**: Externalized authorization via open-source Cedar (`@cedar-policy/cedar-wasm`).

Cedar is the policy language behind Amazon Verified Permissions, but the open-source WASM engine
runs anywhere — Lambda, Express middleware, or even client-side for offline-capable apps.
No AWS managed service dependency required.

Benefits:
- Formal policy verification (Cedar's type system catches invalid policies)
- Externalized policies (update without deploy — store in S3, DynamoDB, etc.)
- Native JWT claim support (map Cognito groups to Cedar principals)
- ABAC beyond simple role checks (attribute-based conditions, resource hierarchies)
- Self-hosted: `@cedar-policy/cedar-wasm` runs in Node.js, Deno, and browsers

### Semgrep Security Rules
**Status**: Post-1.0
**Description**: Custom Semgrep rules for security patterns.
- XSS prevention (innerHTML vs textContent)
- Auth check enforcement
- Token handling patterns

---

## Completed

### v0.12.2
- [x] **Tree-Shaking Support** — `sideEffects: false` + `/*#__PURE__*/` annotations on 11 constants
- [x] Cedar backlog updated for open-source `@cedar-policy/cedar-wasm`

### v0.12.1
- [x] **Client-Side Login Rate Limiting** — exponential backoff on failed login attempts
- [x] Per-email tracking with `maxLoginAttemptsBeforeDelay`, `loginBackoffBaseMs`, `loginBackoffMaxMs` config
- [x] `getLoginAttemptInfo()` for UI display
- [x] OCSF HIGH severity on threshold breach, CRITICAL on Cognito lockout
- [x] Cognito account lockout detection and clear error messaging
- [x] 40 new tests (532 total)

### v0.12.0
- [x] **Conditional UI / Passkey Autofill** — `loginWithConditionalUI()` with Mode A (email known, single prompt) and Mode B (discovery, two prompts)
- [x] **Conditional Create / Passkey Upgrade** — `upgradeToPasskey()` with silent registration, `autoUpgradeToPasskey` config
- [x] **Token Validation on Load** — `validateTokenClaims()` checks issuer, client_id, unreasonable expiry
- [x] **WebAuthn `getClientCapabilities()`** — Level 3 API support in `getPasskeyCapabilities()`, `detectWebView()`
- [x] **`registerPasskey()` Default Improvements** — `residentKey: 'required'`, no platform-only restriction, configurable options
- [x] AbortController management for conditional UI
- [x] `buildAssertionResponse()` and `buildCredentialResponse()` helper extraction
- [x] TypeScript declarations for all new features
- [x] 108 new tests (492 total)

### v0.11.0
- [x] Debug Logging & Diagnostics (`debug` config, `getDebugHistory()`, `getDiagnostics()`, `clearDebugHistory()`)
- [x] 34 debug diagnostics tests
- [x] 384 total tests

### v0.10.0
- [x] Remove speculative features (WebSocket auth, deprecated aliases, domain RBAC roles)
- [x] Design decisions documentation (`docs/design-decisions.md`)
- [x] 1,721 lines removed, 379 tests passing

### v0.9.0
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
