# Changelog

All notable changes to this project will be documented in this file.

## [0.6.1] - 2026-01-21

### Added

- **Accessibility Guide**: `docs/accessibility.md` with comprehensive patterns for:
  - ARIA live regions for error announcements
  - Keyboard navigation for login forms
  - WebAuthn/passkey fallback guidance
  - Session timeout warnings
  - Focus management after login/logout
  - Screen reader testing checklist

## [0.6.0] - 2026-01-21

### Added

- **`onLogin(callback)`**: Subscribe to login events with tokens and auth method
  - Only fires on actual login (password, passkey, OAuth), never on token refresh
  - Callback receives `(tokens, method)` where method is 'password', 'passkey', or 'oauth'
  - Returns unsubscribe function
- **`onLogout(callback)`**: Subscribe to logout events
  - Fires when user logs out or tokens are cleared
  - Returns unsubscribe function
- **Claude-to-Claude workflow**: `docs/claude-workflow.md` for GitHub issue collaboration

### Changed

- **OAuth auth_method**: `exchangeCodeForTokens()` now sets `auth_method: 'oauth'` (was 'passkey')

## [0.5.7] - 2026-01-21

### Fixed

- **onAuthStateChange reload loop**: Token refresh no longer triggers `onAuthStateChange(true)`
  - Previously, `setTokens()` always notified listeners, causing infinite reload loops
  - Added `options.isRefresh` flag to skip notification during token refresh
  - `onAuthStateChange` now only fires on new login or logout, not token refresh

### Added

- **OCSF Security Logging**: Structured security events for AWS Security Lake integration
  - Configure via `securityLogger: 'console'` or custom function
  - Events for: login, logout, token refresh, passkey add/delete
  - OCSF v1.0 schema with Authentication (3001) and Account Change (3002) classes
  - See `docs/ocsf-logging.md` for integration guides

### Changed

- **Documentation reorganization**
  - Created `docs/migration.md` with complete v0.3→v0.5.x upgrade guide
  - Streamlined README from 203→127 lines, focused on quick start
  - Updated `docs/api-reference.md` with UNSAFE_ prefix and best practices

## [0.5.6] - 2026-01-21

### Added

- **GitHub Issue Processor**: `pnpm process-issue <number>` fetches and sanitizes GitHub issues
  - Uses `execFileSync` (no shell) to prevent command injection
  - Validates issue number as positive integer
  - Sanitizes all text content (removes control chars, limits length)
  - Detects suspicious patterns (shell injection, path traversal, script tags)
  - Verifies repository before fetching (prevents wrong-repo attacks)
  - Creates `.claude/issues/issue-<number>.md` with bug fix workflow checklist
  - Outputs are gitignored to prevent accidental commits

### Security

- Defense-in-depth against hostile GitHub issue content
- Unicode normalization to prevent homograph attacks

## [0.5.5] - 2026-01-21

### Added

- **Pre-commit hook**: Prevents committing src/auth.js without syncing dist/auth.js
  - Install with: `pnpm setup-hooks`
- **CI check**: Verifies dist/auth.js is in sync with src/auth.js
- **Auto-sync on release**: `npm version` now automatically syncs dist with src

### Scripts

- `pnpm check-dist` - Verify dist is in sync
- `pnpm sync-dist` - Auto-fix by copying src to dist
- `pnpm setup-hooks` - Install git hooks

## [0.5.4] - 2026-01-21

### Fixed

- **dist/auth.js sync**: The dist file was not updated with v0.5.2 and v0.5.3 changes
  - Now includes PKCE, HTTPS enforcement, cognitoDomain validation, and localStorage fix

## [0.5.3] - 2026-01-21

### Fixed

- **OAuth State Storage**: Switched from sessionStorage to localStorage to fix "Invalid OAuth state" errors
  - Safari ITP and Firefox ETP can clear sessionStorage during cross-domain OAuth redirects
  - localStorage survives cross-domain navigation while maintaining security (single-use, cleared immediately)
  - Also affects PKCE code verifier storage

### Added

- 6 new OAuth state storage tests (total: 174 tests)

## [0.5.2] - 2026-01-21

### Security

- **PKCE Implementation**: Added Proof Key for Code Exchange to prevent authorization code interception attacks
  - Generates cryptographically secure code verifier (RFC 7636 compliant)
  - SHA-256 code challenge sent with authorization request
  - Code verifier stored in localStorage and cleared after use (updated from sessionStorage in 0.5.3)

- **HTTPS Enforcement**: Redirect URIs must use HTTPS (except localhost for development)
  - Prevents token interception via network sniffing

- **Domain Validation**: Added cognitoDomain format validation
  - Prevents open redirect attacks via malicious authorization endpoints
  - Accepts standard Cognito domains and valid custom domains

- **Cookie Security Documentation**: Documented HttpOnly limitation
  - Client-side `document.cookie` cannot set HttpOnly (browser limitation)
  - Mitigations: Secure flag, SameSite=Lax, short-lived tokens

### Added

- **OAuth Security Test Suite**: 38 new tests covering:
  - PKCE code verifier/challenge generation
  - CSRF state parameter validation
  - Redirect URI validation
  - Token exchange security
  - Cookie security flags
  - HTTPS enforcement
  - Cognito domain validation

### Changed

- `loginWithHostedUI()` is now async (generates PKCE challenge)
- Total tests: 168 (was 130)

## [0.5.1] - 2026-01-21

### Added

- **Documentation Validation**: `pnpm validate-docs` script checks:
  - Version references in CLAUDE.md files match package.json
  - Test counts are accurate
  - Referenced files exist

- **Updated CLAUDE.md Files**: Comprehensive Claude Code integration guides with:
  - Current version and test counts
  - Release commands (patch/minor/major)
  - Security patterns and best practices
  - RBAC system documentation
  - Troubleshooting guides

### Changed

- CI now runs documentation validation on Node 20
- Version sync script now updates CLAUDE.md version references
- Plugin name standardized to `l42-cognito-passkey`

## [0.5.0] - 2026-01-21

### Added

- **CI/CD Pipeline**: GitHub Actions workflows for automated testing and publishing
  - `ci.yml`: Runs tests on PRs and pushes to main (Node 18, 20, 22)
  - `publish.yml`: Publishes to npm on version tags, creates GitHub releases

- **Semantic Versioning Automation**: Version bump scripts that keep all files in sync
  - `pnpm release:patch` - Bug fixes (0.5.0 → 0.5.1)
  - `pnpm release:minor` - New features (0.5.0 → 0.6.0)
  - `pnpm release:major` - Breaking changes (0.5.0 → 1.0.0)
  - `pnpm release:prerelease` - Pre-release versions (0.5.1-rc.0)

- **Version Sync Script**: `scripts/sync-version.js` automatically updates version in:
  - `src/auth.js` (@version JSDoc)
  - `plugin/plugin.json`
  - All documentation files

- **Release Documentation**: `docs/RELEASING.md` with complete release process

### Changed

- All previous versions are now preserved on npm (semantic versioning)
- Version consistency tests now run in CI

## [0.4.0] - 2026-01-21

### Security Improvements

- **`UNSAFE_decodeJwtPayload()`**: Renamed from `decodeJwtPayload()` to clearly indicate
  the function returns UNVERIFIED claims. The old function name still works but emits
  a deprecation warning. This prevents developers from accidentally using JWT claims
  for authorization decisions.

- **`requireServerAuthorization()`**: New helper that enforces server-side authorization
  checks. Makes the secure path (server validation) the easy path:
  ```javascript
  const result = await auth.requireServerAuthorization('admin:delete-user');
  if (!result.authorized) throw new Error(result.reason);
  ```

- **`UI_ONLY_hasRole()`**: Explicitly named function for client-side role checks that
  are ONLY for UI display purposes (showing/hiding buttons). The name reminds developers
  this is not for authorization.

- **ccTLD Cookie Domain Fix**: Cookie domain detection now correctly handles country-code
  TLDs like `.co.uk`, `.com.au`, `.co.jp` (30+ public suffixes supported). Previously,
  `app.example.co.uk` would incorrectly set domain to `.co.uk`.

### Added

- **Cognito Group Aliases**: `COGNITO_GROUPS` constant centralizes group name handling
  with alias support. Handles singular/plural variations automatically:
  ```javascript
  import { isInCognitoGroup } from './rbac-roles.js';
  isInCognitoGroup(groups, 'ADMIN'); // matches 'admin', 'admins', 'administrators'
  ```

- **`isInCognitoGroup()`**: Case-insensitive group membership check with alias support
- **`isInAnyCognitoGroup()`**: Check membership in any of multiple groups
- **`getCanonicalGroupName()`**: Get standard group name for Cognito configuration

- **Property-Based Tests**: 22 new tests using fast-check that verify RBAC invariants:
  - Role hierarchy transitivity
  - Admin supremacy (level 100, wildcard permissions)
  - Permission inheritance
  - Cognito group alias consistency
  - Role management anti-reflexivity

- **CLAUDE.md**: Integration guide for Claude Code instances
- **docs/cedar-integration.md**: AWS Cedar + Verified Permissions design document

### Changed

- `decodeJwtPayload()` now emits deprecation warning (use `UNSAFE_decodeJwtPayload()`)
- `parseJwt()` now emits deprecation warning (use `UNSAFE_decodeJwtPayload()`)

### Developer Experience

- Added `fast-check` as dev dependency for property-based testing
- All 119 tests pass (97 existing + 22 new property-based)

## [0.3.0] - 2026-01-21

### Added

- **RBAC Role System**: Comprehensive role definitions in `plugin/templates/rbac-roles.js`
  - 3 core roles: `admin`, `readonly`, `user`
  - 20+ standard roles for common patterns
  - Role hierarchy with level-based permissions (10-100)
  - Permission checking: `hasPermission()`, `canManageRole()`, `getRoleHierarchy()`
  - Cognito group mapping: `getCognitoGroupConfig()`

- **Static Site Pattern** (`plugin/templates/static-site-pattern.html`)
  - Public static site + protected auth area architecture
  - Roles: readonly, user, editor, reviewer, publisher, admin
  - 27 unit tests for RBAC and permission logic

- **Multi-User WASM Pattern** (`plugin/templates/wasm-multiuser-pattern.html`)
  - Real-time WebSocket + WASM architecture for collaborative apps
  - Role hierarchy: player (10) → moderator (30) → dm (50) → admin (100)
  - Session management with 6-character codes (excludes confusing chars)
  - DM controls overlay for session management
  - 29 unit tests for roles, permissions, and session logic

- **Admin Panel Pattern** (`plugin/templates/admin-panel-pattern.html`)
  - Admin-only interface for user management
  - User listing with search/filter and pagination
  - User invitation via email with role assignment
  - User enable/disable and password reset
  - Audit logging for admin actions
  - 41 unit tests for access control, invitations, and filtering

- **XSS-Safe Patterns**: All templates use `textContent` for user data
- **CSP Requirements**: Documented Content-Security-Policy headers
- **Test Framework**: Vitest integration with `npm test`
- **BACKLOG.md**: Documented future features and priorities

### Changed

- Session codes now exclude confusing characters (0, O, 1, I, L)
- Updated plugin/CLAUDE.md with comprehensive documentation

### Fixed

- Session code generator test was using outdated character set

## [0.2.0] - 2026-01-21

### Breaking Changes

- **Self-hosted by default**: Library is now designed to be self-hosted. Copy `src/auth.js` to your project.
- **Configuration required**: Must call `configure()` or set `window.L42_AUTH_CONFIG` before using auth functions.
- **Token storage key changed**: Default key is now `l42_auth_tokens` (was `lexicone_auth_tokens`).

### Added

- `VERSION` export for checking library version
- `isConfigured()` function to check configuration status
- Auto-configuration from `window.L42_AUTH_CONFIG`
- Configurable `allowedDomains` for redirect URI validation
- Configurable `cookieDomain` (auto-detected if not set)
- Better error messages when configuration is missing
- Comprehensive documentation (README, API reference, Cognito setup guide)
- Example files for basic usage
- `cognito-setup.py` script for WebAuthn configuration

### Changed

- Allowed domains now auto-include current domain (no explicit allowlist needed for same-domain)
- Cookie domain is auto-detected based on hostname
- Error messages are more descriptive and actionable

### Fixed

- CORS issues when importing from different domains (now self-hosted)
- Hardcoded domain restrictions that blocked third-party integrations
- Hardcoded cookie domain that prevented cross-domain usage
- Token exchange failures when `configure()` not called (now gives clear error)

### Removed

- Hardcoded `lexicone.com` domain restrictions
- CDN dependency (library is self-hosted)

## [0.1.1] - 2026-01-18

### Added

- Token refresh behavior varies by auth method (1-day for password, 30-day for passkey)
- `ensureValidTokens()` for automatic token refresh before API calls
- `getAuthMethod()` to check current auth method
- `shouldRefreshToken()` for proactive refresh checking

### Changed

- OAuth flow now sets `auth_method: 'passkey'` for longer refresh period

## [0.1.0] - 2026-01-15

### Added

- Initial release
- Password authentication via Cognito USER_PASSWORD_AUTH
- WebAuthn passkey authentication
- OAuth2 flow with CSRF protection
- Token management with localStorage
- Cross-subdomain cookie for Lambda@Edge validation
- RBAC via Cognito groups (admin, readonly)
- Auth state change listeners
- Passkey management (list, register, delete)
