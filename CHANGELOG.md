# Changelog

All notable changes to this project will be documented in this file.

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

## [1.1.0] - 2026-01-18

### Added

- Token refresh behavior varies by auth method (1-day for password, 30-day for passkey)
- `ensureValidTokens()` for automatic token refresh before API calls
- `getAuthMethod()` to check current auth method
- `shouldRefreshToken()` for proactive refresh checking

### Changed

- OAuth flow now sets `auth_method: 'passkey'` for longer refresh period

## [1.0.0] - 2026-01-15

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
