# Changelog

All notable changes to this project will be documented in this file.

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
