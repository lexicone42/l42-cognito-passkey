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

### Token Refresh Implementation
**Status**: Partially implemented
**Description**: Complete automatic token refresh flow with proper error handling.
- Currently relies on `ensureValidTokens()` being called manually
- Add background refresh for long-running sessions
- Handle refresh token expiry gracefully

### Automated JavaScript Tests
**Status**: Templates created, framework pending
**Description**: Set up automated test runner for all templates.
- Configure Vitest or Jest
- Add CI/CD integration
- Target >80% coverage for RBAC functions

## Priority: Medium

### Contentful CMS Integration
**Status**: Backlog (role mapping defined)
**Description**: Integrate with Contentful for headless CMS workflows.

**Planned Features**:
- Map l42 roles to Contentful space roles
- Sync user permissions between Cognito and Contentful
- Webhook handlers for content publish events
- SSG trigger on content changes

**Role Mapping** (tentative):
| l42 Role | Contentful Role |
|----------|-----------------|
| editor | Editor |
| reviewer | Content Reviewer |
| publisher | Publisher |
| admin | Admin |

**Implementation Notes**:
- Use Contentful Management API for role sync
- Consider Contentful webhooks for real-time updates
- May need Lambda function for webhook handling

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
- Currently CDN-only distribution
- Would enable `npm install l42-cognito-passkey`
- TypeScript definitions
- Tree-shaking support

## Priority: Low

### Additional RBAC Role Templates

#### Healthcare Roles
- `patient`, `nurse`, `doctor`, `admin`
- HIPAA compliance considerations

#### Education Roles
- `student`, `teacher`, `ta`, `admin`
- Course-based permissions

#### SaaS Multi-Tier
- `free`, `pro`, `enterprise`, `admin`
- Feature gating by tier

### WebSocket Auth Middleware
**Status**: Planned
**Description**: Authentication middleware for WebSocket connections.
- Token validation on connect
- Auto-disconnect on token expiry
- Reconnect with refresh flow

### Passkey Cross-Device Support
**Status**: Research
**Description**: Improve passkey UX across devices.
- QR code flow for cross-device auth
- Platform authenticator detection
- Graceful fallback to password

## Post-1.0: Advanced Authorization

### AWS Cedar Integration
**Status**: Design complete, implementation post-1.0
**Description**: Externalized authorization via Amazon Verified Permissions.
**Design Doc**: `docs/cedar-integration.md`

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

### v0.4.0 (Current)
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
