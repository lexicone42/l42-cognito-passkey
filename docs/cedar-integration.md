# Cedar Policy Authorization

**Status**: Implemented (v0.13.0)
**Dependencies**: `@cedar-policy/cedar-wasm` (v4.8.2, Apache-2.0, ~4.3 MB runtime)
**Tests**: 101 (including 5 property-based tests)

## Overview

Cedar replaces hardcoded RBAC checks with declarative policy evaluation. Authorization decisions are `(principal, action, resource, context)` tuples evaluated against `.cedar` policy files by the Cedar WASM engine.

This is a **server-side feature** that pairs with handler mode. The WASM bundle rules out client-side use. Existing client-side helpers (`isAdmin()`, `isReadonly()`) remain unchanged for UI hints.

## Architecture

```
Client                          Server
──────                          ──────
isAdmin() → UI hint only        (unchanged)
requireServerAuthorization() → POST /auth/authorize
                                → Cedar engine evaluates policies
                                → { authorized: true/false, reason, diagnostics }
```

The client-side API (`requireServerAuthorization()`) doesn't change. Cedar replaces the internals of the server endpoint.

## File Layout

```
examples/backends/express/
├── server.js                    # Express server with /auth/authorize endpoint
├── cedar-engine.js              # Cedar WASM wrapper (~300 lines)
└── cedar/
    ├── schema.cedarschema.json  # Cedar JSON schema (entity types + actions)
    └── policies/
        ├── admin.cedar          # Admin wildcard permit
        ├── editor.cedar         # Content editing
        ├── reviewer.cedar       # Content review
        ├── publisher.cedar      # Content publishing + deploy
        ├── readonly.cedar       # Read-only access
        ├── user.cedar           # Standard user (own resources)
        ├── moderator.cedar      # Community moderation
        ├── developer.cedar      # Dev tools, APIs, logs
        └── owner-only.cedar     # Ownership enforcement (forbid)
```

## Cedar Schema

The schema maps existing RBAC concepts to Cedar types:

| Cedar Type | Maps From | Description |
|------------|-----------|-------------|
| `App::User` | JWT `sub` claim | Authenticated user principal |
| `App::UserGroup` | Cognito groups | Role groups (admin, editors, etc.) |
| `App::Resource` | Request body | Resource being accessed |

### Actions (23 total)

All permission strings from `rbac-roles.js` are mapped to typed Cedar actions:

```
read:content, write:content, publish:content, approve:content, reject:content
read:own, write:own, delete:own, read:all, write:all, delete:all
deploy:static, read:users, mute:users, kick:users, manage:chat
api:read, api:write, read:logs, read:metrics, debug:view
admin:manage, admin:delete-user
```

### Resource Attributes

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `resourceType` | String | Yes | Type of resource (default: `"application"`) |
| `owner` | Entity (User) | No | Resource owner for ownership enforcement |

## Cedar Engine (`cedar-engine.js`)

### Initialization

```javascript
import { initCedarEngine, authorize } from './cedar-engine.js';

await initCedarEngine({
    schemaPath: './cedar/schema.cedarschema.json',
    policyDir: './cedar/policies/'
});
```

Options:

| Option | Type | Description |
|--------|------|-------------|
| `schemaPath` | string | Path to Cedar JSON schema file |
| `policyDir` | string | Directory containing `.cedar` policy files |
| `schema` | object | Inline Cedar JSON schema (alternative to `schemaPath`) |
| `policies` | string | Inline Cedar policy text (alternative to `policyDir`) |
| `resolveGroup` | function | Custom Cognito group → Cedar group resolver |

### Authorization

```javascript
const result = await authorize({
    session: req.session,
    action: 'admin:delete-user',
    resource: { id: 'doc-123', type: 'document', owner: 'user-sub-456' },
    context: {}
});
// { authorized: boolean, reason: string, diagnostics: object }
```

### Group Alias Resolution

Cognito group names are resolved to Cedar `UserGroup` entity IDs using the same alias mapping from `rbac-roles.js`:

```
'admin', 'admins', 'administrators' → 'admin'
'readonly', 'read-only', 'viewer'   → 'readonly'
'editor', 'editors'                 → 'editors'
'dev', 'devs', 'developer'          → 'developers'
```

Custom resolution is supported via the `resolveGroup` option.

### Performance

The engine uses Cedar's `statefulIsAuthorized` with pre-parsed policies and schema. Per-request evaluation is typically <0.1ms vs ~1-5ms for `isAuthorized` with on-the-fly parsing.

### Fail-Closed Design

If Cedar fails to initialize (e.g., invalid schema), the server still starts but `/auth/authorize` returns HTTP 503:

```json
{ "error": "Authorization engine not available", "authorized": false }
```

## Writing Policies

### Basic Permit

```cedar
@id("editor-content")
permit(
    principal in App::UserGroup::"editors",
    action in [
        App::Action::"read:content",
        App::Action::"write:content",
        App::Action::"publish:content"
    ],
    resource
);
```

### Admin Wildcard

```cedar
@id("admin-permit-all")
permit(
    principal in App::UserGroup::"admin",
    action,
    resource
);
```

### Ownership Enforcement (forbid)

Cedar's `forbid` always overrides `permit`. This pattern denies non-owners from writing/deleting owned resources:

```cedar
@id("deny-non-owner-write")
forbid(
    principal,
    action == App::Action::"write:own",
    resource
) when { resource has owner && resource.owner != principal };
```

The `when { resource has owner && ... }` pattern is required for Cedar's validator to prove safe access to the optional `owner` attribute. If the caller omits `resource.owner`, the `has` check fails and the forbid does not fire — permit policies still apply.

## Entity Provider Interface (Post-1.0)

The `authorize()` function accepts an optional `entityProvider` parameter for loading entities from external stores:

```javascript
// Future: load entities from DynamoDB, Redis, etc.
const provider = {
    async getEntities(claims, resource, context) {
        // Return Cedar EntityJson[]
        return [
            { uid: { type: 'App::User', id: claims.sub }, attrs: {...}, parents: [...] },
            // ...
        ];
    }
};

const result = await authorize({
    session: req.session,
    action: 'write:own',
    resource: { id: 'doc-123' },
    entityProvider: provider
});
```

Default behavior (no provider): builds entities from the current request (JWT claims + request body).

## Testing

101 tests cover:

| Category | Count | Description |
|----------|-------|-------------|
| Policy Validation | 5 | Schema/policy parsing and validation |
| Admin Supremacy | 24 | Admin permits all actions |
| Role-Based Access | 16 | Editor, reviewer, publisher, moderator, developer |
| Readonly Restriction | 16 | Readonly denies all write/admin actions |
| User Own-Resource | 4 | Standard user permissions |
| Ownership Enforcement | 7 | Forbid policies for non-owner access |
| Unauthenticated | 2 | Missing groups denied |
| Multi-Group | 2 | Users in multiple groups |
| Diagnostics | 2 | Policy evaluation diagnostics |
| Engine Integration | 5 | `authorize()` function via cedar-engine.js |
| Group Aliases | 8 | Cognito group alias resolution |
| Initialization Errors | 3 | Missing schema/policy handling |
| Property-Based | 5 | fast-check invariants |
| Schema-RBAC Consistency | 3 | Schema matches rbac-roles.js |

Run Cedar tests:
```bash
pnpm test -- cedar-authorization
```

## License

`@cedar-policy/cedar-wasm` is Apache-2.0, same as this project. No license conflicts.

## References

- [Cedar Policy Language Docs](https://docs.cedarpolicy.com/)
- [Cedar Playground](https://www.cedarpolicy.com/)
- [@cedar-policy/cedar-wasm on npm](https://www.npmjs.com/package/@cedar-policy/cedar-wasm)
