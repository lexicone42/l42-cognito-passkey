# Cedar Policy Authorization — Integration Plan

**Status**: Post-1.0, design documented
**Estimated effort**: ~3 focused days
**Dependencies**: `@cedar-policy/cedar-wasm` (v4.8.2, Apache-2.0, ~13 MB WASM)

## Overview

Replace hardcoded RBAC checks with the open-source Cedar policy engine. Cedar evaluates authorization decisions as `(principal, action, resource, context)` tuples against declarative `.cedar` policy files.

This is a **server-side feature** that pairs with handler mode. The 13 MB WASM bundle rules out client-side use. Existing client-side helpers (`isAdmin()`, `isReadonly()`) remain unchanged for UI hints.

## Why Cedar

- **Formal verification** — Cedar's type system catches invalid policies at write-time (e.g., referencing a nonexistent action), unlike our current string-based permissions (`'admin:delete-user'`)
- **Externalized policies** — Update authorization rules without redeploying (store `.cedar` files in S3, DynamoDB, or filesystem)
- **ABAC support** — Attribute-based conditions beyond simple role checks (resource ownership, time-of-day, IP ranges)
- **Self-hosted** — `@cedar-policy/cedar-wasm` runs in Node.js, Deno, browsers. No AWS managed service dependency

## Architecture

### Current Flow

```
Client                          Server
──────                          ──────
isAdmin() → UI hint only
requireServerAuthorization() → POST /auth/authorize
                                → manual role/permission checks
                                → { authorized: true/false }
```

### With Cedar

```
Client                          Server
──────                          ──────
isAdmin() → UI hint only        (unchanged)
requireServerAuthorization() → POST /auth/authorize
                                → Cedar engine evaluates policies
                                → { authorized: true/false }
```

The external API (`requireServerAuthorization()`) doesn't change. Cedar replaces the internals of the server endpoint.

## Implementation Plan

### Day 1: Schema + Policy Migration

**Goal**: Map existing RBAC concepts to Cedar types and write initial policies.

#### 1a. Define Cedar Schema

Map `STANDARD_ROLES` and `COGNITO_GROUPS` from `rbac-roles.js` to Cedar entity types:

```cedar
// schema.cedarschema
namespace App {
    entity User in [UserGroup] = {
        email: String,
        sub: String,
    };

    entity UserGroup;

    entity Resource = {
        owner: User,
        type: String,
    };

    // Map existing permission strings to typed actions
    action "read:content"  appliesTo { principal: User, resource: Resource };
    action "write:own"     appliesTo { principal: User, resource: Resource };
    action "write:all"     appliesTo { principal: User, resource: Resource };
    action "delete:own"    appliesTo { principal: User, resource: Resource };
    action "delete:all"    appliesTo { principal: User, resource: Resource };
    action "admin:manage"  appliesTo { principal: User, resource: Resource };
    action "api:read"      appliesTo { principal: User, resource: Resource };
    action "api:write"     appliesTo { principal: User, resource: Resource };
}
```

#### 1b. Write Policies

Translate `STANDARD_ROLES` permissions into `.cedar` policy files:

```cedar
// policies/admin.cedar
permit(
    principal in App::UserGroup::"administrators",
    action,
    resource
);

// policies/editor.cedar
permit(
    principal in App::UserGroup::"editors",
    action in [
        App::Action::"read:content",
        App::Action::"write:own",
        App::Action::"write:all",
        App::Action::"delete:own"
    ],
    resource
);

// policies/readonly.cedar
permit(
    principal in App::UserGroup::"readonly",
    action == App::Action::"read:content",
    resource
);

// policies/owner-only.cedar
permit(
    principal,
    action in [App::Action::"write:own", App::Action::"delete:own"],
    resource
) when { resource.owner == principal };
```

#### 1c. Cognito Group Mapping

The existing `COGNITO_GROUPS` aliases map to Cedar `UserGroup` parents:

```javascript
// "admin", "admins", "administrators" all resolve to App::UserGroup::"administrators"
function resolveCanonicalGroup(cognitoGroup) {
    for (const [key, config] of Object.entries(COGNITO_GROUPS)) {
        if (config.aliases.includes(cognitoGroup.toLowerCase())) {
            return config.canonical;
        }
    }
    return cognitoGroup; // passthrough unknown groups
}
```

### Day 2: Engine Integration

**Goal**: Wire Cedar engine into the Express handler mode backend.

#### 2a. Principal Builder

Map Cognito JWT claims to Cedar entities:

```javascript
import { UNSAFE_decodeJwtPayload, getUserGroups } from './auth.js';

function buildCedarPrincipal(tokens) {
    const claims = UNSAFE_decodeJwtPayload(tokens.idToken);
    const groups = getUserGroups();
    return {
        uid: { type: 'App::User', id: claims.sub },
        attrs: { email: claims.email },
        parents: groups.map(g => ({
            type: 'App::UserGroup',
            id: resolveCanonicalGroup(g)
        }))
    };
}
```

#### 2b. Engine Setup

```javascript
import { CedarInlineAuthorizationEngine } from '@cedar-policy/cedar-authorization';

const engine = new CedarInlineAuthorizationEngine({
    staticPolicies: loadPoliciesFromDirectory('./policies/'),
    schema: {
        type: 'jsonString',
        schema: fs.readFileSync('./schema.cedarschema.json', 'utf8')
    }
});
```

#### 2c. Authorization Endpoint

Replace manual checks in the `/auth/authorize` Express route:

```javascript
app.post('/auth/authorize', async (req, res) => {
    const { action, resource, context } = req.body;
    const principal = buildCedarPrincipal(req.session.tokens);

    const decision = engine.isAuthorized({
        principal: principal.uid,
        action: { type: 'App::Action', id: action },
        resource: { type: 'App::Resource', id: resource.id },
        context: { ...context, hour: new Date().getHours() },
        entities: [principal, ...buildGroupEntities()]
    });

    res.json({
        authorized: decision.decision === 'Allow',
        diagnostics: decision.diagnostics  // which policies matched
    });
});
```

#### 2d. Optional: Express Middleware

For apps that want per-route authorization instead of explicit calls:

```javascript
import { ExpressAuthorizationMiddleware } from '@cedar-policy/authorization-for-expressjs';

// Drop-in middleware that auto-maps routes to Cedar actions
const cedarMiddleware = new ExpressAuthorizationMiddleware({
    schema: { type: 'jsonString', schema: schemaJson },
    authorizationEngine: engine,
    principalConfiguration: {
        type: 'custom',
        getPrincipalEntity: (req) => buildCedarPrincipal(req.session.tokens)
    },
    skippedEndpoints: [
        { httpVerb: 'get', path: '/login' },
        { httpVerb: 'get', path: '/health' }
    ]
});
```

### Day 3: Tests + Config API

**Goal**: Test suite and the user-facing configuration surface.

#### 3a. Configuration

Add optional Cedar config to `configure()`:

```javascript
configure({
    clientId: 'xxx',
    cognitoDomain: 'xxx.auth.region.amazoncognito.com',
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    // New: Cedar authorization (server-side only)
    cedar: {
        policyDirectory: './policies/',
        schemaPath: './schema.cedarschema.json',
        // or inline:
        // policies: policyString,
        // schema: schemaJson,
    }
});
```

#### 3b. Tests

- Policy validation: schema catches malformed policies
- Admin supremacy: admin group permits all actions (mirrors existing property test)
- Owner-only: `write:own` denied when `resource.owner !== principal`
- Group alias resolution: all Cognito aliases map to correct Cedar groups
- Readonly restriction: readonly group can only `read:content`
- Context conditions: time-based deny policies work
- Missing principal: unauthenticated requests denied
- Diagnostics: response includes which policies matched

#### 3c. Migration Guide

Document in `docs/migration.md`:
- Cedar is optional — existing `isAdmin()`/`isReadonly()` keeps working
- `requireServerAuthorization()` API unchanged from caller's perspective
- How to write first policy file
- How to test policies locally before deploying

## Key Decisions (To Resolve)

1. **Policy loading**: Filesystem only? Or also support S3/DynamoDB for dynamic updates?
   - Recommendation: Start with filesystem, add remote loading later

2. **Client-side evaluation**: Skip for now (13 MB). Revisit if Cedar ships a lighter build
   - Keep `isAdmin()`/`isReadonly()` for client UI hints

3. **Policy hot-reload**: Watch filesystem for changes in dev mode?
   - Recommendation: Yes for dev, explicit reload for production

4. **Backward compatibility**: Keep `rbac-roles.js` as the "simple mode"?
   - Recommendation: Yes — Cedar is the advanced path, RBAC roles stay for simple apps

## npm Packages

| Package | Purpose | Size |
|---------|---------|------|
| `@cedar-policy/cedar-wasm` | Core WASM engine | ~13 MB |
| `@cedar-policy/cedar-authorization` | Higher-level JS wrapper | Small |
| `@cedar-policy/authorization-for-expressjs` | Express middleware | Small |

All Apache-2.0, maintained by AWS Cedar team.

## References

- [Cedar Policy Language Docs](https://docs.cedarpolicy.com/)
- [Cedar Playground](https://www.cedarpolicy.com/)
- [@cedar-policy/cedar-wasm on npm](https://www.npmjs.com/package/@cedar-policy/cedar-wasm)
- [Cedar Authorization for Express.js](https://github.com/cedar-policy/authorization-for-expressjs)
- [AWS Blog: Secure Express APIs with Cedar](https://aws.amazon.com/blogs/opensource/secure-your-application-apis-in-5-minutes-with-cedar/)
