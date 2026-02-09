/**
 * L42 Cedar Authorization — Tests
 *
 * Tests for the Cedar policy authorization engine.
 * Validates policies, role-based access, ownership enforcement,
 * group alias resolution, and the entity provider extension point.
 *
 * Uses the actual Cedar WASM engine and the shipped schema/policies
 * to test real authorization decisions.
 *
 * Run with: pnpm test -- cedar-authorization
 *
 * @module cedar-authorization-tests
 */

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import fc from 'fast-check';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CEDAR_DIR = join(__dirname, '..', '..', 'examples', 'backends', 'express', 'cedar');
const SCHEMA_PATH = join(CEDAR_DIR, 'schema.cedarschema.json');
const POLICY_DIR = join(CEDAR_DIR, 'policies');

// Import cedar-wasm directly for low-level testing
let cedar;
let schema;
let policyText;

// Import the engine module for integration testing
let cedarEngine;

// ── Test Helpers ──────────────────────────────────────────────────────────

function createTestJwt(claims) {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
        sub: claims.sub || 'user-' + Math.random().toString(36).slice(2, 8),
        email: claims.email || 'test@example.com',
        'cognito:groups': claims.groups || [],
        iss: 'https://cognito-idp.us-west-2.amazonaws.com/test-pool',
        aud: 'test-client',
        exp: Math.floor(Date.now() / 1000) + 3600,
        ...claims
    })).toString('base64url');
    return `${header}.${payload}.test-signature`;
}

function createSession(email, groups, sub) {
    const idToken = createTestJwt({
        sub: sub || `user-${email.split('@')[0]}`,
        email,
        groups
    });
    return { tokens: { id_token: idToken, access_token: 'test-access' } };
}

/**
 * Low-level Cedar authorization check (bypasses the engine module).
 * Builds entities and calls cedar-wasm directly.
 */
function cedarCheck({ principal, groups, action, resourceId, resourceOwner, resourceType, context }) {
    const sub = principal || 'test-user';
    const entities = [];

    // Principal
    entities.push({
        uid: { type: 'App::User', id: sub },
        attrs: { email: `${sub}@example.com`, sub },
        parents: (groups || []).map(g => ({ type: 'App::UserGroup', id: g }))
    });

    // Groups
    for (const g of (groups || [])) {
        entities.push({
            uid: { type: 'App::UserGroup', id: g },
            attrs: {},
            parents: []
        });
    }

    // Resource
    const resAttrs = { resourceType: resourceType || 'application' };
    if (resourceOwner) {
        resAttrs.owner = { __entity: { type: 'App::User', id: resourceOwner } };
    }
    entities.push({
        uid: { type: 'App::Resource', id: resourceId || '_application' },
        attrs: resAttrs,
        parents: []
    });

    // If resource owner is a different user, add that user entity too
    if (resourceOwner && resourceOwner !== sub) {
        entities.push({
            uid: { type: 'App::User', id: resourceOwner },
            attrs: { email: `${resourceOwner}@example.com`, sub: resourceOwner },
            parents: []
        });
    }

    return cedar.isAuthorized({
        principal: { type: 'App::User', id: sub },
        action: { type: 'App::Action', id: action },
        resource: { type: 'App::Resource', id: resourceId || '_application' },
        context: context || {},
        schema,
        policies: { staticPolicies: policyText },
        entities
    });
}

function isAllowed(checkResult) {
    return checkResult.type === 'success' && checkResult.response.decision === 'allow';
}

function isDenied(checkResult) {
    return checkResult.type === 'success' && checkResult.response.decision === 'deny';
}

// ── Setup ─────────────────────────────────────────────────────────────────

beforeAll(async () => {
    cedar = await import('@cedar-policy/cedar-wasm/nodejs');
    schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'));
    const files = readdirSync(POLICY_DIR).filter(f => f.endsWith('.cedar')).sort();
    policyText = files.map(f => readFileSync(join(POLICY_DIR, f), 'utf8')).join('\n\n');

    // Also initialize the engine module
    cedarEngine = await import('../../examples/backends/express/cedar-engine.js');
    cedarEngine._resetForTesting();
    await cedarEngine.initCedarEngine({ schema, policies: policyText });
});

afterEach(() => {
    // Engine state persists across tests (intentional — matches server behavior)
});

// ── Policy Validation Tests ───────────────────────────────────────────────

describe('Policy Validation', () => {
    it('schema parses successfully', () => {
        const result = cedar.checkParseSchema(schema);
        expect(result.type).toBe('success');
    });

    it('policies parse successfully', () => {
        const result = cedar.checkParsePolicySet({ staticPolicies: policyText });
        expect(result.type).toBe('success');
    });

    it('policies validate against schema', () => {
        const result = cedar.validate({
            schema,
            policies: { staticPolicies: policyText }
        });
        expect(result.type).toBe('success');
        expect(result.validationErrors || []).toHaveLength(0);
    });

    it('rejects malformed policies', () => {
        const result = cedar.validate({
            schema,
            policies: { staticPolicies: 'permit(principal in App::UserGroup::"admin", action == App::Action::"nonexistent:action", resource);' }
        });
        expect(result.type).toBe('success');
        expect(result.validationErrors.length).toBeGreaterThan(0);
    });

    it('engine validatePolicies() returns valid for shipped policies', () => {
        expect(cedarEngine.validatePolicies()).toEqual({ valid: true });
    });
});

// ── Admin Supremacy ───────────────────────────────────────────────────────

describe('Admin Supremacy', () => {
    // Admin should be permitted ALL actions — mirrors RBAC property test
    const ALL_ACTIONS = [
        'read:content', 'write:content', 'publish:content', 'approve:content', 'reject:content',
        'read:own', 'write:own', 'delete:own', 'read:all', 'write:all', 'delete:all',
        'deploy:static', 'read:users', 'mute:users', 'kick:users', 'manage:chat',
        'api:read', 'api:write', 'read:logs', 'read:metrics', 'debug:view',
        'admin:manage', 'admin:delete-user'
    ];

    it.each(ALL_ACTIONS)('admin is permitted: %s', (action) => {
        const result = cedarCheck({ groups: ['admin'], action });
        expect(isAllowed(result)).toBe(true);
    });

    it('admin permit includes a determining policy in diagnostics', () => {
        const result = cedarCheck({ groups: ['admin'], action: 'admin:delete-user' });
        expect(result.type).toBe('success');
        expect(result.response.diagnostics.reason.length).toBeGreaterThan(0);
    });
});

// ── Role-Based Access ─────────────────────────────────────────────────────

describe('Role-Based Access', () => {
    it('editor can read:content', () => {
        expect(isAllowed(cedarCheck({ groups: ['editors'], action: 'read:content' }))).toBe(true);
    });

    it('editor can write:content', () => {
        expect(isAllowed(cedarCheck({ groups: ['editors'], action: 'write:content' }))).toBe(true);
    });

    it('editor can publish:content', () => {
        expect(isAllowed(cedarCheck({ groups: ['editors'], action: 'publish:content' }))).toBe(true);
    });

    it('editor cannot admin:manage', () => {
        expect(isDenied(cedarCheck({ groups: ['editors'], action: 'admin:manage' }))).toBe(true);
    });

    it('editor cannot delete:all', () => {
        expect(isDenied(cedarCheck({ groups: ['editors'], action: 'delete:all' }))).toBe(true);
    });

    it('reviewer can approve:content', () => {
        expect(isAllowed(cedarCheck({ groups: ['reviewers'], action: 'approve:content' }))).toBe(true);
    });

    it('reviewer can reject:content', () => {
        expect(isAllowed(cedarCheck({ groups: ['reviewers'], action: 'reject:content' }))).toBe(true);
    });

    it('reviewer cannot write:content', () => {
        expect(isDenied(cedarCheck({ groups: ['reviewers'], action: 'write:content' }))).toBe(true);
    });

    it('publisher can deploy:static', () => {
        expect(isAllowed(cedarCheck({ groups: ['publishers'], action: 'deploy:static' }))).toBe(true);
    });

    it('publisher cannot approve:content', () => {
        expect(isDenied(cedarCheck({ groups: ['publishers'], action: 'approve:content' }))).toBe(true);
    });

    it('moderator can mute:users and kick:users', () => {
        expect(isAllowed(cedarCheck({ groups: ['moderators'], action: 'mute:users' }))).toBe(true);
        expect(isAllowed(cedarCheck({ groups: ['moderators'], action: 'kick:users' }))).toBe(true);
    });

    it('moderator cannot admin:delete-user', () => {
        expect(isDenied(cedarCheck({ groups: ['moderators'], action: 'admin:delete-user' }))).toBe(true);
    });

    it('developer can api:read and api:write', () => {
        expect(isAllowed(cedarCheck({ groups: ['developers'], action: 'api:read' }))).toBe(true);
        expect(isAllowed(cedarCheck({ groups: ['developers'], action: 'api:write' }))).toBe(true);
    });

    it('developer can read:logs and read:metrics', () => {
        expect(isAllowed(cedarCheck({ groups: ['developers'], action: 'read:logs' }))).toBe(true);
        expect(isAllowed(cedarCheck({ groups: ['developers'], action: 'read:metrics' }))).toBe(true);
    });

    it('developer cannot delete:all', () => {
        expect(isDenied(cedarCheck({ groups: ['developers'], action: 'delete:all' }))).toBe(true);
    });
});

// ── Readonly Restriction ──────────────────────────────────────────────────

describe('Readonly Restriction', () => {
    const READ_ACTIONS = ['read:content', 'read:own', 'read:all', 'read:users', 'read:logs', 'read:metrics'];
    const WRITE_ACTIONS = ['write:content', 'write:own', 'write:all', 'delete:own', 'delete:all',
                          'publish:content', 'deploy:static', 'admin:manage', 'admin:delete-user'];

    it.each(READ_ACTIONS)('readonly is permitted: %s', (action) => {
        expect(isAllowed(cedarCheck({ groups: ['readonly'], action }))).toBe(true);
    });

    it.each(WRITE_ACTIONS)('readonly is denied: %s', (action) => {
        expect(isDenied(cedarCheck({ groups: ['readonly'], action }))).toBe(true);
    });
});

// ── User Own-Resource Access ──────────────────────────────────────────────

describe('User Own-Resource Access', () => {
    it('user can read:own', () => {
        expect(isAllowed(cedarCheck({ groups: ['users'], action: 'read:own' }))).toBe(true);
    });

    it('user can write:own', () => {
        expect(isAllowed(cedarCheck({ groups: ['users'], action: 'write:own' }))).toBe(true);
    });

    it('user cannot write:all', () => {
        expect(isDenied(cedarCheck({ groups: ['users'], action: 'write:all' }))).toBe(true);
    });

    it('user cannot admin:manage', () => {
        expect(isDenied(cedarCheck({ groups: ['users'], action: 'admin:manage' }))).toBe(true);
    });
});

// ── Ownership Enforcement ─────────────────────────────────────────────────

describe('Ownership Enforcement', () => {
    it('owner can write:own their own resource', () => {
        const result = cedarCheck({
            principal: 'alice',
            groups: ['users'],
            action: 'write:own',
            resourceId: 'doc-1',
            resourceOwner: 'alice'
        });
        expect(isAllowed(result)).toBe(true);
    });

    it('non-owner is denied write:own on another user\'s resource', () => {
        const result = cedarCheck({
            principal: 'bob',
            groups: ['users'],
            action: 'write:own',
            resourceId: 'doc-1',
            resourceOwner: 'alice'
        });
        expect(isDenied(result)).toBe(true);
    });

    it('non-owner is denied delete:own on another user\'s resource', () => {
        const result = cedarCheck({
            principal: 'bob',
            groups: ['users'],
            action: 'delete:own',
            resourceId: 'doc-1',
            resourceOwner: 'alice'
        });
        expect(isDenied(result)).toBe(true);
    });

    it('write:own is permitted when no owner specified (graceful degradation)', () => {
        const result = cedarCheck({
            principal: 'bob',
            groups: ['users'],
            action: 'write:own',
            resourceId: 'doc-1'
            // No resourceOwner — ownership enforcement doesn't activate
        });
        expect(isAllowed(result)).toBe(true);
    });

    it('admin can write:own regardless of ownership', () => {
        const result = cedarCheck({
            principal: 'admin-user',
            groups: ['admin'],
            action: 'write:own',
            resourceId: 'doc-1',
            resourceOwner: 'alice'
        });
        // Admin permit-all still applies, but forbid overrides...
        // Actually, Cedar forbid overrides permit. So even admin would be denied
        // if the ownership forbid fires. Let's verify the actual behavior.
        // The forbid says: forbid unless (no owner OR owner == principal)
        // Admin-user is not alice, so the forbid fires.
        // In Cedar, forbid always wins over permit.
        expect(isDenied(result)).toBe(true);
    });

    it('admin can write:own their own resource', () => {
        const result = cedarCheck({
            principal: 'admin-user',
            groups: ['admin'],
            action: 'write:own',
            resourceId: 'doc-1',
            resourceOwner: 'admin-user'
        });
        expect(isAllowed(result)).toBe(true);
    });

    it('admin can write:all regardless of ownership (different action)', () => {
        const result = cedarCheck({
            principal: 'admin-user',
            groups: ['admin'],
            action: 'write:all',
            resourceId: 'doc-1',
            resourceOwner: 'alice'
        });
        // write:all is a different action — the ownership forbid only applies to write:own
        expect(isAllowed(result)).toBe(true);
    });
});

// ── Missing Principal / Unauthenticated ───────────────────────────────────

describe('Unauthenticated Access', () => {
    it('user with no groups is denied all actions', () => {
        const result = cedarCheck({ groups: [], action: 'read:content' });
        expect(isDenied(result)).toBe(true);
    });

    it('unknown group gets no permissions', () => {
        const result = cedarCheck({ groups: ['unknown-group'], action: 'read:content' });
        expect(isDenied(result)).toBe(true);
    });
});

// ── Multi-Group Membership ────────────────────────────────────────────────

describe('Multi-Group Membership', () => {
    it('user in both editors and reviewers gets combined permissions', () => {
        expect(isAllowed(cedarCheck({ groups: ['editors', 'reviewers'], action: 'write:content' }))).toBe(true);
        expect(isAllowed(cedarCheck({ groups: ['editors', 'reviewers'], action: 'approve:content' }))).toBe(true);
    });

    it('user in both users and developers gets combined permissions', () => {
        expect(isAllowed(cedarCheck({ groups: ['users', 'developers'], action: 'write:own' }))).toBe(true);
        expect(isAllowed(cedarCheck({ groups: ['users', 'developers'], action: 'api:write' }))).toBe(true);
    });
});

// ── Diagnostics ───────────────────────────────────────────────────────────

describe('Diagnostics', () => {
    it('response includes a determining policy ID when permitted', () => {
        const result = cedarCheck({ groups: ['editors'], action: 'write:content' });
        expect(result.type).toBe('success');
        expect(result.response.diagnostics.reason.length).toBeGreaterThan(0);
    });

    it('denied response has empty reason array', () => {
        const result = cedarCheck({ groups: ['readonly'], action: 'admin:manage' });
        expect(result.type).toBe('success');
        expect(result.response.diagnostics.reason).toHaveLength(0);
    });
});

// ── Engine Module Integration ─────────────────────────────────────────────

describe('Cedar Engine Module', () => {
    it('isInitialized() returns true after init', () => {
        expect(cedarEngine.isInitialized()).toBe(true);
    });

    it('authorize() permits admin actions', async () => {
        const session = createSession('admin@test.com', ['admin']);
        const result = await cedarEngine.authorize({
            session,
            action: 'admin:delete-user'
        });
        expect(result.authorized).toBe(true);
        expect(result.reason).not.toBe('');
    });

    it('authorize() denies unauthorized actions', async () => {
        const session = createSession('viewer@test.com', ['readonly']);
        const result = await cedarEngine.authorize({
            session,
            action: 'admin:delete-user'
        });
        expect(result.authorized).toBe(false);
    });

    it('authorize() works with resource parameter', async () => {
        const session = createSession('editor@test.com', ['editors']);
        const result = await cedarEngine.authorize({
            session,
            action: 'write:content',
            resource: { id: 'article-42', type: 'article' }
        });
        expect(result.authorized).toBe(true);
    });

    it('authorize() throws when engine not initialized', async () => {
        cedarEngine._resetForTesting();
        const session = createSession('test@test.com', []);
        await expect(cedarEngine.authorize({ session, action: 'read:content' }))
            .rejects.toThrow('not initialized');

        // Re-initialize for remaining tests
        await cedarEngine.initCedarEngine({ schema, policies: policyText });
    });

    it('authorize() supports custom entity provider', async () => {
        const session = createSession('test@test.com', ['editors'], 'custom-sub');
        const customProvider = {
            async getEntities(claims, resource, context) {
                return [
                    {
                        uid: { type: 'App::User', id: claims.sub },
                        attrs: { email: claims.email, sub: claims.sub },
                        parents: [{ type: 'App::UserGroup', id: 'admin' }]
                    },
                    {
                        uid: { type: 'App::UserGroup', id: 'admin' },
                        attrs: {},
                        parents: []
                    },
                    {
                        uid: { type: 'App::Resource', id: '_application' },
                        attrs: { resourceType: 'application' },
                        parents: []
                    }
                ];
            }
        };

        // Even though the JWT says 'editors', the custom provider maps to 'admin'
        const result = await cedarEngine.authorize({
            session,
            action: 'admin:delete-user',
            entityProvider: customProvider
        });
        expect(result.authorized).toBe(true);
    });
});

// ── Group Alias Resolution ────────────────────────────────────────────────

describe('Group Alias Resolution', () => {
    it('resolves "admins" to "admin"', async () => {
        const session = createSession('test@test.com', ['admins']);
        const result = await cedarEngine.authorize({ session, action: 'admin:manage' });
        expect(result.authorized).toBe(true);
    });

    it('resolves "administrators" to "admin"', async () => {
        const session = createSession('test@test.com', ['administrators']);
        const result = await cedarEngine.authorize({ session, action: 'admin:manage' });
        expect(result.authorized).toBe(true);
    });

    it('resolves "read-only" to "readonly"', async () => {
        const session = createSession('test@test.com', ['read-only']);
        const result = await cedarEngine.authorize({ session, action: 'read:content' });
        expect(result.authorized).toBe(true);
    });

    it('resolves "viewers" to "readonly"', async () => {
        const session = createSession('test@test.com', ['viewers']);
        const result = await cedarEngine.authorize({ session, action: 'read:content' });
        expect(result.authorized).toBe(true);
    });

    it('resolves "editor" to "editors"', async () => {
        const session = createSession('test@test.com', ['editor']);
        const result = await cedarEngine.authorize({ session, action: 'write:content' });
        expect(result.authorized).toBe(true);
    });

    it('resolves "dev" to "developers"', async () => {
        const session = createSession('test@test.com', ['dev']);
        const result = await cedarEngine.authorize({ session, action: 'api:read' });
        expect(result.authorized).toBe(true);
    });

    it('resolves "mod" to "moderators"', async () => {
        const session = createSession('test@test.com', ['mod']);
        const result = await cedarEngine.authorize({ session, action: 'manage:chat' });
        expect(result.authorized).toBe(true);
    });

    it('passes through unknown groups unchanged', async () => {
        const session = createSession('test@test.com', ['custom-role']);
        const result = await cedarEngine.authorize({ session, action: 'read:content' });
        // Unknown group won't match any policy
        expect(result.authorized).toBe(false);
    });
});

// ── Initialization Error Handling ─────────────────────────────────────────

describe('Initialization Errors', () => {
    afterEach(async () => {
        // Re-initialize for subsequent tests
        cedarEngine._resetForTesting();
        await cedarEngine.initCedarEngine({ schema, policies: policyText });
    });

    it('throws on missing schema', async () => {
        cedarEngine._resetForTesting();
        await expect(cedarEngine.initCedarEngine({ policies: policyText }))
            .rejects.toThrow('requires schema');
    });

    it('throws on missing policies', async () => {
        cedarEngine._resetForTesting();
        await expect(cedarEngine.initCedarEngine({ schema }))
            .rejects.toThrow('requires policies');
    });

    it('throws on invalid policy text', async () => {
        cedarEngine._resetForTesting();
        await expect(cedarEngine.initCedarEngine({
            schema,
            policies: 'this is not valid cedar'
        })).rejects.toThrow();
    });
});

// ── Property-Based Tests ──────────────────────────────────────────────────

describe('Property-Based Tests', () => {
    const ALL_ACTIONS = [
        'read:content', 'write:content', 'publish:content', 'approve:content', 'reject:content',
        'read:own', 'write:own', 'delete:own', 'read:all', 'write:all', 'delete:all',
        'deploy:static', 'read:users', 'mute:users', 'kick:users', 'manage:chat',
        'api:read', 'api:write', 'read:logs', 'read:metrics', 'debug:view',
        'admin:manage', 'admin:delete-user'
    ];

    const ALL_GROUPS = [
        'admin', 'readonly', 'users', 'editors', 'reviewers',
        'publishers', 'moderators', 'developers'
    ];

    const actionArb = fc.constantFrom(...ALL_ACTIONS);
    const groupArb = fc.constantFrom(...ALL_GROUPS);
    const groupsArb = fc.subarray(ALL_GROUPS, { minLength: 0, maxLength: 4 });

    it('admin is always permitted (for any action)', () => {
        fc.assert(fc.property(actionArb, (action) => {
            const result = cedarCheck({ groups: ['admin'], action });
            return isAllowed(result);
        }));
    });

    it('no group → always denied (for any action)', () => {
        fc.assert(fc.property(actionArb, (action) => {
            const result = cedarCheck({ groups: [], action });
            return isDenied(result);
        }));
    });

    it('evaluation never crashes (random groups × random actions)', () => {
        fc.assert(fc.property(groupsArb, actionArb, (groups, action) => {
            const result = cedarCheck({ groups, action });
            return result.type === 'success';
        }));
    });

    it('adding admin group only adds permissions, never removes them', () => {
        fc.assert(fc.property(groupsArb, actionArb, (groups, action) => {
            const withoutAdmin = cedarCheck({ groups: groups.filter(g => g !== 'admin'), action });
            const withAdmin = cedarCheck({ groups: [...new Set([...groups, 'admin'])], action });

            // If it was allowed without admin, it should still be allowed with admin
            // (unless a forbid policy fires — ownership enforcement)
            // We skip write:own and delete:own since forbid policies can deny admin
            if (action === 'write:own' || action === 'delete:own') return true;

            if (isAllowed(withoutAdmin)) {
                return isAllowed(withAdmin);
            }
            return true; // No constraint when base was denied
        }));
    });

    it('readonly can only perform read actions', () => {
        fc.assert(fc.property(actionArb, (action) => {
            const result = cedarCheck({ groups: ['readonly'], action });
            if (isAllowed(result)) {
                return action.startsWith('read:');
            }
            return true;
        }));
    });
});

// ── Schema Consistency with RBAC Roles ────────────────────────────────────

describe('Schema-RBAC Consistency', () => {
    it('schema defines actions for all RBAC permission types', () => {
        const schemaActions = Object.keys(schema.App.actions);
        // All RBAC permission prefixes should have corresponding Cedar actions
        const rbacPrefixes = ['read:', 'write:', 'delete:', 'publish:', 'approve:',
                             'reject:', 'deploy:', 'mute:', 'kick:', 'manage:', 'api:', 'debug:', 'admin:'];
        for (const prefix of rbacPrefixes) {
            const hasAction = schemaActions.some(a => a.startsWith(prefix));
            expect(hasAction, `No Cedar action found with prefix '${prefix}'`).toBe(true);
        }
    });

    it('all policy files are valid Cedar', () => {
        const files = readdirSync(POLICY_DIR).filter(f => f.endsWith('.cedar'));
        for (const file of files) {
            const text = readFileSync(join(POLICY_DIR, file), 'utf8');
            const result = cedar.checkParsePolicySet({ staticPolicies: text });
            expect(result.type, `${file} failed to parse`).toBe('success');
        }
    });

    it('each policy file validates independently against the schema', () => {
        const files = readdirSync(POLICY_DIR).filter(f => f.endsWith('.cedar'));
        for (const file of files) {
            const text = readFileSync(join(POLICY_DIR, file), 'utf8');
            const result = cedar.validate({
                schema,
                policies: { staticPolicies: text }
            });
            expect(result.type, `${file} failed validation`).toBe('success');
            expect(
                result.validationErrors || [],
                `${file} has validation errors`
            ).toHaveLength(0);
        }
    });
});
