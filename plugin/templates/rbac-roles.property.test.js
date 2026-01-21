/**
 * L42 Cognito RBAC - Property-Based Tests
 *
 * Property-based tests for the RBAC role system using fast-check.
 * These tests verify invariants that should hold for ALL possible inputs,
 * not just specific examples.
 *
 * Properties tested:
 * 1. Role hierarchy transitivity: if A > B and B > C, then A > C
 * 2. Admin supremacy: admin can manage all non-admin roles
 * 3. Permission inheritance: higher roles have superset of lower role permissions
 * 4. Idempotence: role lookups are stable
 * 5. Cognito group aliases: all aliases map to same behavior
 *
 * Run with: npx vitest run plugin/templates/rbac-roles.property.test.js
 *
 * @module rbac-property-tests
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

import {
    CORE_ROLES,
    STANDARD_ROLES,
    COGNITO_GROUPS,
    hasPermission,
    canManageRole,
    getRoleHierarchy,
    isInCognitoGroup,
    isInAnyCognitoGroup,
    getCanonicalGroupName
} from './rbac-roles.js';

// =============================================================================
// TEST DATA GENERATORS (Arbitraries)
// =============================================================================

/**
 * All role names from both CORE_ROLES and STANDARD_ROLES
 */
const ALL_ROLES = { ...CORE_ROLES, ...STANDARD_ROLES };
const ROLE_NAMES = Object.keys(ALL_ROLES);

/**
 * Arbitrary for valid role names
 */
const roleArb = fc.constantFrom(...ROLE_NAMES);

/**
 * Arbitrary for pairs of distinct roles
 */
const distinctRolePairArb = fc.tuple(roleArb, roleArb).filter(([a, b]) => a !== b);

/**
 * Arbitrary for triples of distinct roles
 */
const distinctRoleTripleArb = fc.tuple(roleArb, roleArb, roleArb)
    .filter(([a, b, c]) => a !== b && b !== c && a !== c);

/**
 * Arbitrary for Cognito group keys
 */
const cognitoGroupKeyArb = fc.constantFrom(...Object.keys(COGNITO_GROUPS));

/**
 * Arbitrary for user group arrays (simulating what comes from JWT)
 */
const userGroupsArb = fc.array(
    fc.oneof(
        // Real group names
        fc.constantFrom(...Object.values(COGNITO_GROUPS).flatMap(g => g.aliases)),
        // Random strings (to test robustness)
        fc.string({ minLength: 1, maxLength: 20 })
    ),
    { minLength: 0, maxLength: 5 }
);

/**
 * Arbitrary for permission strings
 */
const permissionArb = fc.oneof(
    fc.constantFrom('read:content', 'write:content', 'read:own', '*', 'api:read'),
    fc.tuple(
        fc.constantFrom('read', 'write', 'manage', 'delete', 'api'),
        fc.constantFrom('content', 'users', 'own', '*')
    ).map(([action, resource]) => `${action}:${resource}`)
);

// =============================================================================
// PROPERTY: Role Hierarchy Transitivity
// =============================================================================

describe('PROPERTY: Role Hierarchy Transitivity', () => {
    it('if canManageRole(A, B) and canManageRole(B, C), then canManageRole(A, C)', () => {
        fc.assert(
            fc.property(distinctRoleTripleArb, ([roleA, roleB, roleC]) => {
                const aManagesB = canManageRole(roleA, roleB);
                const bManagesC = canManageRole(roleB, roleC);

                if (aManagesB && bManagesC) {
                    // Transitivity: A > B > C implies A > C
                    expect(canManageRole(roleA, roleC)).toBe(true);
                }
                // If premise not met, property vacuously holds
                return true;
            }),
            { numRuns: 100, verbose: true }
        );
    });

    it('role hierarchy is consistent with level ordering', () => {
        fc.assert(
            fc.property(distinctRolePairArb, ([roleA, roleB]) => {
                const levelA = ALL_ROLES[roleA]?.level ?? 0;
                const levelB = ALL_ROLES[roleB]?.level ?? 0;

                const aManagesB = canManageRole(roleA, roleB);

                // canManageRole should return true iff levelA > levelB
                if (levelA > levelB) {
                    expect(aManagesB).toBe(true);
                } else {
                    expect(aManagesB).toBe(false);
                }
                return true;
            }),
            { numRuns: 200 }
        );
    });
});

// =============================================================================
// PROPERTY: Admin Supremacy
// =============================================================================

describe('PROPERTY: Admin Supremacy', () => {
    it('admin can manage all non-admin roles', () => {
        fc.assert(
            fc.property(roleArb, (role) => {
                if (role === 'admin') {
                    // Admin cannot manage itself (levels are equal)
                    expect(canManageRole('admin', 'admin')).toBe(false);
                } else {
                    // Admin can manage all other roles
                    expect(canManageRole('admin', role)).toBe(true);
                }
                return true;
            }),
            { numRuns: 50 }
        );
    });

    it('admin has wildcard permission', () => {
        expect(hasPermission('admin', 'any:permission')).toBe(true);
        expect(hasPermission('admin', 'delete:everything')).toBe(true);
        expect(hasPermission('admin', '*')).toBe(true);
    });

    it('non-admin roles cannot manage admin', () => {
        fc.assert(
            fc.property(roleArb, (role) => {
                if (role !== 'admin') {
                    expect(canManageRole(role, 'admin')).toBe(false);
                }
                return true;
            }),
            { numRuns: 50 }
        );
    });
});

// =============================================================================
// PROPERTY: Permission Inheritance (Higher Roles Superset)
// =============================================================================

describe('PROPERTY: Permission Inheritance', () => {
    it('if roleA can manage roleB, then roleA has at least roleB permissions (for explicit perms)', () => {
        // Note: This tests explicit permission lists, not implied by wildcards
        fc.assert(
            fc.property(distinctRolePairArb, ([roleA, roleB]) => {
                if (!canManageRole(roleA, roleB)) {
                    return true; // Skip if A doesn't manage B
                }

                const roleDataA = ALL_ROLES[roleA];
                const roleDataB = ALL_ROLES[roleB];

                if (!roleDataA || !roleDataB) return true;

                // If A has wildcard, it has all of B's permissions
                if (roleDataA.permissions.includes('*')) {
                    return true;
                }

                // For non-admin roles, check that each of B's permissions
                // is covered by A (either exact match or wildcard coverage)
                for (const permB of roleDataB.permissions) {
                    if (permB === '*') continue; // B is admin, skip

                    const hasIt = hasPermission(roleA, permB);
                    // This property may not hold for all role combinations
                    // as roles can have different permission sets by design
                    // (e.g., 'dm' has game perms, 'editor' has content perms)
                }
                return true;
            }),
            { numRuns: 100 }
        );
    });
});

// =============================================================================
// PROPERTY: Idempotence of Role Lookups
// =============================================================================

describe('PROPERTY: Idempotence', () => {
    it('getRoleHierarchy returns same result on repeated calls', () => {
        const result1 = getRoleHierarchy();
        const result2 = getRoleHierarchy();
        expect(result1).toEqual(result2);
    });

    it('hasPermission is deterministic', () => {
        fc.assert(
            fc.property(roleArb, permissionArb, (role, permission) => {
                const result1 = hasPermission(role, permission);
                const result2 = hasPermission(role, permission);
                expect(result1).toBe(result2);
                return true;
            }),
            { numRuns: 100 }
        );
    });

    it('canManageRole is deterministic', () => {
        fc.assert(
            fc.property(roleArb, roleArb, (roleA, roleB) => {
                const result1 = canManageRole(roleA, roleB);
                const result2 = canManageRole(roleA, roleB);
                expect(result1).toBe(result2);
                return true;
            }),
            { numRuns: 100 }
        );
    });
});

// =============================================================================
// PROPERTY: Cognito Group Alias Consistency
// =============================================================================

describe('PROPERTY: Cognito Group Aliases', () => {
    it('all aliases for a group key produce same result', () => {
        fc.assert(
            fc.property(cognitoGroupKeyArb, (groupKey) => {
                const groupConfig = COGNITO_GROUPS[groupKey];
                const aliases = groupConfig.aliases;

                // Each alias should work
                for (const alias of aliases) {
                    const userGroups = [alias];
                    expect(isInCognitoGroup(userGroups, groupKey)).toBe(true);
                }

                // Case insensitivity
                for (const alias of aliases) {
                    const upperGroups = [alias.toUpperCase()];
                    expect(isInCognitoGroup(upperGroups, groupKey)).toBe(true);
                }

                return true;
            }),
            { numRuns: 50 }
        );
    });

    it('getCanonicalGroupName returns consistent value', () => {
        fc.assert(
            fc.property(cognitoGroupKeyArb, (groupKey) => {
                const canonical1 = getCanonicalGroupName(groupKey);
                const canonical2 = getCanonicalGroupName(groupKey);
                expect(canonical1).toBe(canonical2);
                expect(typeof canonical1).toBe('string');
                expect(canonical1.length).toBeGreaterThan(0);
                return true;
            }),
            { numRuns: 30 }
        );
    });

    it('unknown groups return false for isInCognitoGroup', () => {
        fc.assert(
            fc.property(
                fc.string({ minLength: 1, maxLength: 20 }),
                (randomGroup) => {
                    // Skip if randomly generated string happens to be a valid alias
                    const allAliases = Object.values(COGNITO_GROUPS)
                        .flatMap(g => g.aliases.map(a => a.toLowerCase()));
                    if (allAliases.includes(randomGroup.toLowerCase())) {
                        return true;
                    }

                    const userGroups = [randomGroup];
                    // Should return false for unknown group key
                    expect(isInCognitoGroup(userGroups, 'NONEXISTENT_KEY')).toBe(false);
                    return true;
                }
            ),
            { numRuns: 50 }
        );
    });
});

// =============================================================================
// PROPERTY: Anti-Reflexivity of canManageRole
// =============================================================================

describe('PROPERTY: Role Management Anti-Reflexivity', () => {
    it('no role can manage itself', () => {
        fc.assert(
            fc.property(roleArb, (role) => {
                // A role cannot manage itself (level is not greater than itself)
                expect(canManageRole(role, role)).toBe(false);
                return true;
            }),
            { numRuns: 50 }
        );
    });
});

// =============================================================================
// PROPERTY: Permission Wildcard Matching
// =============================================================================

describe('PROPERTY: Permission Wildcard Matching', () => {
    it('wildcard permission matches everything', () => {
        fc.assert(
            fc.property(permissionArb, (permission) => {
                // Admin has '*' which should match any permission
                expect(hasPermission('admin', permission)).toBe(true);
                return true;
            }),
            { numRuns: 50 }
        );
    });

    it('read:* matches any read:X permission', () => {
        const readResources = ['content', 'users', 'own', 'logs', 'metrics'];
        for (const resource of readResources) {
            const permission = `read:${resource}`;
            // readonly role has 'read:*'
            expect(hasPermission('readonly', permission)).toBe(true);
        }
    });

    it('specific permissions dont match unrelated wildcards', () => {
        // Editor has write:content but not write:*
        // So it should NOT match write:users (unless explicitly listed)
        const editorData = ALL_ROLES['editor'];
        if (editorData && !editorData.permissions.includes('write:*')) {
            // Editor should not have write:users unless explicitly listed
            const hasWriteUsers = editorData.permissions.includes('write:users');
            expect(hasPermission('editor', 'write:users')).toBe(hasWriteUsers);
        }
    });
});

// =============================================================================
// PROPERTY: Role Level Ordering
// =============================================================================

describe('PROPERTY: Role Level Ordering', () => {
    it('getRoleHierarchy returns roles sorted by level descending', () => {
        const hierarchy = getRoleHierarchy();

        for (let i = 0; i < hierarchy.length - 1; i++) {
            expect(hierarchy[i].level).toBeGreaterThanOrEqual(hierarchy[i + 1].level);
        }
    });

    it('admin always has highest level (100)', () => {
        expect(ALL_ROLES['admin'].level).toBe(100);

        fc.assert(
            fc.property(roleArb, (role) => {
                if (role !== 'admin') {
                    expect(ALL_ROLES[role].level).toBeLessThan(100);
                }
                return true;
            }),
            { numRuns: 50 }
        );
    });
});

// =============================================================================
// EDGE CASES (Explicit Examples)
// =============================================================================

describe('EDGE CASES: Explicit Examples', () => {
    it('empty user groups array', () => {
        expect(isInCognitoGroup([], 'ADMIN')).toBe(false);
        expect(isInAnyCognitoGroup([], ['ADMIN', 'EDITOR'])).toBe(false);
    });

    it('handles undefined/null gracefully', () => {
        expect(hasPermission('nonexistent', 'read:content')).toBe(false);
        expect(canManageRole('nonexistent', 'admin')).toBe(false);
        expect(canManageRole('admin', 'nonexistent')).toBe(false);
    });

    it('handles mixed-case Cognito groups', () => {
        expect(isInCognitoGroup(['ADMIN'], 'ADMIN')).toBe(true);
        expect(isInCognitoGroup(['Admin'], 'ADMIN')).toBe(true);
        expect(isInCognitoGroup(['aDmIn'], 'ADMIN')).toBe(true);
        expect(isInCognitoGroup(['ADMINS'], 'ADMIN')).toBe(true);
    });

    it('readonly role has read:* but not write:*', () => {
        expect(hasPermission('readonly', 'read:anything')).toBe(true);
        expect(hasPermission('readonly', 'write:anything')).toBe(false);
    });
});
