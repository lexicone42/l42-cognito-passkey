/**
 * L42 Cognito Passkey - Multi-User WASM Pattern Tests
 *
 * Unit tests for the multi-user WASM authentication pattern.
 * Tests role hierarchy, permissions, and session management.
 *
 * Run with: npx vitest run templates/wasm-multiuser-pattern.test.js
 * Or with Jest: npx jest templates/wasm-multiuser-pattern.test.js
 *
 * @module wasm-multiuser-pattern-tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// =====================================================================
// ROLE DEFINITIONS (Mirror from template)
// =====================================================================

/**
 * Role hierarchy levels (higher = more permissions)
 * @constant {Object.<string, number>}
 */
const ROLE_LEVELS = {
    player: 10,
    moderator: 30,
    dm: 50,
    admin: 100
};

/**
 * Permission sets by role
 * @constant {Object.<string, string[]>}
 */
const ROLE_PERMISSIONS = {
    player: ['chat', 'move-character', 'view-map'],
    moderator: ['chat', 'move-character', 'view-map', 'mute-player', 'kick-player'],
    dm: ['chat', 'move-character', 'view-map', 'mute-player', 'kick-player',
         'spawn-npc', 'reveal-area', 'pause-session', 'end-session'],
    admin: ['*']  // All permissions
};

// =====================================================================
// ROLE HELPER FUNCTIONS (Mirror from template)
// =====================================================================

/**
 * Check if role has at least the specified level.
 * @param {string} userRole - User's current role
 * @param {string} requiredRole - Minimum required role
 * @returns {boolean}
 */
function hasRoleLevel(userRole, requiredRole) {
    const userLevel = ROLE_LEVELS[userRole] || 0;
    const requiredLevel = ROLE_LEVELS[requiredRole] || 0;
    return userLevel >= requiredLevel;
}

/**
 * Check if role has specific permission.
 * @param {string} role - User's role
 * @param {string} permission - Permission to check
 * @returns {boolean}
 */
function hasPermission(role, permission) {
    const perms = ROLE_PERMISSIONS[role] || [];
    return perms.includes('*') || perms.includes(permission);
}

/**
 * Get highest role from Cognito groups.
 * @param {string[]} groups - Cognito group names
 * @returns {string} Role name
 */
function getRoleFromGroups(groups) {
    if (groups.includes('admin') || groups.includes('admins')) return 'admin';
    if (groups.includes('dm') || groups.includes('dms')) return 'dm';
    if (groups.includes('moderator') || groups.includes('moderators')) return 'moderator';
    return 'player';
}

// =====================================================================
// ROLE HIERARCHY TESTS
// =====================================================================

describe('Role Hierarchy', () => {
    describe('ROLE_LEVELS', () => {
        it('should have player as lowest level', () => {
            expect(ROLE_LEVELS.player).toBeLessThan(ROLE_LEVELS.moderator);
            expect(ROLE_LEVELS.player).toBeLessThan(ROLE_LEVELS.dm);
            expect(ROLE_LEVELS.player).toBeLessThan(ROLE_LEVELS.admin);
        });

        it('should have moderator between player and dm', () => {
            expect(ROLE_LEVELS.moderator).toBeGreaterThan(ROLE_LEVELS.player);
            expect(ROLE_LEVELS.moderator).toBeLessThan(ROLE_LEVELS.dm);
        });

        it('should have dm between moderator and admin', () => {
            expect(ROLE_LEVELS.dm).toBeGreaterThan(ROLE_LEVELS.moderator);
            expect(ROLE_LEVELS.dm).toBeLessThan(ROLE_LEVELS.admin);
        });

        it('should have admin as highest level', () => {
            expect(ROLE_LEVELS.admin).toBeGreaterThan(ROLE_LEVELS.dm);
        });
    });

    describe('hasRoleLevel', () => {
        it('should allow player for player-required actions', () => {
            expect(hasRoleLevel('player', 'player')).toBe(true);
        });

        it('should deny player for moderator-required actions', () => {
            expect(hasRoleLevel('player', 'moderator')).toBe(false);
        });

        it('should allow moderator for moderator-required actions', () => {
            expect(hasRoleLevel('moderator', 'moderator')).toBe(true);
        });

        it('should allow dm for moderator-required actions', () => {
            expect(hasRoleLevel('dm', 'moderator')).toBe(true);
        });

        it('should allow admin for all role levels', () => {
            expect(hasRoleLevel('admin', 'player')).toBe(true);
            expect(hasRoleLevel('admin', 'moderator')).toBe(true);
            expect(hasRoleLevel('admin', 'dm')).toBe(true);
            expect(hasRoleLevel('admin', 'admin')).toBe(true);
        });

        it('should deny dm for admin-required actions', () => {
            expect(hasRoleLevel('dm', 'admin')).toBe(false);
        });
    });
});

// =====================================================================
// PERMISSION TESTS
// =====================================================================

describe('Permissions', () => {
    describe('Player permissions', () => {
        it('should allow basic actions', () => {
            expect(hasPermission('player', 'chat')).toBe(true);
            expect(hasPermission('player', 'move-character')).toBe(true);
            expect(hasPermission('player', 'view-map')).toBe(true);
        });

        it('should deny moderation actions', () => {
            expect(hasPermission('player', 'mute-player')).toBe(false);
            expect(hasPermission('player', 'kick-player')).toBe(false);
        });

        it('should deny DM actions', () => {
            expect(hasPermission('player', 'spawn-npc')).toBe(false);
            expect(hasPermission('player', 'reveal-area')).toBe(false);
            expect(hasPermission('player', 'end-session')).toBe(false);
        });
    });

    describe('Moderator permissions', () => {
        it('should allow player actions', () => {
            expect(hasPermission('moderator', 'chat')).toBe(true);
            expect(hasPermission('moderator', 'move-character')).toBe(true);
        });

        it('should allow moderation actions', () => {
            expect(hasPermission('moderator', 'mute-player')).toBe(true);
            expect(hasPermission('moderator', 'kick-player')).toBe(true);
        });

        it('should deny DM actions', () => {
            expect(hasPermission('moderator', 'spawn-npc')).toBe(false);
            expect(hasPermission('moderator', 'reveal-area')).toBe(false);
        });
    });

    describe('DM permissions', () => {
        it('should allow all player and mod actions', () => {
            expect(hasPermission('dm', 'chat')).toBe(true);
            expect(hasPermission('dm', 'mute-player')).toBe(true);
            expect(hasPermission('dm', 'kick-player')).toBe(true);
        });

        it('should allow DM-specific actions', () => {
            expect(hasPermission('dm', 'spawn-npc')).toBe(true);
            expect(hasPermission('dm', 'reveal-area')).toBe(true);
            expect(hasPermission('dm', 'pause-session')).toBe(true);
            expect(hasPermission('dm', 'end-session')).toBe(true);
        });
    });

    describe('Admin permissions', () => {
        it('should allow any permission via wildcard', () => {
            expect(hasPermission('admin', 'chat')).toBe(true);
            expect(hasPermission('admin', 'kick-player')).toBe(true);
            expect(hasPermission('admin', 'spawn-npc')).toBe(true);
            expect(hasPermission('admin', 'some-future-permission')).toBe(true);
        });
    });
});

// =====================================================================
// COGNITO GROUP MAPPING TESTS
// =====================================================================

describe('Cognito Group Mapping', () => {
    describe('getRoleFromGroups', () => {
        it('should return player for empty groups', () => {
            expect(getRoleFromGroups([])).toBe('player');
        });

        it('should return player for unrecognized groups', () => {
            expect(getRoleFromGroups(['users', 'customers'])).toBe('player');
        });

        it('should return moderator for moderator group', () => {
            expect(getRoleFromGroups(['moderator'])).toBe('moderator');
            expect(getRoleFromGroups(['moderators'])).toBe('moderator');
        });

        it('should return dm for dm group', () => {
            expect(getRoleFromGroups(['dm'])).toBe('dm');
            expect(getRoleFromGroups(['dms'])).toBe('dm');
        });

        it('should return admin for admin group', () => {
            expect(getRoleFromGroups(['admin'])).toBe('admin');
            expect(getRoleFromGroups(['admins'])).toBe('admin');
        });

        it('should return highest role when multiple groups present', () => {
            expect(getRoleFromGroups(['moderator', 'dm'])).toBe('dm');
            expect(getRoleFromGroups(['player', 'moderator', 'admin'])).toBe('admin');
        });
    });
});

// =====================================================================
// SESSION MANAGEMENT TESTS
// =====================================================================

describe('Session Management', () => {
    /**
     * Generate session code (mirror from template)
     */
    function generateSessionCode() {
        const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';  // Excludes 0, O, 1, I, L
        let code = '';
        for (let i = 0; i < 6; i++) {
            code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return code;
    }

    it('should generate 6-character codes', () => {
        const code = generateSessionCode();
        expect(code.length).toBe(6);
    });

    it('should only use allowed characters', () => {
        const code = generateSessionCode();
        const allowedChars = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]+$/;  // Excludes 0, O, 1, I, L
        expect(code).toMatch(allowedChars);
    });

    it('should not include confusing characters (0, O, 1, I, L)', () => {
        // Generate many codes to have good coverage
        for (let i = 0; i < 100; i++) {
            const code = generateSessionCode();
            expect(code).not.toContain('0');
            expect(code).not.toContain('O');
            expect(code).not.toContain('1');
            expect(code).not.toContain('I');
            expect(code).not.toContain('L');
        }
    });

    it('should generate unique codes', () => {
        const codes = new Set();
        for (let i = 0; i < 100; i++) {
            codes.add(generateSessionCode());
        }
        // Very high probability all 100 are unique (36^6 = 2 billion combinations)
        expect(codes.size).toBe(100);
    });
});

// =====================================================================
// MOCK AUTH FOR INTEGRATION TESTS
// =====================================================================

/**
 * Create mock auth module for testing.
 * @param {Object} options - Configuration
 * @returns {Object} Mock auth module
 */
export function createMockAuth({
    authenticated = false,
    email = 'player@test.com',
    groups = []
} = {}) {
    let _authenticated = authenticated;
    let _email = email;
    let _groups = groups;
    const _listeners = [];

    return {
        isAuthenticated: vi.fn(() => _authenticated),
        getUserEmail: vi.fn(() => _authenticated ? _email : null),
        getUserGroups: vi.fn(() => _authenticated ? _groups : []),

        getTokens: vi.fn(() => _authenticated ? {
            id_token: 'mock-id',
            access_token: 'mock-access',
            refresh_token: 'mock-refresh'
        } : null),

        ensureValidTokens: vi.fn(async () => _authenticated ? {
            id_token: 'mock-id',
            access_token: 'mock-access',
            refresh_token: 'mock-refresh'
        } : null),

        loginWithHostedUI: vi.fn(),
        logout: vi.fn(() => {
            _authenticated = false;
            _listeners.forEach(cb => cb(false));
        }),

        exchangeCodeForTokens: vi.fn(async () => {
            _authenticated = true;
            _listeners.forEach(cb => cb(true));
        }),

        onAuthStateChange: vi.fn((cb) => {
            _listeners.push(cb);
            return () => {
                const idx = _listeners.indexOf(cb);
                if (idx >= 0) _listeners.splice(idx, 1);
            };
        }),

        // Test helpers
        _setAuthenticated: (v) => { _authenticated = v; _listeners.forEach(cb => cb(v)); },
        _setGroups: (g) => { _groups = g; },
        _setEmail: (e) => { _email = e; }
    };
}

// =====================================================================
// E2E TEST SCENARIOS
// =====================================================================

/**
 * E2E test scenarios for Playwright/Cypress.
 * Each scenario defines setup state and expected UI assertions.
 */
export const e2eScenarios = {
    anonymousPlayer: {
        description: 'Anonymous user can join as player',
        setup: () => ({ authenticated: false }),
        actions: ['join-session'],
        assertions: {
            canChat: true,
            canMoveCharacter: true,
            seeDmControls: false,
            seeKickButtons: false
        }
    },

    authenticatedPlayer: {
        description: 'Logged in player with basic permissions',
        setup: () => ({
            authenticated: true,
            email: 'player@test.com',
            groups: ['players']
        }),
        actions: ['join-session'],
        assertions: {
            displayName: 'player@test.com',
            roleBadge: 'player',
            canChat: true,
            seeDmControls: false
        }
    },

    moderatorUser: {
        description: 'Moderator can mute/kick players',
        setup: () => ({
            authenticated: true,
            email: 'mod@test.com',
            groups: ['moderators']
        }),
        actions: ['join-session'],
        assertions: {
            roleBadge: 'moderator',
            seeMuteButtons: true,
            seeKickButtons: true,
            seeDmControls: false
        }
    },

    dmUser: {
        description: 'DM has full session control',
        setup: () => ({
            authenticated: true,
            email: 'dm@test.com',
            groups: ['dms']
        }),
        actions: ['create-session'],
        assertions: {
            roleBadge: 'dm',
            seeDmControls: true,
            canSpawnNpc: true,
            canEndSession: true
        }
    },

    adminUser: {
        description: 'Admin has all permissions',
        setup: () => ({
            authenticated: true,
            email: 'admin@test.com',
            groups: ['admin']
        }),
        actions: ['join-session'],
        assertions: {
            roleBadge: 'admin',
            seeDmControls: true,
            canDoAnything: true
        }
    }
};
