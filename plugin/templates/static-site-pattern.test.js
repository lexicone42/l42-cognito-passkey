/**
 * L42 Cognito Passkey - Static Site Pattern Tests
 *
 * Unit tests for the static site authentication pattern.
 * Uses a mock auth module to test UI behavior without real Cognito calls.
 *
 * Run with: npx vitest run templates/static-site-pattern.test.js
 * Or with Jest: npx jest templates/static-site-pattern.test.js
 *
 * @module static-site-pattern-tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// =====================================================================
// MOCK AUTH MODULE
// =====================================================================

/**
 * Create a mock auth module for testing.
 * Simulates all auth functions without real Cognito calls.
 *
 * @param {Object} options - Initial state
 * @param {boolean} options.authenticated - Initial auth state
 * @param {string} options.email - User email
 * @param {string[]} options.groups - User groups/roles
 * @returns {Object} Mock auth module
 */
export function createMockAuth({
    authenticated = false,
    email = 'test@example.com',
    groups = []
} = {}) {
    let _authenticated = authenticated;
    let _email = email;
    let _groups = groups;
    const _listeners = [];

    return {
        // State checks
        isAuthenticated: vi.fn(() => _authenticated),
        getUserEmail: vi.fn(() => _authenticated ? _email : null),
        getUserGroups: vi.fn(() => _authenticated ? _groups : []),
        isAdmin: vi.fn(() => _groups.includes('admin')),
        isReadonly: vi.fn(() => _groups.includes('readonly') && !_groups.includes('admin')),
        hasAdminScope: vi.fn(() => _groups.includes('admin')),

        // Token management
        getTokens: vi.fn(() => _authenticated ? {
            id_token: 'mock-id-token',
            access_token: 'mock-access-token',
            refresh_token: 'mock-refresh-token'
        } : null),
        ensureValidTokens: vi.fn(async () => _authenticated ? {
            id_token: 'mock-id-token',
            access_token: 'mock-access-token',
            refresh_token: 'mock-refresh-token'
        } : null),

        // Login methods
        loginWithPassword: vi.fn(async (inputEmail, password) => {
            if (password === 'correct-password') {
                _authenticated = true;
                _email = inputEmail;
                _listeners.forEach(cb => cb(true));
                return { success: true };
            }
            throw new Error('Invalid credentials');
        }),
        loginWithPasskey: vi.fn(async (inputEmail) => {
            _authenticated = true;
            _email = inputEmail;
            _listeners.forEach(cb => cb(true));
            return { success: true };
        }),
        loginWithHostedUI: vi.fn((emailHint) => {
            // Would redirect in real implementation
        }),

        // Logout
        logout: vi.fn(() => {
            _authenticated = false;
            _listeners.forEach(cb => cb(false));
        }),

        // OAuth callback
        exchangeCodeForTokens: vi.fn(async () => {
            _authenticated = true;
            _listeners.forEach(cb => cb(true));
            return { success: true };
        }),

        // Event subscription
        onAuthStateChange: vi.fn((callback) => {
            _listeners.push(callback);
            return () => {
                const idx = _listeners.indexOf(callback);
                if (idx >= 0) _listeners.splice(idx, 1);
            };
        }),

        // Test helpers (not part of real auth module)
        _setAuthenticated: (val) => {
            _authenticated = val;
            _listeners.forEach(cb => cb(val));
        },
        _setGroups: (newGroups) => {
            _groups = newGroups;
        },
        _setEmail: (newEmail) => {
            _email = newEmail;
        }
    };
}

// =====================================================================
// ROLE-BASED ACCESS TESTS
// =====================================================================

describe('Role-Based Access Control', () => {
    /**
     * ADMIN_ROLES constant from the template.
     * These roles grant access to the admin panel.
     */
    const ADMIN_ROLES = ['admin', 'publisher', 'editor'];

    /**
     * Test helper: Check if user has admin access
     */
    function hasAdminAccess(groups) {
        return groups.some(r => ADMIN_ROLES.includes(r));
    }

    /**
     * Test helper: Get highest role
     */
    function getHighestRole(groups) {
        if (groups.includes('admin')) return 'admin';
        if (groups.includes('publisher')) return 'publisher';
        if (groups.includes('editor')) return 'editor';
        if (groups.includes('readonly')) return 'readonly';
        return 'user';
    }

    describe('hasAdminAccess', () => {
        it('should return true for admin role', () => {
            expect(hasAdminAccess(['admin'])).toBe(true);
        });

        it('should return true for publisher role', () => {
            expect(hasAdminAccess(['publisher'])).toBe(true);
        });

        it('should return true for editor role', () => {
            expect(hasAdminAccess(['editor'])).toBe(true);
        });

        it('should return false for readonly role', () => {
            expect(hasAdminAccess(['readonly'])).toBe(false);
        });

        it('should return false for user role', () => {
            expect(hasAdminAccess(['users'])).toBe(false);
        });

        it('should return true if user has multiple roles including admin', () => {
            expect(hasAdminAccess(['readonly', 'editor'])).toBe(true);
        });

        it('should return false for empty roles', () => {
            expect(hasAdminAccess([])).toBe(false);
        });
    });

    describe('getHighestRole', () => {
        it('should return admin when user has admin role', () => {
            expect(getHighestRole(['admin', 'editor'])).toBe('admin');
        });

        it('should return publisher when user has publisher but not admin', () => {
            expect(getHighestRole(['publisher', 'editor'])).toBe('publisher');
        });

        it('should return editor when user has editor but not publisher/admin', () => {
            expect(getHighestRole(['editor', 'readonly'])).toBe('editor');
        });

        it('should return readonly when user only has readonly', () => {
            expect(getHighestRole(['readonly'])).toBe('readonly');
        });

        it('should return user as default', () => {
            expect(getHighestRole(['users', 'customers'])).toBe('user');
        });

        it('should return user for empty roles', () => {
            expect(getHighestRole([])).toBe('user');
        });
    });
});

// =====================================================================
// AUTH STATE TESTS
// =====================================================================

describe('Auth State Management', () => {
    let mockAuth;

    beforeEach(() => {
        mockAuth = createMockAuth();
    });

    it('should start unauthenticated by default', () => {
        expect(mockAuth.isAuthenticated()).toBe(false);
        expect(mockAuth.getUserEmail()).toBeNull();
    });

    it('should authenticate with password login', async () => {
        await mockAuth.loginWithPassword('user@test.com', 'correct-password');
        expect(mockAuth.isAuthenticated()).toBe(true);
    });

    it('should fail with wrong password', async () => {
        await expect(
            mockAuth.loginWithPassword('user@test.com', 'wrong-password')
        ).rejects.toThrow('Invalid credentials');
    });

    it('should notify listeners on auth state change', async () => {
        const listener = vi.fn();
        mockAuth.onAuthStateChange(listener);

        await mockAuth.loginWithPassword('user@test.com', 'correct-password');
        expect(listener).toHaveBeenCalledWith(true);

        mockAuth.logout();
        expect(listener).toHaveBeenCalledWith(false);
    });

    it('should clear auth state on logout', async () => {
        mockAuth._setAuthenticated(true);
        expect(mockAuth.isAuthenticated()).toBe(true);

        mockAuth.logout();
        expect(mockAuth.isAuthenticated()).toBe(false);
    });
});

// =====================================================================
// TOKEN MANAGEMENT TESTS
// =====================================================================

describe('Token Management', () => {
    let mockAuth;

    beforeEach(() => {
        mockAuth = createMockAuth({ authenticated: true });
    });

    it('should return tokens when authenticated', () => {
        const tokens = mockAuth.getTokens();
        expect(tokens).toHaveProperty('id_token');
        expect(tokens).toHaveProperty('access_token');
        expect(tokens).toHaveProperty('refresh_token');
    });

    it('should return null tokens when not authenticated', () => {
        mockAuth._setAuthenticated(false);
        expect(mockAuth.getTokens()).toBeNull();
    });

    it('should ensure valid tokens for API calls', async () => {
        const tokens = await mockAuth.ensureValidTokens();
        expect(tokens).not.toBeNull();
        expect(tokens.access_token).toBe('mock-access-token');
    });

    it('should return null from ensureValidTokens when not authenticated', async () => {
        mockAuth._setAuthenticated(false);
        const tokens = await mockAuth.ensureValidTokens();
        expect(tokens).toBeNull();
    });
});

// =====================================================================
// UI STATE TESTS (Simulated)
// =====================================================================

describe('UI State Updates', () => {
    /**
     * Simulates the updateUI function from the template.
     * In real tests, you'd use JSDOM or Playwright for DOM testing.
     */
    function getUIState(auth) {
        const authenticated = auth.isAuthenticated();
        const groups = auth.getUserGroups();
        const ADMIN_ROLES = ['admin', 'publisher', 'editor'];

        return {
            loginButtonVisible: !authenticated,
            logoutButtonVisible: authenticated,
            protectedContentVisible: authenticated,
            adminPanelVisible: authenticated && groups.some(r => ADMIN_ROLES.includes(r)),
            userEmail: authenticated ? auth.getUserEmail() : '',
            displayedRole: authenticated ? (
                groups.includes('admin') ? 'admin' :
                groups.includes('publisher') ? 'publisher' :
                groups.includes('editor') ? 'editor' :
                groups.includes('readonly') ? 'readonly' : 'user'
            ) : ''
        };
    }

    it('should show login button when not authenticated', () => {
        const mockAuth = createMockAuth({ authenticated: false });
        const state = getUIState(mockAuth);

        expect(state.loginButtonVisible).toBe(true);
        expect(state.logoutButtonVisible).toBe(false);
        expect(state.protectedContentVisible).toBe(false);
        expect(state.adminPanelVisible).toBe(false);
    });

    it('should show protected content when authenticated', () => {
        const mockAuth = createMockAuth({
            authenticated: true,
            email: 'user@test.com',
            groups: ['users']
        });
        const state = getUIState(mockAuth);

        expect(state.loginButtonVisible).toBe(false);
        expect(state.logoutButtonVisible).toBe(true);
        expect(state.protectedContentVisible).toBe(true);
        expect(state.adminPanelVisible).toBe(false);
    });

    it('should show admin panel for editor role', () => {
        const mockAuth = createMockAuth({
            authenticated: true,
            email: 'editor@test.com',
            groups: ['editor']
        });
        const state = getUIState(mockAuth);

        expect(state.adminPanelVisible).toBe(true);
        expect(state.displayedRole).toBe('editor');
    });

    it('should show admin panel for admin role', () => {
        const mockAuth = createMockAuth({
            authenticated: true,
            email: 'admin@test.com',
            groups: ['admin']
        });
        const state = getUIState(mockAuth);

        expect(state.adminPanelVisible).toBe(true);
        expect(state.displayedRole).toBe('admin');
    });

    it('should not show admin panel for readonly role', () => {
        const mockAuth = createMockAuth({
            authenticated: true,
            email: 'readonly@test.com',
            groups: ['readonly']
        });
        const state = getUIState(mockAuth);

        expect(state.adminPanelVisible).toBe(false);
        expect(state.displayedRole).toBe('readonly');
    });
});

// =====================================================================
// INTEGRATION TEST HELPERS
// =====================================================================

/**
 * Helper for E2E tests with Playwright or Cypress.
 * Export test scenarios that can be run against the actual template.
 */
export const e2eScenarios = {
    /**
     * Test: Anonymous user sees public content only
     */
    anonymousUser: {
        setup: () => ({ authenticated: false }),
        assertions: (page) => ({
            loginVisible: true,
            logoutVisible: false,
            protectedVisible: false,
            adminVisible: false
        })
    },

    /**
     * Test: Regular user sees protected content
     */
    regularUser: {
        setup: () => ({
            authenticated: true,
            email: 'user@test.com',
            groups: ['users']
        }),
        assertions: (page) => ({
            loginVisible: false,
            logoutVisible: true,
            protectedVisible: true,
            adminVisible: false
        })
    },

    /**
     * Test: Editor sees admin panel
     */
    editorUser: {
        setup: () => ({
            authenticated: true,
            email: 'editor@test.com',
            groups: ['editor']
        }),
        assertions: (page) => ({
            loginVisible: false,
            logoutVisible: true,
            protectedVisible: true,
            adminVisible: true
        })
    },

    /**
     * Test: Admin sees everything
     */
    adminUser: {
        setup: () => ({
            authenticated: true,
            email: 'admin@test.com',
            groups: ['admin']
        }),
        assertions: (page) => ({
            loginVisible: false,
            logoutVisible: true,
            protectedVisible: true,
            adminVisible: true
        })
    }
};
