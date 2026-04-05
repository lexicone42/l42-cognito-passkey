/**
 * L42 Cognito Passkey - Handler Mode Sync API Tests
 *
 * Tests REAL auth.js sync functions: getAuthMethod, getIdTokenClaims,
 * getUserEmail, getUserGroups, isAdmin, isReadonly, hasAdminScope,
 * shouldRefreshToken, isAuthenticated, isTokenExpired.
 *
 * Uses _resetForTesting() for isolation between tests.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    configure,
    setTokens,
    clearTokens,
    isAuthenticated,
    isTokenExpired,
    shouldRefreshToken,
    getAuthMethod,
    getIdTokenClaims,
    getUserEmail,
    getUserGroups,
    isAdmin,
    isReadonly,
    hasAdminScope,
    UNSAFE_decodeJwtPayload,
    _resetForTesting
} from '../../src/auth.js';

// ============================================================================
// Test Helpers
// ============================================================================

function createTestJwt(claims) {
    const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const payload = btoa(JSON.stringify(claims))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return `${header}.${payload}.test-signature`;
}

function configureForTest(overrides = {}) {
    configure({
        clientId: 'test-client',
        cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
        cognitoRegion: 'us-west-2',
        tokenEndpoint: '/auth/token',
        refreshEndpoint: '/auth/refresh',
        logoutEndpoint: '/auth/logout',
        sessionEndpoint: '/auth/session',
        ...overrides
    });
}

/** Create mock tokens with valid JWT structure. */
function createMockTokens(overrides = {}) {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const claims = {
        sub: 'user-123',
        email: 'test@example.com',
        'cognito:groups': ['admin', 'developers'],
        aud: 'test-client',
        iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
        exp: futureExp,
        ...overrides
    };
    return {
        access_token: createTestJwt({
            sub: claims.sub,
            scope: 'openid email aws.cognito.signin.user.admin',
            client_id: 'test-client',
            exp: claims.exp
        }),
        id_token: createTestJwt(claims),
        auth_method: overrides.auth_method || 'passkey'
    };
}

// ============================================================================
// Tests: Handler Mode Sync API Functions — REAL auth.js
// ============================================================================

describe('Handler Mode Sync API', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const pastExp = Math.floor(Date.now() / 1000) - 3600;

    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    describe('getAuthMethod()', () => {
        it('returns auth method from cached tokens', () => {
            setTokens(createMockTokens());
            expect(getAuthMethod()).toBe('passkey');
        });

        it('returns "password" as default when auth_method missing', () => {
            const tokens = createMockTokens();
            delete tokens.auth_method;
            setTokens(tokens);
            expect(getAuthMethod()).toBe('password');
        });

        it('returns null when not authenticated', () => {
            expect(getAuthMethod()).toBeNull();
        });

        it('returns "handler" for handler-originated tokens', () => {
            setTokens(createMockTokens({ auth_method: 'handler' }));
            expect(getAuthMethod()).toBe('handler');
        });
    });

    describe('getIdTokenClaims()', () => {
        it('returns decoded claims from cached ID token', () => {
            setTokens(createMockTokens());
            const claims = getIdTokenClaims();
            expect(claims.email).toBe('test@example.com');
            expect(claims.sub).toBe('user-123');
            expect(claims['cognito:groups']).toEqual(['admin', 'developers']);
        });

        it('returns null when not authenticated', () => {
            expect(getIdTokenClaims()).toBeNull();
        });

        it('returns null when id_token is missing', () => {
            setTokens({ access_token: createTestJwt({ sub: 'x', client_id: 'test-client', exp: futureExp }) });
            expect(getIdTokenClaims()).toBeNull();
        });

        it('returns null for invalid JWT', () => {
            setTokens({ access_token: 'x', id_token: 'not-a-jwt' });
            expect(getIdTokenClaims()).toBeNull();
        });
    });

    describe('getUserEmail()', () => {
        it('returns email from cached tokens', () => {
            setTokens(createMockTokens());
            expect(getUserEmail()).toBe('test@example.com');
        });

        it('returns null when not authenticated', () => {
            expect(getUserEmail()).toBeNull();
        });
    });

    describe('getUserGroups()', () => {
        it('returns groups from cached tokens', () => {
            setTokens(createMockTokens());
            expect(getUserGroups()).toEqual(['admin', 'developers']);
        });

        it('returns empty array when not authenticated', () => {
            expect(getUserGroups()).toEqual([]);
        });

        it('returns empty array when no groups in token', () => {
            const claims = { sub: 'user-123', email: 'test@example.com', exp: futureExp };
            delete claims['cognito:groups'];
            setTokens(createMockTokens(claims));
            // The override merges, so explicitly create without groups
            const noGroupTokens = {
                access_token: createTestJwt({ sub: 'x', client_id: 'test-client', exp: futureExp }),
                id_token: createTestJwt({
                    sub: 'user-123', email: 'test@example.com',
                    aud: 'test-client',
                    iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
                    exp: futureExp
                }),
                auth_method: 'handler'
            };
            setTokens(noGroupTokens);
            expect(getUserGroups()).toEqual([]);
        });
    });

    describe('hasAdminScope()', () => {
        it('returns true when access token has admin scope', () => {
            setTokens(createMockTokens());
            expect(hasAdminScope()).toBe(true);
        });

        it('returns false when not authenticated', () => {
            expect(hasAdminScope()).toBe(false);
        });

        it('returns false when scope is missing', () => {
            const tokens = {
                access_token: createTestJwt({ sub: 'x', client_id: 'test-client', exp: futureExp }),
                id_token: createTestJwt({
                    sub: 'x', aud: 'test-client',
                    iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
                    exp: futureExp
                }),
                auth_method: 'handler'
            };
            setTokens(tokens);
            expect(hasAdminScope()).toBe(false);
        });

        it('returns false for limited scope', () => {
            const tokens = {
                access_token: createTestJwt({
                    sub: 'x', scope: 'openid email', client_id: 'test-client', exp: futureExp
                }),
                id_token: createTestJwt({
                    sub: 'x', aud: 'test-client',
                    iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
                    exp: futureExp
                }),
                auth_method: 'handler'
            };
            setTokens(tokens);
            expect(hasAdminScope()).toBe(false);
        });
    });

    describe('isAuthenticated()', () => {
        it('returns true with valid cached tokens', () => {
            setTokens(createMockTokens());
            expect(isAuthenticated()).toBe(true);
        });

        it('returns false when cache is empty', () => {
            expect(isAuthenticated()).toBe(false);
        });

        it('returns false when tokens are expired', () => {
            setTokens(createMockTokens({ exp: pastExp }));
            expect(isAuthenticated()).toBe(false);
        });
    });
});

// ============================================================================
// Tests: isAdmin() and isReadonly() Alias Support — REAL auth.js
// ============================================================================

describe('isAdmin() Alias Support', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;

    function setWithGroups(groups) {
        setTokens({
            access_token: createTestJwt({ sub: 'x', client_id: 'test-client', exp: futureExp }),
            id_token: createTestJwt({
                sub: 'user-1', email: 'a@b.com',
                'cognito:groups': groups,
                aud: 'test-client',
                iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
                exp: futureExp
            })
        });
    }

    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    it('recognizes "admin" group', () => {
        setWithGroups(['admin']);
        expect(isAdmin()).toBe(true);
    });

    it('recognizes "admins" group (plural alias)', () => {
        setWithGroups(['admins']);
        expect(isAdmin()).toBe(true);
    });

    it('recognizes "administrators" group (full alias)', () => {
        setWithGroups(['administrators']);
        expect(isAdmin()).toBe(true);
    });

    it('is case-insensitive', () => {
        setWithGroups(['ADMINS']);
        expect(isAdmin()).toBe(true);
    });

    it('returns false for non-admin groups', () => {
        setWithGroups(['editors', 'users']);
        expect(isAdmin()).toBe(false);
    });

    it('returns false when not authenticated', () => {
        expect(isAdmin()).toBe(false);
    });
});

describe('isReadonly() Alias Support', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;

    function setWithGroups(groups) {
        setTokens({
            access_token: createTestJwt({ sub: 'x', client_id: 'test-client', exp: futureExp }),
            id_token: createTestJwt({
                sub: 'user-1', email: 'a@b.com',
                'cognito:groups': groups,
                aud: 'test-client',
                iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
                exp: futureExp
            })
        });
    }

    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    it('recognizes "readonly" group', () => {
        setWithGroups(['readonly']);
        expect(isReadonly()).toBe(true);
    });

    it('recognizes "read-only" group (hyphenated alias)', () => {
        setWithGroups(['read-only']);
        expect(isReadonly()).toBe(true);
    });

    it('recognizes "viewer" group', () => {
        setWithGroups(['viewer']);
        expect(isReadonly()).toBe(true);
    });

    it('recognizes "viewers" group (plural)', () => {
        setWithGroups(['viewers']);
        expect(isReadonly()).toBe(true);
    });

    it('returns false when user is also admin', () => {
        setWithGroups(['readonly', 'admin']);
        expect(isReadonly()).toBe(false);
    });

    it('returns false when user is admin via alias', () => {
        setWithGroups(['readonly', 'admins']);
        expect(isReadonly()).toBe(false);
    });

    it('is case-insensitive', () => {
        setWithGroups(['ReadOnly']);
        expect(isReadonly()).toBe(true);
    });

    it('returns false when not authenticated', () => {
        expect(isReadonly()).toBe(false);
    });
});

// ============================================================================
// Tests: shouldRefreshToken() — REAL auth.js
// ============================================================================

describe('shouldRefreshToken() Handler Mode', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    it('returns true for tokens approaching expiry (password, 5-min window)', () => {
        const nearExpiry = Math.floor(Date.now() / 1000) + 120;
        const tokens = {
            access_token: 'x',
            id_token: createTestJwt({ sub: 'user-1', exp: nearExpiry }),
            auth_method: 'password'
        };
        expect(shouldRefreshToken(tokens)).toBe(true);
    });

    it('returns false for tokens with plenty of time left', () => {
        const farExpiry = Math.floor(Date.now() / 1000) + 7200;
        const tokens = {
            access_token: 'x',
            id_token: createTestJwt({ sub: 'user-1', exp: farExpiry }),
            auth_method: 'password'
        };
        expect(shouldRefreshToken(tokens)).toBe(false);
    });

    it('uses passkey refresh window (1 hour) for passkey tokens', () => {
        const nearExpiry = Math.floor(Date.now() / 1000) + 1800;
        const tokens = {
            access_token: 'x',
            id_token: createTestJwt({ sub: 'user-1', exp: nearExpiry }),
            auth_method: 'passkey'
        };
        expect(shouldRefreshToken(tokens)).toBe(true);
    });

    it('does not require client-side refresh_token in handler mode', () => {
        const nearExpiry = Math.floor(Date.now() / 1000) + 120;
        const tokens = {
            access_token: 'x',
            id_token: createTestJwt({ sub: 'user-1', exp: nearExpiry }),
            auth_method: 'password'
            // No refresh_token — server has it
        };
        expect(shouldRefreshToken(tokens)).toBe(true);
    });

    it('works with refresh_token present', () => {
        const nearExpiry = Math.floor(Date.now() / 1000) + 120;
        const tokens = {
            access_token: 'x',
            id_token: createTestJwt({ sub: 'user-1', exp: nearExpiry }),
            refresh_token: 'refresh-xxx',
            auth_method: 'password'
        };
        expect(shouldRefreshToken(tokens)).toBe(true);
    });

    it('returns false for null tokens', () => {
        expect(shouldRefreshToken(null)).toBe(false);
    });

    it('returns false for tokens without id_token', () => {
        expect(shouldRefreshToken({ access_token: 'x' })).toBe(false);
    });

    it('returns false for invalid JWT in id_token', () => {
        expect(shouldRefreshToken({ access_token: 'x', id_token: 'not-a-jwt' })).toBe(false);
    });
});

// ============================================================================
// Tests: Regression — all sync functions work with real auth.js
// ============================================================================

describe('Handler Mode Regression Tests', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();

        const futureExp = Math.floor(Date.now() / 1000) + 3600;
        setTokens({
            access_token: createTestJwt({
                sub: 'user-123',
                scope: 'openid email aws.cognito.signin.user.admin',
                client_id: 'test-client',
                exp: futureExp
            }),
            id_token: createTestJwt({
                sub: 'user-123',
                email: 'admin@company.com',
                'cognito:groups': ['admins', 'developers'],
                aud: 'test-client',
                iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
                exp: futureExp
            }),
            auth_method: 'handler'
        });
    });

    it('getAuthMethod does NOT return Promise', () => {
        const result = getAuthMethod();
        expect(result).not.toBeInstanceOf(Promise);
        expect(result).toBe('handler');
    });

    it('getIdTokenClaims does NOT return null in handler mode', () => {
        const claims = getIdTokenClaims();
        expect(claims).not.toBeNull();
        expect(claims.email).toBe('admin@company.com');
    });

    it('getUserEmail does NOT return null in handler mode', () => {
        expect(getUserEmail()).toBe('admin@company.com');
    });

    it('getUserGroups does NOT return empty array in handler mode', () => {
        const groups = getUserGroups();
        expect(groups).not.toEqual([]);
        expect(groups).toContain('admins');
        expect(groups).toContain('developers');
    });

    it('isAdmin returns true for user with "admins" group', () => {
        expect(isAdmin()).toBe(true);
    });

    it('hasAdminScope returns true with valid cached tokens', () => {
        expect(hasAdminScope()).toBe(true);
    });

    it('all sync functions work together in handler mode', () => {
        expect(isAuthenticated()).toBe(true);
        expect(getUserEmail()).toBe('admin@company.com');
        expect(isAdmin()).toBe(true);
        expect(isReadonly()).toBe(false);
        expect(getAuthMethod()).toBe('handler');
        expect(hasAdminScope()).toBe(true);
        expect(getUserGroups()).toContain('admins');
    });
});
