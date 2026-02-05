/**
 * L42 Cognito Passkey - Handler Mode Sync API Tests
 *
 * Tests that sync functions (getAuthMethod, getIdTokenClaims, getUserEmail,
 * getUserGroups, isAdmin, isReadonly, hasAdminScope) work correctly in
 * handler mode by using cached tokens instead of async getTokens().
 *
 * Also tests:
 * - shouldRefreshToken() proactive refresh in handler mode
 * - isAdmin/isReadonly alias support
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// Test Helpers - mirror auth.js internals
// ============================================================================

/**
 * Minimal JWT encoder for test tokens.
 * Creates a valid JWT structure (header.payload.signature) with
 * base64url-encoded payload.
 */
function createTestJwt(claims) {
    const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const payload = btoa(JSON.stringify(claims))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const signature = 'test-signature';
    return `${header}.${payload}.${signature}`;
}

function UNSAFE_decodeJwtPayload(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
}

// ============================================================================
// Simulated auth.js handler mode internals
// ============================================================================

let config = {
    tokenStorage: 'handler',
    tokenKey: 'l42_auth_tokens',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    handlerCacheTtl: 30000
};

const REFRESH_CONFIG = {
    password: { cookieMaxAge: 86400, refreshBefore: 300000 },
    passkey: { cookieMaxAge: 2592000, refreshBefore: 3600000 }
};

const HandlerTokenStore = {
    _cache: null,
    _cacheExpiry: 0,
    _fetchPromise: null,

    async get(_tokenKey) {
        if (this._cache && Date.now() < this._cacheExpiry) {
            return this._cache;
        }
        // In real implementation, would fetch from server
        // For tests, just return cache or null
        return this._cache;
    },

    set(_tokenKey, tokens) {
        this._cache = tokens;
        this._cacheExpiry = Date.now() + (config.handlerCacheTtl || 30000);
    },

    clear(_tokenKey) {
        this._cache = null;
        this._cacheExpiry = 0;
    },

    getCached() {
        if (this._cache && Date.now() < this._cacheExpiry) {
            return this._cache;
        }
        return null;
    },

    _reset() {
        this._cache = null;
        this._cacheExpiry = 0;
        this._fetchPromise = null;
    }
};

function isHandlerMode() {
    return config.tokenStorage === 'handler';
}

/**
 * The fix: getTokensSync() uses getCached() in handler mode
 * instead of the async get() method.
 */
function getTokensSync() {
    if (isHandlerMode()) {
        return HandlerTokenStore.getCached();
    }
    // In non-handler modes, this would return from localStorage/memory
    return null;
}

// Sync API functions that now use getTokensSync()
function getAuthMethod() {
    const tokens = getTokensSync();
    return tokens ? (tokens.auth_method || 'password') : null;
}

function getIdTokenClaims() {
    const tokens = getTokensSync();
    if (!tokens || !tokens.id_token) return null;
    try {
        return UNSAFE_decodeJwtPayload(tokens.id_token);
    } catch {
        return null;
    }
}

function getUserEmail() {
    const claims = getIdTokenClaims();
    return claims ? claims.email : null;
}

function getUserGroups() {
    const claims = getIdTokenClaims();
    return claims && claims['cognito:groups'] ? claims['cognito:groups'] : [];
}

function isAdmin() {
    const groups = getUserGroups().map(g => g.toLowerCase());
    return groups.includes('admin') || groups.includes('admins') || groups.includes('administrators');
}

function isReadonly() {
    const groups = getUserGroups().map(g => g.toLowerCase());
    const hasReadonly = groups.includes('readonly') || groups.includes('read-only') ||
                        groups.includes('viewer') || groups.includes('viewers');
    const hasAdmin = groups.includes('admin') || groups.includes('admins') || groups.includes('administrators');
    return hasReadonly && !hasAdmin;
}

function hasAdminScope() {
    const tokens = getTokensSync();
    if (!tokens || !tokens.access_token) return false;
    try {
        const payload = UNSAFE_decodeJwtPayload(tokens.access_token);
        const scope = payload.scope || '';
        return scope.includes('aws.cognito.signin.user.admin');
    } catch {
        return false;
    }
}

function isTokenExpired(tokens) {
    try {
        return Date.now() >= UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
    } catch {
        return true;
    }
}

function shouldRefreshToken(tokens) {
    if (!tokens || !tokens.id_token) return false;
    // Handler mode fix: don't require refresh_token (it's server-side)
    if (!isHandlerMode() && !tokens.refresh_token) return false;
    try {
        const exp = UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
        const authMethod = tokens.auth_method || 'password';
        const refreshConfig = REFRESH_CONFIG[authMethod] || REFRESH_CONFIG.password;
        return Date.now() >= (exp - refreshConfig.refreshBefore);
    } catch {
        return false;
    }
}

function isAuthenticated() {
    if (isHandlerMode()) {
        const cached = HandlerTokenStore.getCached();
        return !!(cached && !isTokenExpired(cached));
    }
    const tokens = getTokensSync();
    return !!(tokens && !isTokenExpired(tokens));
}

// ============================================================================
// Tests: Handler Mode Sync API Functions
// ============================================================================

describe('Handler Mode Sync API', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
    const pastExp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

    const mockIdToken = createTestJwt({
        sub: 'user-123',
        email: 'test@example.com',
        'cognito:groups': ['admin', 'developers'],
        exp: futureExp
    });

    const mockAccessToken = createTestJwt({
        sub: 'user-123',
        scope: 'openid email aws.cognito.signin.user.admin',
        exp: futureExp
    });

    const mockTokens = {
        access_token: mockAccessToken,
        id_token: mockIdToken,
        auth_method: 'passkey'
    };

    beforeEach(() => {
        config.tokenStorage = 'handler';
        HandlerTokenStore._reset();
    });

    describe('getTokensSync()', () => {
        it('returns cached tokens in handler mode', () => {
            HandlerTokenStore.set('key', mockTokens);

            const result = getTokensSync();

            expect(result).toEqual(mockTokens);
            expect(result).not.toBeInstanceOf(Promise);
        });

        it('returns null when cache is empty', () => {
            expect(getTokensSync()).toBeNull();
        });

        it('returns null when cache is expired', () => {
            HandlerTokenStore._cache = mockTokens;
            HandlerTokenStore._cacheExpiry = Date.now() - 1000;

            expect(getTokensSync()).toBeNull();
        });
    });

    describe('getAuthMethod()', () => {
        it('returns auth method from cached tokens', () => {
            HandlerTokenStore.set('key', mockTokens);

            expect(getAuthMethod()).toBe('passkey');
        });

        it('returns "password" as default when auth_method missing', () => {
            HandlerTokenStore.set('key', {
                access_token: mockAccessToken,
                id_token: mockIdToken
                // no auth_method
            });

            expect(getAuthMethod()).toBe('password');
        });

        it('returns null when not authenticated', () => {
            expect(getAuthMethod()).toBeNull();
        });

        it('returns "handler" for handler-originated tokens', () => {
            HandlerTokenStore.set('key', {
                access_token: mockAccessToken,
                id_token: mockIdToken,
                auth_method: 'handler'
            });

            expect(getAuthMethod()).toBe('handler');
        });
    });

    describe('getIdTokenClaims()', () => {
        it('returns decoded claims from cached ID token', () => {
            HandlerTokenStore.set('key', mockTokens);

            const claims = getIdTokenClaims();

            expect(claims.email).toBe('test@example.com');
            expect(claims.sub).toBe('user-123');
            expect(claims['cognito:groups']).toEqual(['admin', 'developers']);
        });

        it('returns null when not authenticated', () => {
            expect(getIdTokenClaims()).toBeNull();
        });

        it('returns null when id_token is missing', () => {
            HandlerTokenStore.set('key', { access_token: 'x' });

            expect(getIdTokenClaims()).toBeNull();
        });

        it('returns null for invalid JWT', () => {
            HandlerTokenStore.set('key', {
                access_token: 'x',
                id_token: 'not-a-jwt'
            });

            expect(getIdTokenClaims()).toBeNull();
        });
    });

    describe('getUserEmail()', () => {
        it('returns email from cached tokens', () => {
            HandlerTokenStore.set('key', mockTokens);

            expect(getUserEmail()).toBe('test@example.com');
        });

        it('returns null when not authenticated', () => {
            expect(getUserEmail()).toBeNull();
        });
    });

    describe('getUserGroups()', () => {
        it('returns groups from cached tokens', () => {
            HandlerTokenStore.set('key', mockTokens);

            expect(getUserGroups()).toEqual(['admin', 'developers']);
        });

        it('returns empty array when not authenticated', () => {
            expect(getUserGroups()).toEqual([]);
        });

        it('returns empty array when no groups in token', () => {
            const noGroupsToken = createTestJwt({
                sub: 'user-123',
                email: 'test@example.com',
                exp: futureExp
            });

            HandlerTokenStore.set('key', {
                access_token: mockAccessToken,
                id_token: noGroupsToken,
                auth_method: 'handler'
            });

            expect(getUserGroups()).toEqual([]);
        });
    });

    describe('hasAdminScope()', () => {
        it('returns true when access token has admin scope', () => {
            HandlerTokenStore.set('key', mockTokens);

            expect(hasAdminScope()).toBe(true);
        });

        it('returns false when not authenticated', () => {
            expect(hasAdminScope()).toBe(false);
        });

        it('returns false when scope is missing', () => {
            const noScopeToken = createTestJwt({
                sub: 'user-123',
                exp: futureExp
            });

            HandlerTokenStore.set('key', {
                access_token: noScopeToken,
                id_token: mockIdToken,
                auth_method: 'handler'
            });

            expect(hasAdminScope()).toBe(false);
        });

        it('returns false for limited scope', () => {
            const limitedScopeToken = createTestJwt({
                sub: 'user-123',
                scope: 'openid email',
                exp: futureExp
            });

            HandlerTokenStore.set('key', {
                access_token: limitedScopeToken,
                id_token: mockIdToken,
                auth_method: 'handler'
            });

            expect(hasAdminScope()).toBe(false);
        });
    });

    describe('isAuthenticated()', () => {
        it('returns true with valid cached tokens', () => {
            HandlerTokenStore.set('key', mockTokens);

            expect(isAuthenticated()).toBe(true);
        });

        it('returns false when cache is empty', () => {
            expect(isAuthenticated()).toBe(false);
        });

        it('returns false when tokens are expired', () => {
            const expiredIdToken = createTestJwt({
                sub: 'user-123',
                email: 'test@example.com',
                exp: pastExp
            });

            HandlerTokenStore.set('key', {
                access_token: mockAccessToken,
                id_token: expiredIdToken,
                auth_method: 'handler'
            });

            expect(isAuthenticated()).toBe(false);
        });
    });
});

// ============================================================================
// Tests: isAdmin() and isReadonly() Alias Support
// ============================================================================

describe('isAdmin() Alias Support', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const mockAccessToken = createTestJwt({ sub: 'x', exp: futureExp });

    beforeEach(() => {
        config.tokenStorage = 'handler';
        HandlerTokenStore._reset();
    });

    it('recognizes "admin" group', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['admin'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isAdmin()).toBe(true);
    });

    it('recognizes "admins" group (plural alias)', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['admins'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isAdmin()).toBe(true);
    });

    it('recognizes "administrators" group (full alias)', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['administrators'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isAdmin()).toBe(true);
    });

    it('is case-insensitive', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['ADMINS'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isAdmin()).toBe(true);
    });

    it('returns false for non-admin groups', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['editors', 'users'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isAdmin()).toBe(false);
    });

    it('returns false when not authenticated', () => {
        expect(isAdmin()).toBe(false);
    });
});

describe('isReadonly() Alias Support', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;
    const mockAccessToken = createTestJwt({ sub: 'x', exp: futureExp });

    beforeEach(() => {
        config.tokenStorage = 'handler';
        HandlerTokenStore._reset();
    });

    it('recognizes "readonly" group', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['readonly'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isReadonly()).toBe(true);
    });

    it('recognizes "read-only" group (hyphenated alias)', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['read-only'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isReadonly()).toBe(true);
    });

    it('recognizes "viewer" group', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['viewer'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isReadonly()).toBe(true);
    });

    it('recognizes "viewers" group (plural)', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['viewers'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isReadonly()).toBe(true);
    });

    it('returns false when user is also admin', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['readonly', 'admin'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isReadonly()).toBe(false);
    });

    it('returns false when user is admin via alias', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['readonly', 'admins'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isReadonly()).toBe(false);
    });

    it('is case-insensitive', () => {
        const idToken = createTestJwt({
            sub: 'user-1', email: 'a@b.com',
            'cognito:groups': ['ReadOnly'],
            exp: futureExp
        });
        HandlerTokenStore.set('key', { access_token: mockAccessToken, id_token: idToken });

        expect(isReadonly()).toBe(true);
    });

    it('returns false when not authenticated', () => {
        expect(isReadonly()).toBe(false);
    });
});

// ============================================================================
// Tests: shouldRefreshToken() Handler Mode Fix
// ============================================================================

describe('shouldRefreshToken() Handler Mode', () => {
    beforeEach(() => {
        config.tokenStorage = 'handler';
    });

    it('returns true for tokens approaching expiry (no refresh_token needed)', () => {
        // Token expires in 2 minutes - within the 5-minute refresh window for password
        const nearExpiry = Math.floor(Date.now() / 1000) + 120;
        const idToken = createTestJwt({
            sub: 'user-1',
            exp: nearExpiry
        });

        const tokens = {
            access_token: 'x',
            id_token: idToken,
            auth_method: 'password'
            // Note: no refresh_token - it's server-side in handler mode
        };

        expect(shouldRefreshToken(tokens)).toBe(true);
    });

    it('returns false for tokens with plenty of time left', () => {
        const farExpiry = Math.floor(Date.now() / 1000) + 7200; // 2 hours
        const idToken = createTestJwt({
            sub: 'user-1',
            exp: farExpiry
        });

        const tokens = {
            access_token: 'x',
            id_token: idToken,
            auth_method: 'password'
        };

        expect(shouldRefreshToken(tokens)).toBe(false);
    });

    it('uses passkey refresh window (1 hour) for passkey tokens', () => {
        // Token expires in 30 minutes - within the 1-hour refresh window for passkey
        const nearExpiry = Math.floor(Date.now() / 1000) + 1800;
        const idToken = createTestJwt({
            sub: 'user-1',
            exp: nearExpiry
        });

        const tokens = {
            access_token: 'x',
            id_token: idToken,
            auth_method: 'passkey'
        };

        expect(shouldRefreshToken(tokens)).toBe(true);
    });

    it('requires refresh_token in non-handler modes', () => {
        config.tokenStorage = 'localStorage';

        const nearExpiry = Math.floor(Date.now() / 1000) + 120;
        const idToken = createTestJwt({
            sub: 'user-1',
            exp: nearExpiry
        });

        const tokens = {
            access_token: 'x',
            id_token: idToken,
            auth_method: 'password'
            // No refresh_token
        };

        expect(shouldRefreshToken(tokens)).toBe(false);
    });

    it('works with refresh_token in non-handler modes', () => {
        config.tokenStorage = 'localStorage';

        const nearExpiry = Math.floor(Date.now() / 1000) + 120;
        const idToken = createTestJwt({
            sub: 'user-1',
            exp: nearExpiry
        });

        const tokens = {
            access_token: 'x',
            id_token: idToken,
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
        expect(shouldRefreshToken({
            access_token: 'x',
            id_token: 'not-a-jwt'
        })).toBe(false);
    });
});

// ============================================================================
// Tests: Previously Broken Behavior (Regression)
// ============================================================================

describe('Handler Mode Regression Tests', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600;

    const mockIdToken = createTestJwt({
        sub: 'user-123',
        email: 'admin@company.com',
        'cognito:groups': ['admins', 'developers'],
        exp: futureExp
    });

    const mockAccessToken = createTestJwt({
        sub: 'user-123',
        scope: 'openid email aws.cognito.signin.user.admin',
        exp: futureExp
    });

    const mockTokens = {
        access_token: mockAccessToken,
        id_token: mockIdToken,
        auth_method: 'handler'
    };

    beforeEach(() => {
        config.tokenStorage = 'handler';
        HandlerTokenStore._reset();
        HandlerTokenStore.set('key', mockTokens);
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
        // Previously returned false because:
        // 1. getTokens() returned Promise in handler mode
        // 2. isAdmin() only checked exact 'admin' string
        expect(isAdmin()).toBe(true);
    });

    it('hasAdminScope returns true with valid cached tokens', () => {
        expect(hasAdminScope()).toBe(true);
    });

    it('all sync functions work together in handler mode', () => {
        // Simulate a real use case: checking auth state on page load
        expect(isAuthenticated()).toBe(true);
        expect(getUserEmail()).toBe('admin@company.com');
        expect(isAdmin()).toBe(true);
        expect(isReadonly()).toBe(false);
        expect(getAuthMethod()).toBe('handler');
        expect(hasAdminScope()).toBe(true);
        expect(getUserGroups()).toContain('admins');
    });
});
