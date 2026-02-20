/**
 * L42 Cognito Passkey - Token Validation on Load Tests (v0.12.0)
 *
 * Tests:
 * - validateTokenClaims() — issuer verification
 * - validateTokenClaims() — client_id/aud verification
 * - validateTokenClaims() — unreasonable exp rejection
 * - isAuthenticated() clears invalid tokens
 * - Tokens from wrong pool rejected
 * - Normal tokens pass validation
 * - Handler mode validation
 * - Edge cases (null tokens, missing claims, decode errors)
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

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

function UNSAFE_decodeJwtPayload(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
}

function createValidTokens(claimOverrides = {}) {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const defaultClaims = {
        sub: 'user1',
        email: 'test@example.com',
        'cognito:groups': ['admin'],
        aud: 'test-client',
        iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
        exp
    };
    const claims = { ...defaultClaims, ...claimOverrides };
    return {
        access_token: createTestJwt({
            sub: claims.sub,
            scope: 'openid email aws.cognito.signin.user.admin',
            client_id: claims.aud,
            exp: claims.exp
        }),
        id_token: createTestJwt(claims),
        refresh_token: 'refresh-token-123',
        auth_method: 'password'
    };
}

// ============================================================================
// Simulated auth.js internals for token validation
// ============================================================================

const VERSION = '0.12.0';
const DEBUG_HISTORY_MAX = 100;
let _debugHistory = [];
let config = {
    debug: false,
    clientId: 'test-client',
    cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
    cognitoRegion: 'us-west-2',
    tokenStorage: 'handler',
    tokenKey: 'l42_auth_tokens',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout'
};
let _storedTokens = null;
let _tokenCleared = false;

function debugLog(category, message, data) {
    if (!config.debug) return;
    const event = {
        timestamp: Date.now(),
        category,
        message,
        ...(data !== undefined ? { data } : {}),
        version: VERSION
    };
    _debugHistory.push(event);
}

function getTokens() {
    return _storedTokens;
}

function clearTokens() {
    _storedTokens = null;
    _tokenCleared = true;
}

function isTokenExpired(tokens) {
    try {
        const claims = UNSAFE_decodeJwtPayload(tokens.id_token);
        return Date.now() >= claims.exp * 1000;
    } catch {
        return true;
    }
}

// The actual validateTokenClaims implementation (matches src/auth.js)
function validateTokenClaims(tokens) {
    if (!tokens || !tokens.id_token) return false;

    try {
        const claims = UNSAFE_decodeJwtPayload(tokens.id_token);

        // Verify issuer matches configured Cognito pool
        if (claims.iss) {
            const expectedIssPrefix = 'https://cognito-idp.' + config.cognitoRegion + '.amazonaws.com/';
            if (!claims.iss.startsWith(expectedIssPrefix)) {
                debugLog('token', 'validateTokenClaims:failed', {
                    reason: 'issuer mismatch',
                    expected: expectedIssPrefix + '...',
                    actual: claims.iss
                });
                return false;
            }
        }

        // Verify audience/client_id matches configured clientId
        const tokenClientId = claims.aud || claims.client_id;
        if (!tokenClientId) {
            debugLog('token', 'validateTokenClaims:failed', {
                reason: 'missing audience claim (aud or client_id)'
            });
            return false;
        }
        if (tokenClientId !== config.clientId) {
            debugLog('token', 'validateTokenClaims:failed', {
                reason: 'client_id mismatch',
                expected: config.clientId,
                actual: tokenClientId
            });
            return false;
        }

        // Reject tokens without expiry or with unreasonable exp (> 30 days in future)
        if (!claims.exp || typeof claims.exp !== 'number') {
            debugLog('token', 'validateTokenClaims:failed', {
                reason: 'missing or invalid expiry claim'
            });
            return false;
        }
        var maxReasonableExp = Date.now() / 1000 + (30 * 24 * 60 * 60);
        if (claims.exp > maxReasonableExp) {
            debugLog('token', 'validateTokenClaims:failed', {
                reason: 'unreasonable expiry',
                exp: claims.exp
            });
            return false;
        }

        return true;
    } catch {
        debugLog('token', 'validateTokenClaims:failed', { reason: 'decode error' });
        return false;
    }
}

// Updated isAuthenticated with validation (matches src/auth.js)
function isAuthenticated() {
    // In handler mode, uses cached tokens for sync check
    const tokens = getTokens();
    if (tokens && !validateTokenClaims(tokens)) {
        clearTokens();
        return false;
    }
    return !!(tokens && !isTokenExpired(tokens));
}

// ============================================================================
// Tests
// ============================================================================

describe('Token Validation on Load', () => {
    beforeEach(() => {
        _storedTokens = null;
        _tokenCleared = false;
        _debugHistory = [];
        config.debug = false;
        config.clientId = 'test-client';
        config.cognitoRegion = 'us-west-2';
    });

    describe('validateTokenClaims() — issuer verification', () => {
        it('accepts tokens with matching issuer region', () => {
            const tokens = createValidTokens();
            expect(validateTokenClaims(tokens)).toBe(true);
        });

        it('rejects tokens from different region', () => {
            config.debug = true;
            const tokens = createValidTokens({
                iss: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_wrongPool'
            });
            expect(validateTokenClaims(tokens)).toBe(false);
            expect(_debugHistory[0].data.reason).toBe('issuer mismatch');
        });

        it('rejects tokens from non-Cognito issuer', () => {
            config.debug = true;
            const tokens = createValidTokens({
                iss: 'https://evil.example.com/tokens'
            });
            expect(validateTokenClaims(tokens)).toBe(false);
        });

        it('accepts tokens without iss claim (no verification possible)', () => {
            const exp = Math.floor(Date.now() / 1000) + 3600;
            const tokens = {
                id_token: createTestJwt({
                    sub: 'user1',
                    email: 'test@example.com',
                    aud: 'test-client',
                    exp
                }),
                access_token: createTestJwt({ sub: 'user1', exp }),
                refresh_token: 'refresh-123'
            };
            expect(validateTokenClaims(tokens)).toBe(true);
        });

        it('handles different configured regions', () => {
            config.cognitoRegion = 'ap-southeast-1';
            const tokens = createValidTokens({
                iss: 'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_pool'
            });
            expect(validateTokenClaims(tokens)).toBe(true);
        });
    });

    describe('validateTokenClaims() — client_id/aud verification', () => {
        it('accepts tokens with matching aud', () => {
            const tokens = createValidTokens({ aud: 'test-client' });
            expect(validateTokenClaims(tokens)).toBe(true);
        });

        it('rejects tokens with different aud', () => {
            config.debug = true;
            const tokens = createValidTokens({ aud: 'other-client-id' });
            expect(validateTokenClaims(tokens)).toBe(false);
            expect(_debugHistory[0].data.reason).toBe('client_id mismatch');
        });

        it('rejects tokens without aud or client_id', () => {
            config.debug = true;
            const exp = Math.floor(Date.now() / 1000) + 3600;
            const tokens = {
                id_token: createTestJwt({
                    sub: 'user1',
                    email: 'test@example.com',
                    iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test',
                    exp
                }),
                access_token: createTestJwt({ sub: 'user1', exp }),
                refresh_token: 'refresh-123'
            };
            expect(validateTokenClaims(tokens)).toBe(false);
            expect(_debugHistory[0].data.reason).toBe('missing audience claim (aud or client_id)');
        });

        it('checks client_id fallback when aud is missing', () => {
            config.debug = true;
            const exp = Math.floor(Date.now() / 1000) + 3600;
            const tokens = {
                id_token: createTestJwt({
                    sub: 'user1',
                    client_id: 'wrong-client',
                    iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test',
                    exp
                }),
                access_token: createTestJwt({ sub: 'user1', exp }),
                refresh_token: 'refresh-123'
            };
            expect(validateTokenClaims(tokens)).toBe(false);
            expect(_debugHistory[0].data.reason).toBe('client_id mismatch');
        });
    });

    describe('validateTokenClaims() — unreasonable exp rejection', () => {
        it('accepts tokens with normal expiry (1 hour)', () => {
            const tokens = createValidTokens();
            expect(validateTokenClaims(tokens)).toBe(true);
        });

        it('accepts tokens with 29-day expiry', () => {
            const exp = Math.floor(Date.now() / 1000) + (29 * 24 * 60 * 60);
            const tokens = createValidTokens({ exp });
            expect(validateTokenClaims(tokens)).toBe(true);
        });

        it('rejects tokens with exp > 30 days in future', () => {
            config.debug = true;
            const exp = Math.floor(Date.now() / 1000) + (31 * 24 * 60 * 60);
            const tokens = createValidTokens({ exp });
            expect(validateTokenClaims(tokens)).toBe(false);
            expect(_debugHistory[0].data.reason).toBe('unreasonable expiry');
        });

        it('rejects tokens with exp 1 year in future', () => {
            const exp = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60);
            const tokens = createValidTokens({ exp });
            expect(validateTokenClaims(tokens)).toBe(false);
        });

        it('accepts already-expired tokens (validation only checks future bound)', () => {
            const exp = Math.floor(Date.now() / 1000) - 3600;
            const tokens = createValidTokens({ exp });
            // validateTokenClaims checks unreasonable future, not past expiry
            // isTokenExpired handles past expiry
            expect(validateTokenClaims(tokens)).toBe(true);
        });
    });

    describe('validateTokenClaims() — edge cases', () => {
        it('returns false for null tokens', () => {
            expect(validateTokenClaims(null)).toBe(false);
        });

        it('returns false for undefined tokens', () => {
            expect(validateTokenClaims(undefined)).toBe(false);
        });

        it('returns false for tokens without id_token', () => {
            expect(validateTokenClaims({ access_token: 'abc' })).toBe(false);
        });

        it('returns false for malformed JWT', () => {
            config.debug = true;
            expect(validateTokenClaims({ id_token: 'not-a-jwt' })).toBe(false);
            expect(_debugHistory[0].data.reason).toBe('decode error');
        });

        it('returns false for empty id_token', () => {
            expect(validateTokenClaims({ id_token: '' })).toBe(false);
        });
    });

    describe('isAuthenticated() with validation', () => {
        it('returns true for valid tokens', () => {
            _storedTokens = createValidTokens();
            expect(isAuthenticated()).toBe(true);
        });

        it('returns false and clears tokens from wrong pool', () => {
            _storedTokens = createValidTokens({
                iss: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_wrongPool'
            });
            expect(isAuthenticated()).toBe(false);
            expect(_tokenCleared).toBe(true);
            expect(_storedTokens).toBeNull();
        });

        it('returns false and clears tokens with wrong client_id', () => {
            _storedTokens = createValidTokens({ aud: 'different-app-client' });
            expect(isAuthenticated()).toBe(false);
            expect(_tokenCleared).toBe(true);
        });

        it('returns false and clears tokens with unreasonable expiry', () => {
            const exp = Math.floor(Date.now() / 1000) + (60 * 24 * 60 * 60);
            _storedTokens = createValidTokens({ exp });
            expect(isAuthenticated()).toBe(false);
            expect(_tokenCleared).toBe(true);
        });

        it('returns false for expired but valid-claims tokens', () => {
            const exp = Math.floor(Date.now() / 1000) - 3600;
            _storedTokens = createValidTokens({ exp });
            // Claims are valid but token is expired
            expect(isAuthenticated()).toBe(false);
            // Token is NOT cleared because claims are valid — it's just expired
            expect(_tokenCleared).toBe(false);
        });

        it('returns false when no tokens stored', () => {
            _storedTokens = null;
            expect(isAuthenticated()).toBe(false);
            expect(_tokenCleared).toBe(false);
        });
    });

    describe('debug logging for validation failures', () => {
        beforeEach(() => {
            config.debug = true;
        });

        it('logs issuer mismatch with expected and actual', () => {
            const tokens = createValidTokens({
                iss: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_other'
            });
            validateTokenClaims(tokens);
            expect(_debugHistory[0].message).toBe('validateTokenClaims:failed');
            expect(_debugHistory[0].data.reason).toBe('issuer mismatch');
            expect(_debugHistory[0].data.expected).toContain('us-west-2');
            expect(_debugHistory[0].data.actual).toContain('eu-west-1');
        });

        it('logs client_id mismatch with expected and actual', () => {
            const tokens = createValidTokens({ aud: 'wrong-client' });
            validateTokenClaims(tokens);
            expect(_debugHistory[0].data.reason).toBe('client_id mismatch');
            expect(_debugHistory[0].data.expected).toBe('test-client');
            expect(_debugHistory[0].data.actual).toBe('wrong-client');
        });

        it('logs unreasonable expiry with exp value', () => {
            const exp = Math.floor(Date.now() / 1000) + (60 * 24 * 60 * 60);
            const tokens = createValidTokens({ exp });
            validateTokenClaims(tokens);
            expect(_debugHistory[0].data.reason).toBe('unreasonable expiry');
            expect(_debugHistory[0].data.exp).toBe(exp);
        });

        it('logs decode error for malformed tokens', () => {
            validateTokenClaims({ id_token: 'bad.token.here' });
            expect(_debugHistory[0].data.reason).toBe('decode error');
        });
    });

    describe('cross-environment token migration', () => {
        it('detects dev tokens used in staging (different region)', () => {
            // Simulates: dev tokens in localStorage from us-east-1 pool
            // while current app is configured for us-west-2
            config.cognitoRegion = 'us-west-2';
            const devTokens = createValidTokens({
                iss: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_devPool'
            });
            expect(validateTokenClaims(devTokens)).toBe(false);
        });

        it('detects tokens from a different app (different client_id)', () => {
            config.clientId = 'prod-client-abc';
            const otherAppTokens = createValidTokens({ aud: 'staging-client-xyz' });
            expect(validateTokenClaims(otherAppTokens)).toBe(false);
        });
    });
});
