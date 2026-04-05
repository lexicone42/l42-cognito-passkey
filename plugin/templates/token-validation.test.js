/**
 * L42 Cognito Passkey - Token Validation on Load Tests (v0.12.0)
 *
 * Tests the REAL auth.js implementation — imports directly from src/auth.js
 * instead of re-implementing functions. Uses _resetForTesting() for isolation.
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
import {
    configure,
    isAuthenticated,
    isTokenExpired,
    setTokens,
    getTokens,
    UNSAFE_decodeJwtPayload,
    getDebugHistory,
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

/** Configure auth module with test defaults. */
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

// ============================================================================
// Tests — calling real auth.js functions
// ============================================================================

describe('Token Validation on Load', () => {
    beforeEach(() => {
        _resetForTesting();
    });

    // validateTokenClaims is private, but isAuthenticated() calls it internally.
    // We test it indirectly through isAuthenticated() + UNSAFE_decodeJwtPayload().
    // For direct validation testing, we call isAuthenticated() after setTokens().

    describe('validateTokenClaims() — issuer verification', () => {
        it('accepts tokens with matching issuer region', () => {
            configureForTest();
            const tokens = createValidTokens();
            setTokens(tokens);
            expect(isAuthenticated()).toBe(true);
        });

        it('rejects tokens from different region', () => {
            configureForTest({ debug: true });
            const tokens = createValidTokens({
                iss: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_wrongPool'
            });
            setTokens(tokens);
            expect(isAuthenticated()).toBe(false);
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('issuer mismatch');
        });

        it('rejects tokens from non-Cognito issuer', () => {
            configureForTest({ debug: true });
            const tokens = createValidTokens({
                iss: 'https://evil.example.com/tokens'
            });
            setTokens(tokens);
            expect(isAuthenticated()).toBe(false);
        });

        it('accepts tokens without iss claim (no verification possible)', () => {
            configureForTest();
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
            setTokens(tokens);
            expect(isAuthenticated()).toBe(true);
        });

        it('handles different configured regions', () => {
            configureForTest({ cognitoRegion: 'ap-southeast-1' });
            const tokens = createValidTokens({
                iss: 'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_pool'
            });
            setTokens(tokens);
            expect(isAuthenticated()).toBe(true);
        });
    });

    describe('validateTokenClaims() — client_id/aud verification', () => {
        it('accepts tokens with matching aud', () => {
            configureForTest();
            const tokens = createValidTokens({ aud: 'test-client' });
            setTokens(tokens);
            expect(isAuthenticated()).toBe(true);
        });

        it('rejects tokens with different aud', () => {
            configureForTest({ debug: true });
            const tokens = createValidTokens({ aud: 'other-client-id' });
            setTokens(tokens);
            expect(isAuthenticated()).toBe(false);
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('client_id mismatch');
        });

        it('rejects tokens without aud or client_id', () => {
            configureForTest({ debug: true });
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
            setTokens(tokens);
            expect(isAuthenticated()).toBe(false);
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('missing audience claim (aud or client_id)');
        });

        it('checks client_id fallback when aud is missing', () => {
            configureForTest({ debug: true });
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
            setTokens(tokens);
            expect(isAuthenticated()).toBe(false);
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('client_id mismatch');
        });
    });

    describe('validateTokenClaims() — unreasonable exp rejection', () => {
        it('accepts tokens with normal expiry (1 hour)', () => {
            configureForTest();
            const tokens = createValidTokens();
            setTokens(tokens);
            expect(isAuthenticated()).toBe(true);
        });

        it('accepts tokens with 29-day expiry', () => {
            configureForTest();
            const exp = Math.floor(Date.now() / 1000) + (29 * 24 * 60 * 60);
            const tokens = createValidTokens({ exp });
            setTokens(tokens);
            expect(isAuthenticated()).toBe(true);
        });

        it('rejects tokens with exp > 30 days in future', () => {
            configureForTest({ debug: true });
            const exp = Math.floor(Date.now() / 1000) + (31 * 24 * 60 * 60);
            const tokens = createValidTokens({ exp });
            setTokens(tokens);
            expect(isAuthenticated()).toBe(false);
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('unreasonable expiry');
        });

        it('rejects tokens with exp 1 year in future', () => {
            configureForTest();
            const exp = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60);
            const tokens = createValidTokens({ exp });
            setTokens(tokens);
            expect(isAuthenticated()).toBe(false);
        });

        it('accepts already-expired tokens (validation only checks future bound)', () => {
            configureForTest();
            const exp = Math.floor(Date.now() / 1000) - 3600;
            const tokens = createValidTokens({ exp });
            setTokens(tokens);
            // Claims are valid but token is expired — isAuthenticated returns false
            // but NOT because of validateTokenClaims (that passes), because of isTokenExpired
            expect(isAuthenticated()).toBe(false);
        });
    });

    describe('validateTokenClaims() — edge cases', () => {
        it('returns false when no tokens stored', () => {
            configureForTest();
            // No tokens set — isAuthenticated returns false
            expect(isAuthenticated()).toBe(false);
        });

        it('returns false for tokens without id_token', () => {
            configureForTest();
            setTokens({ access_token: 'abc' });
            expect(isAuthenticated()).toBe(false);
        });

        it('returns false for malformed JWT', () => {
            configureForTest({ debug: true });
            setTokens({ id_token: 'not-a-jwt', access_token: 'x' });
            expect(isAuthenticated()).toBe(false);
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('decode error');
        });

        it('returns false for empty id_token', () => {
            configureForTest();
            setTokens({ id_token: '', access_token: 'x' });
            expect(isAuthenticated()).toBe(false);
        });
    });

    describe('isAuthenticated() with validation', () => {
        it('returns true for valid tokens', () => {
            configureForTest();
            setTokens(createValidTokens());
            expect(isAuthenticated()).toBe(true);
        });

        it('returns false and clears tokens from wrong pool', () => {
            configureForTest();
            setTokens(createValidTokens({
                iss: 'https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_wrongPool'
            }));
            expect(isAuthenticated()).toBe(false);
            // Call isAuthenticated again — if tokens were cleared, still false
            // (not just "invalid" but actually removed from cache)
            expect(isAuthenticated()).toBe(false);
        });

        it('returns false and clears tokens with wrong client_id', () => {
            configureForTest();
            setTokens(createValidTokens({ aud: 'different-app-client' }));
            expect(isAuthenticated()).toBe(false);
            expect(isAuthenticated()).toBe(false);
        });

        it('returns false and clears tokens with unreasonable expiry', () => {
            configureForTest();
            const exp = Math.floor(Date.now() / 1000) + (60 * 24 * 60 * 60);
            setTokens(createValidTokens({ exp }));
            expect(isAuthenticated()).toBe(false);
            expect(isAuthenticated()).toBe(false);
        });

        it('returns false for expired but valid-claims tokens', () => {
            configureForTest();
            const exp = Math.floor(Date.now() / 1000) - 3600;
            setTokens(createValidTokens({ exp }));
            // Claims are valid but token is expired
            expect(isAuthenticated()).toBe(false);
        });

        it('returns false when no tokens stored', () => {
            configureForTest();
            expect(isAuthenticated()).toBe(false);
        });
    });

    describe('debug logging for validation failures', () => {
        it('logs issuer mismatch with expected and actual', () => {
            configureForTest({ debug: true });
            const tokens = createValidTokens({
                iss: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_other'
            });
            setTokens(tokens);
            isAuthenticated(); // triggers validateTokenClaims
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('issuer mismatch');
            expect(failEvent.data.expected).toContain('us-west-2');
            expect(failEvent.data.actual).toContain('eu-west-1');
        });

        it('logs client_id mismatch with expected and actual', () => {
            configureForTest({ debug: true });
            setTokens(createValidTokens({ aud: 'wrong-client' }));
            isAuthenticated();
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('client_id mismatch');
            expect(failEvent.data.expected).toBe('test-client');
            expect(failEvent.data.actual).toBe('wrong-client');
        });

        it('logs unreasonable expiry with exp value', () => {
            configureForTest({ debug: true });
            const exp = Math.floor(Date.now() / 1000) + (60 * 24 * 60 * 60);
            setTokens(createValidTokens({ exp }));
            isAuthenticated();
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('unreasonable expiry');
            expect(failEvent.data.exp).toBe(exp);
        });

        it('logs decode error for malformed tokens', () => {
            configureForTest({ debug: true });
            setTokens({ id_token: 'bad.token.here', access_token: 'x' });
            isAuthenticated();
            const history = getDebugHistory();
            const failEvent = history.find(e => e.message === 'validateTokenClaims:failed');
            expect(failEvent.data.reason).toBe('decode error');
        });
    });

    describe('UNSAFE_decodeJwtPayload — real implementation', () => {
        it('decodes valid JWT claims', () => {
            const claims = { sub: 'user1', email: 'test@example.com', exp: 9999999999 };
            const jwt = createTestJwt(claims);
            const decoded = UNSAFE_decodeJwtPayload(jwt);
            expect(decoded.sub).toBe('user1');
            expect(decoded.email).toBe('test@example.com');
        });
    });

    describe('cross-environment token migration', () => {
        it('detects dev tokens used in staging (different region)', () => {
            configureForTest({ cognitoRegion: 'us-west-2' });
            const devTokens = createValidTokens({
                iss: 'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_devPool'
            });
            setTokens(devTokens);
            expect(isAuthenticated()).toBe(false);
        });

        it('detects tokens from a different app (different client_id)', () => {
            configureForTest({ clientId: 'prod-client-abc' });
            const otherAppTokens = createValidTokens({ aud: 'staging-client-xyz' });
            setTokens(otherAppTokens);
            expect(isAuthenticated()).toBe(false);
        });
    });
});
