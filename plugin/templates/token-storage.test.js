/**
 * L42 Cognito Passkey - Token Storage Tests
 *
 * Tests for token storage abstraction (handler mode only as of v0.15.0).
 * Uses REAL auth.js functions via _resetForTesting().
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    configure,
    setTokens,
    clearTokens,
    getTokens,
    isAuthenticated,
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

function createMockTokens(overrides = {}) {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    return {
        access_token: createTestJwt({ sub: 'user1', client_id: 'test-client', exp }),
        id_token: createTestJwt({
            sub: 'user1', aud: 'test-client',
            iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test',
            exp, ...overrides
        }),
        auth_method: 'passkey'
    };
}

function configureForTest(overrides = {}) {
    configure({
        clientId: 'test-client',
        cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
        tokenEndpoint: '/auth/token',
        refreshEndpoint: '/auth/refresh',
        logoutEndpoint: '/auth/logout',
        sessionEndpoint: '/auth/session',
        ...overrides
    });
}

// ============================================================================
// Handler Token Store — REAL auth.js
// ============================================================================

describe('Handler Token Store', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    it('caches tokens in memory via setTokens', () => {
        const tokens = createMockTokens();
        setTokens(tokens);
        expect(isAuthenticated()).toBe(true);
    });

    it('returns false when no tokens cached', () => {
        expect(isAuthenticated()).toBe(false);
    });

    it('clears cached tokens', () => {
        setTokens(createMockTokens());
        clearTokens();
        expect(isAuthenticated()).toBe(false);
    });

    it('overwrites existing cached tokens on set', () => {
        setTokens(createMockTokens());
        setTokens(createMockTokens({ email: 'new@example.com' }));
        expect(isAuthenticated()).toBe(true);
    });

    it('supports full token lifecycle: set, get, clear', () => {
        expect(isAuthenticated()).toBe(false);
        setTokens(createMockTokens());
        expect(isAuthenticated()).toBe(true);
        clearTokens();
        expect(isAuthenticated()).toBe(false);
    });
});

// ============================================================================
// Configuration Validation — REAL configure()
// ============================================================================

describe('Token Storage Configuration', () => {
    beforeEach(() => {
        _resetForTesting();
    });

    it('accepts "handler" mode', () => {
        expect(() => configureForTest({ tokenStorage: 'handler' })).not.toThrow();
    });

    it('accepts undefined mode (uses default handler)', () => {
        expect(() => configureForTest()).not.toThrow();
    });

    it('rejects deprecated "localStorage" mode', () => {
        expect(() => configureForTest({ tokenStorage: 'localStorage' })).toThrow(/removed in v0\.15\.0/);
    });

    it('rejects deprecated "memory" mode', () => {
        expect(() => configureForTest({ tokenStorage: 'memory' })).toThrow(/removed in v0\.15\.0/);
    });

    it('rejects "sessionStorage" (never supported)', () => {
        expect(() => configureForTest({ tokenStorage: 'sessionStorage' })).toThrow(/removed in v0\.15\.0/);
    });

    it('rejects "cookie" (never supported)', () => {
        expect(() => configureForTest({ tokenStorage: 'cookie' })).toThrow(/removed in v0\.15\.0/);
    });
});

// ============================================================================
// Handler Mode Security Properties — REAL auth.js
// ============================================================================

describe('Handler Mode Security Properties', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
        localStorage.clear();
    });

    afterEach(() => {
        localStorage.clear();
    });

    it('tokens are not stored in localStorage', () => {
        setTokens(createMockTokens());

        const allKeys = Object.keys(localStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('tokens are not stored in sessionStorage', () => {
        setTokens(createMockTokens());

        const allKeys = Object.keys(sessionStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('tokens are only cached briefly in memory', () => {
        setTokens(createMockTokens());

        expect(isAuthenticated()).toBe(true);
        expect(localStorage.getItem('l42_auth_tokens')).toBeNull();
        expect(sessionStorage.getItem('l42_auth_tokens')).toBeNull();
    });
});
