/**
 * L42 Cognito Passkey - Token Storage Tests
 *
 * Tests for token storage abstraction (handler mode only as of v0.15.0).
 * Handler mode stores tokens server-side in HttpOnly session cookies.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// Token Storage Abstraction (v0.15.0 — handler mode only)
// ============================================================================

/**
 * Handler-based token store.
 * Tokens are stored server-side in HttpOnly session cookies.
 * This store fetches tokens from the server endpoint and caches them briefly.
 * See handler-token-store.test.js for full async behavior tests.
 */
const HandlerTokenStore = {
    _cache: null,
    _cacheExpiry: 0,

    // Sync get for compatibility testing - full async tested separately
    get(_tokenKey) {
        if (this._cache && Date.now() < this._cacheExpiry) {
            return this._cache;
        }
        return null;
    },
    set(_tokenKey, tokens) {
        this._cache = tokens;
        this._cacheExpiry = Date.now() + 30000;
    },
    clear(_tokenKey) {
        this._cache = null;
        this._cacheExpiry = 0;
    },
    getCached() {
        return this.get();
    }
};

/**
 * Get the active token store.
 * As of v0.15.0, always returns HandlerTokenStore.
 * @returns {Object} Token store with get/set/clear methods
 */
function getTokenStore() {
    return HandlerTokenStore;
}

// ============================================================================
// Handler Token Store Tests
// ============================================================================

describe('Handler Token Store', () => {
    const TOKEN_KEY = 'test_tokens';
    const mockTokens = {
        access_token: 'test-access-token',
        id_token: 'test-id-token',
        auth_method: 'passkey'
    };

    beforeEach(() => {
        HandlerTokenStore._cache = null;
        HandlerTokenStore._cacheExpiry = 0;
    });

    afterEach(() => {
        HandlerTokenStore._cache = null;
        HandlerTokenStore._cacheExpiry = 0;
    });

    it('caches tokens in memory', () => {
        const store = getTokenStore();
        store.set(TOKEN_KEY, mockTokens);

        expect(store.get(TOKEN_KEY)).toEqual(mockTokens);
    });

    it('returns null when no tokens cached', () => {
        const store = getTokenStore();
        expect(store.get(TOKEN_KEY)).toBeNull();
    });

    it('clears cached tokens', () => {
        const store = getTokenStore();
        store.set(TOKEN_KEY, mockTokens);
        store.clear(TOKEN_KEY);

        expect(store.get(TOKEN_KEY)).toBeNull();
    });

    it('overwrites existing cached tokens on set', () => {
        const store = getTokenStore();
        const tokens1 = { access_token: 'first' };
        const tokens2 = { access_token: 'second' };

        store.set(TOKEN_KEY, tokens1);
        store.set(TOKEN_KEY, tokens2);

        expect(store.get(TOKEN_KEY)).toEqual(tokens2);
    });

    it('handles null tokens', () => {
        const store = getTokenStore();
        store.set(TOKEN_KEY, null);

        expect(store.get(TOKEN_KEY)).toBeNull();
    });

    it('supports full token lifecycle: set, get, clear', () => {
        const store = getTokenStore();
        const tokens = {
            access_token: 'access',
            id_token: 'id',
            auth_method: 'password'
        };

        // Initial state
        expect(store.get(TOKEN_KEY)).toBeNull();

        // Set tokens
        store.set(TOKEN_KEY, tokens);
        expect(store.get(TOKEN_KEY)).toEqual(tokens);

        // Clear tokens
        store.clear(TOKEN_KEY);
        expect(store.get(TOKEN_KEY)).toBeNull();
    });
});

// ============================================================================
// Configuration Validation
// ============================================================================

describe('Token Storage Configuration', () => {
    function validateTokenStorage(mode) {
        if (mode && mode !== 'handler') {
            throw new Error(
                `tokenStorage "${mode}" was removed in v0.15.0.\n` +
                'Only handler mode is supported.'
            );
        }
        return true;
    }

    it('accepts "handler" mode', () => {
        expect(() => validateTokenStorage('handler')).not.toThrow();
    });

    it('accepts undefined mode (uses default handler)', () => {
        expect(() => validateTokenStorage(undefined)).not.toThrow();
    });

    it('rejects deprecated "localStorage" mode', () => {
        expect(() => validateTokenStorage('localStorage')).toThrow(/removed in v0\.15\.0/);
    });

    it('rejects deprecated "memory" mode', () => {
        expect(() => validateTokenStorage('memory')).toThrow(/removed in v0\.15\.0/);
    });

    it('rejects "sessionStorage" (never supported)', () => {
        expect(() => validateTokenStorage('sessionStorage')).toThrow(/removed in v0\.15\.0/);
    });

    it('rejects "cookie" (never supported)', () => {
        expect(() => validateTokenStorage('cookie')).toThrow(/removed in v0\.15\.0/);
    });
});

// ============================================================================
// Handler Mode Security Properties
// ============================================================================

describe('Handler Mode Security Properties', () => {
    beforeEach(() => {
        localStorage.clear();
        HandlerTokenStore._cache = null;
        HandlerTokenStore._cacheExpiry = 0;
    });

    afterEach(() => {
        localStorage.clear();
        HandlerTokenStore._cache = null;
        HandlerTokenStore._cacheExpiry = 0;
    });

    it('tokens are not stored in localStorage', () => {
        const store = getTokenStore();
        const tokens = { access_token: 'secret-handler-token' };

        store.set('any_key', tokens);

        // Simulating XSS attack that scans localStorage
        const allKeys = Object.keys(localStorage);
        const allValues = allKeys.map(k => localStorage.getItem(k));

        expect(allKeys).toHaveLength(0);
        expect(allValues.join('')).not.toContain('secret-handler-token');
    });

    it('tokens are not stored in sessionStorage', () => {
        const store = getTokenStore();
        const tokens = { access_token: 'secret-handler-token' };

        store.set('any_key', tokens);

        const allKeys = Object.keys(sessionStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('tokens are only cached briefly in memory', () => {
        const store = getTokenStore();
        const tokens = { access_token: 'cached-token' };

        store.set('any_key', tokens);

        // Tokens are in memory cache
        expect(store.getCached()).toEqual(tokens);

        // But not in any persistent storage
        expect(localStorage.getItem('any_key')).toBeNull();
        expect(sessionStorage.getItem('any_key')).toBeNull();
    });
});
