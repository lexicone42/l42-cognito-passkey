/**
 * L42 Cognito Passkey - Token Storage Tests
 *
 * Tests for token storage abstraction including:
 * - localStorage mode (default)
 * - memory mode (v0.7.0)
 * - Configuration validation
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// Token Storage Abstraction
// ============================================================================

/**
 * LocalStorage-based token store (default).
 * Tokens persist across page reloads but are accessible to XSS.
 */
const LocalStorageTokenStore = {
    get(tokenKey) {
        try {
            return JSON.parse(localStorage.getItem(tokenKey));
        } catch {
            return null;
        }
    },
    set(tokenKey, tokens) {
        localStorage.setItem(tokenKey, JSON.stringify(tokens));
    },
    clear(tokenKey) {
        localStorage.removeItem(tokenKey);
    }
};

/**
 * Memory-based token store.
 * Tokens are lost on page reload but not accessible via storage APIs.
 */
const MemoryTokenStore = {
    _tokens: null,
    get(_tokenKey) {
        return this._tokens;
    },
    set(_tokenKey, tokens) {
        this._tokens = tokens;
    },
    clear(_tokenKey) {
        this._tokens = null;
    }
};

/**
 * Handler-based token store (v0.8.0).
 * Simplified version for testing - returns sync values.
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
 * Get the active token store based on configuration.
 * @param {string} mode - 'localStorage', 'memory', or 'handler'
 * @returns {Object} Token store with get/set/clear methods
 */
function getTokenStore(mode) {
    switch (mode) {
        case 'memory':
            return MemoryTokenStore;
        case 'handler':
            return HandlerTokenStore;
        case 'localStorage':
        default:
            return LocalStorageTokenStore;
    }
}

// ============================================================================
// localStorage Mode Tests (Default Behavior)
// ============================================================================

describe('LocalStorage Token Store', () => {
    const TOKEN_KEY = 'test_tokens';
    const mockTokens = {
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        id_token: 'test-id-token',
        auth_method: 'password',
        expires_at: Date.now() + 3600000
    };

    beforeEach(() => {
        localStorage.clear();
    });

    afterEach(() => {
        localStorage.clear();
    });

    it('stores tokens in localStorage', () => {
        const store = getTokenStore('localStorage');
        store.set(TOKEN_KEY, mockTokens);

        const stored = localStorage.getItem(TOKEN_KEY);
        expect(stored).toBeTruthy();
        expect(JSON.parse(stored)).toEqual(mockTokens);
    });

    it('retrieves tokens from localStorage', () => {
        localStorage.setItem(TOKEN_KEY, JSON.stringify(mockTokens));

        const store = getTokenStore('localStorage');
        const retrieved = store.get(TOKEN_KEY);

        expect(retrieved).toEqual(mockTokens);
    });

    it('returns null for missing tokens', () => {
        const store = getTokenStore('localStorage');
        const retrieved = store.get(TOKEN_KEY);

        expect(retrieved).toBeNull();
    });

    it('returns null for invalid JSON', () => {
        localStorage.setItem(TOKEN_KEY, 'not valid json');

        const store = getTokenStore('localStorage');
        const retrieved = store.get(TOKEN_KEY);

        expect(retrieved).toBeNull();
    });

    it('clears tokens from localStorage', () => {
        localStorage.setItem(TOKEN_KEY, JSON.stringify(mockTokens));

        const store = getTokenStore('localStorage');
        store.clear(TOKEN_KEY);

        expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    });

    it('persists tokens across store instances', () => {
        const store1 = getTokenStore('localStorage');
        store1.set(TOKEN_KEY, mockTokens);

        const store2 = getTokenStore('localStorage');
        const retrieved = store2.get(TOKEN_KEY);

        expect(retrieved).toEqual(mockTokens);
    });
});

// ============================================================================
// Memory Mode Tests (v0.7.0)
// ============================================================================

describe('Memory Token Store', () => {
    const TOKEN_KEY = 'test_tokens';
    const mockTokens = {
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        id_token: 'test-id-token',
        auth_method: 'passkey',
        expires_at: Date.now() + 3600000
    };

    beforeEach(() => {
        // Reset memory store between tests
        MemoryTokenStore._tokens = null;
    });

    it('stores tokens in memory', () => {
        const store = getTokenStore('memory');
        store.set(TOKEN_KEY, mockTokens);

        expect(store._tokens).toEqual(mockTokens);
    });

    it('retrieves tokens from memory', () => {
        const store = getTokenStore('memory');
        store.set(TOKEN_KEY, mockTokens);

        const retrieved = store.get(TOKEN_KEY);

        expect(retrieved).toEqual(mockTokens);
    });

    it('returns null for missing tokens', () => {
        const store = getTokenStore('memory');
        const retrieved = store.get(TOKEN_KEY);

        expect(retrieved).toBeNull();
    });

    it('clears tokens from memory', () => {
        const store = getTokenStore('memory');
        store.set(TOKEN_KEY, mockTokens);
        store.clear(TOKEN_KEY);

        expect(store.get(TOKEN_KEY)).toBeNull();
    });

    it('does NOT persist to localStorage', () => {
        const store = getTokenStore('memory');
        store.set(TOKEN_KEY, mockTokens);

        expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    });

    it('ignores tokenKey parameter (single memory slot)', () => {
        const store = getTokenStore('memory');

        store.set('key1', mockTokens);
        const retrieved = store.get('key2'); // Different key

        // Memory store uses single slot, ignores key
        expect(retrieved).toEqual(mockTokens);
    });

    it('shares state within same store reference', () => {
        const store = getTokenStore('memory');
        store.set(TOKEN_KEY, mockTokens);

        // Same reference, should see the tokens
        const retrieved = store.get(TOKEN_KEY);
        expect(retrieved).toEqual(mockTokens);
    });
});

// ============================================================================
// Token Store Selection
// ============================================================================

describe('Token Store Selection', () => {
    beforeEach(() => {
        localStorage.clear();
        MemoryTokenStore._tokens = null;
        HandlerTokenStore._cache = null;
        HandlerTokenStore._cacheExpiry = 0;
    });

    afterEach(() => {
        localStorage.clear();
        MemoryTokenStore._tokens = null;
        HandlerTokenStore._cache = null;
        HandlerTokenStore._cacheExpiry = 0;
    });

    it('returns LocalStorageTokenStore for "localStorage" mode', () => {
        const store = getTokenStore('localStorage');
        expect(store).toBe(LocalStorageTokenStore);
    });

    it('returns MemoryTokenStore for "memory" mode', () => {
        const store = getTokenStore('memory');
        expect(store).toBe(MemoryTokenStore);
    });

    it('returns HandlerTokenStore for "handler" mode', () => {
        const store = getTokenStore('handler');
        expect(store).toBe(HandlerTokenStore);
    });

    it('returns LocalStorageTokenStore for undefined mode (default)', () => {
        const store = getTokenStore(undefined);
        expect(store).toBe(LocalStorageTokenStore);
    });

    it('returns LocalStorageTokenStore for unknown mode (fallback)', () => {
        const store = getTokenStore('unknown');
        expect(store).toBe(LocalStorageTokenStore);
    });

    it('stores are isolated from each other', () => {
        const TOKEN_KEY = 'test_tokens';
        const localTokens = { access_token: 'local' };
        const memoryTokens = { access_token: 'memory' };
        const handlerTokens = { access_token: 'handler' };

        const localStore = getTokenStore('localStorage');
        const memoryStore = getTokenStore('memory');
        const handlerStore = getTokenStore('handler');

        localStore.set(TOKEN_KEY, localTokens);
        memoryStore.set(TOKEN_KEY, memoryTokens);
        handlerStore.set(TOKEN_KEY, handlerTokens);

        expect(localStore.get(TOKEN_KEY)).toEqual(localTokens);
        expect(memoryStore.get(TOKEN_KEY)).toEqual(memoryTokens);
        expect(handlerStore.get(TOKEN_KEY)).toEqual(handlerTokens);
    });
});

// ============================================================================
// Configuration Validation
// ============================================================================

describe('Token Storage Configuration', () => {
    const validStorageModes = ['localStorage', 'memory', 'handler'];

    function validateTokenStorage(mode) {
        if (mode && !validStorageModes.includes(mode)) {
            throw new Error(
                `Invalid tokenStorage: '${mode}'.\n` +
                `Valid options: ${validStorageModes.join(', ')}`
            );
        }
        return true;
    }

    it('accepts "localStorage" mode', () => {
        expect(() => validateTokenStorage('localStorage')).not.toThrow();
    });

    it('accepts "memory" mode', () => {
        expect(() => validateTokenStorage('memory')).not.toThrow();
    });

    it('accepts "handler" mode', () => {
        expect(() => validateTokenStorage('handler')).not.toThrow();
    });

    it('accepts undefined mode (uses default)', () => {
        expect(() => validateTokenStorage(undefined)).not.toThrow();
    });

    it('rejects invalid mode with descriptive error', () => {
        expect(() => validateTokenStorage('invalid')).toThrow(
            /Invalid tokenStorage.*'invalid'/
        );
        expect(() => validateTokenStorage('invalid')).toThrow(
            /Valid options.*localStorage.*memory.*handler/
        );
    });

    it('rejects "sessionStorage" (not supported)', () => {
        expect(() => validateTokenStorage('sessionStorage')).toThrow();
    });

    it('rejects "cookie" (not supported)', () => {
        expect(() => validateTokenStorage('cookie')).toThrow();
    });
});

// ============================================================================
// Security Properties
// ============================================================================

describe('Memory Mode Security Properties', () => {
    beforeEach(() => {
        localStorage.clear();
        MemoryTokenStore._tokens = null;
    });

    afterEach(() => {
        localStorage.clear();
        MemoryTokenStore._tokens = null;
    });

    it('memory tokens are not accessible via localStorage API', () => {
        const store = getTokenStore('memory');
        const tokens = { access_token: 'secret-token' };

        store.set('any_key', tokens);

        // Simulating XSS attack that scans localStorage
        const allKeys = Object.keys(localStorage);
        const allValues = allKeys.map(k => localStorage.getItem(k));

        expect(allKeys).not.toContain('any_key');
        expect(allValues.join('')).not.toContain('secret-token');
    });

    it('memory tokens are not in sessionStorage', () => {
        const store = getTokenStore('memory');
        const tokens = { access_token: 'secret-token' };

        store.set('any_key', tokens);

        const allKeys = Object.keys(sessionStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('localStorage tokens ARE accessible via localStorage API', () => {
        const store = getTokenStore('localStorage');
        const tokens = { access_token: 'exposed-token' };
        const TOKEN_KEY = 'l42_auth_tokens';

        store.set(TOKEN_KEY, tokens);

        // This is the XSS risk we're documenting
        const storedValue = localStorage.getItem(TOKEN_KEY);
        expect(storedValue).toContain('exposed-token');
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

    it('handler tokens are not stored in localStorage', () => {
        const store = getTokenStore('handler');
        const tokens = { access_token: 'secret-handler-token' };

        store.set('any_key', tokens);

        // Simulating XSS attack that scans localStorage
        const allKeys = Object.keys(localStorage);
        const allValues = allKeys.map(k => localStorage.getItem(k));

        expect(allKeys).toHaveLength(0);
        expect(allValues.join('')).not.toContain('secret-handler-token');
    });

    it('handler tokens are not stored in sessionStorage', () => {
        const store = getTokenStore('handler');
        const tokens = { access_token: 'secret-handler-token' };

        store.set('any_key', tokens);

        const allKeys = Object.keys(sessionStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('handler mode only caches tokens briefly in memory', () => {
        const store = getTokenStore('handler');
        const tokens = { access_token: 'cached-token' };

        store.set('any_key', tokens);

        // Tokens are in memory cache
        expect(store.getCached()).toEqual(tokens);

        // But not in any persistent storage
        expect(localStorage.getItem('any_key')).toBeNull();
        expect(sessionStorage.getItem('any_key')).toBeNull();
    });
});

// ============================================================================
// Token Lifecycle
// ============================================================================

describe('Token Lifecycle', () => {
    const TOKEN_KEY = 'test_tokens';

    beforeEach(() => {
        localStorage.clear();
        MemoryTokenStore._tokens = null;
        HandlerTokenStore._cache = null;
        HandlerTokenStore._cacheExpiry = 0;
    });

    afterEach(() => {
        localStorage.clear();
        MemoryTokenStore._tokens = null;
        HandlerTokenStore._cache = null;
        HandlerTokenStore._cacheExpiry = 0;
    });

    describe.each(['localStorage', 'memory', 'handler'])('%s mode', (mode) => {
        it('supports full token lifecycle: set, get, clear', () => {
            const store = getTokenStore(mode);
            const tokens = {
                access_token: 'access',
                refresh_token: 'refresh',
                id_token: 'id',
                expires_at: Date.now() + 3600000
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

        it('overwrites existing tokens on set', () => {
            const store = getTokenStore(mode);
            const tokens1 = { access_token: 'first' };
            const tokens2 = { access_token: 'second' };

            store.set(TOKEN_KEY, tokens1);
            store.set(TOKEN_KEY, tokens2);

            expect(store.get(TOKEN_KEY)).toEqual(tokens2);
        });

        it('handles null tokens', () => {
            const store = getTokenStore(mode);

            store.set(TOKEN_KEY, null);

            // Both stores should handle null gracefully
            const retrieved = store.get(TOKEN_KEY);
            expect(retrieved).toBeNull();
        });
    });
});
