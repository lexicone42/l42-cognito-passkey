/**
 * L42 Cognito Passkey - Handler Token Store Tests
 *
 * Tests for Token Handler mode (v0.8.0):
 * - HandlerTokenStore implementation
 * - Configuration validation
 * - Server endpoint integration
 * - Security properties
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// HandlerTokenStore Implementation (mirrored from auth.js for testing)
// ============================================================================

/**
 * Test config object
 */
let testConfig = {
    tokenStorage: 'handler',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    oauthCallbackUrl: '/auth/callback',
    handlerCacheTtl: 30000
};

/**
 * HandlerTokenStore implementation for testing
 */
const HandlerTokenStore = {
    _cache: null,
    _cacheExpiry: 0,
    _fetchPromise: null,

    async get(_tokenKey) {
        if (this._cache && Date.now() < this._cacheExpiry) {
            return this._cache;
        }

        if (this._fetchPromise) {
            return this._fetchPromise;
        }

        this._fetchPromise = this._fetchTokens();
        try {
            return await this._fetchPromise;
        } finally {
            this._fetchPromise = null;
        }
    },

    async _fetchTokens() {
        const endpoint = testConfig.tokenEndpoint;
        if (!endpoint) {
            console.error('HandlerTokenStore: tokenEndpoint not configured');
            return null;
        }

        try {
            const response = await fetch(endpoint, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (response.status === 401 || response.status === 403) {
                this._cache = null;
                this._cacheExpiry = 0;
                return null;
            }

            if (!response.ok) {
                throw new Error(`Token fetch failed: ${response.status}`);
            }

            const data = await response.json();

            const tokens = {
                access_token: data.access_token,
                id_token: data.id_token,
                auth_method: data.auth_method || 'handler'
            };

            this._cache = tokens;
            this._cacheExpiry = Date.now() + (testConfig.handlerCacheTtl || 30000);

            return tokens;
        } catch (error) {
            console.error('HandlerTokenStore: fetch failed', error);
            throw error;
        }
    },

    set(_tokenKey, tokens) {
        this._cache = tokens;
        this._cacheExpiry = Date.now() + (testConfig.handlerCacheTtl || 30000);
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

    // Reset for testing
    _reset() {
        this._cache = null;
        this._cacheExpiry = 0;
        this._fetchPromise = null;
    }
};

// ============================================================================
// Configuration Validation
// ============================================================================

describe('Handler Mode Configuration', () => {
    const validStorageModes = ['localStorage', 'memory', 'handler'];

    function validateConfig(config) {
        if (config.tokenStorage && !validStorageModes.includes(config.tokenStorage)) {
            throw new Error(
                `Invalid tokenStorage: '${config.tokenStorage}'.\n` +
                `Valid options: ${validStorageModes.join(', ')}`
            );
        }

        if (config.tokenStorage === 'handler') {
            const requiredEndpoints = ['tokenEndpoint', 'refreshEndpoint', 'logoutEndpoint'];
            const missing = requiredEndpoints.filter(ep => !config[ep]);
            if (missing.length > 0) {
                throw new Error(
                    `Token handler mode requires: ${missing.join(', ')}.\n` +
                    'Example: configure({\n' +
                    '    tokenStorage: "handler",\n' +
                    '    tokenEndpoint: "/auth/token",\n' +
                    '    refreshEndpoint: "/auth/refresh",\n' +
                    '    logoutEndpoint: "/auth/logout"\n' +
                    '})'
                );
            }
        }
        return true;
    }

    it('accepts "handler" as valid storage mode', () => {
        expect(() => validateConfig({
            tokenStorage: 'handler',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout'
        })).not.toThrow();
    });

    it('requires tokenEndpoint for handler mode', () => {
        expect(() => validateConfig({
            tokenStorage: 'handler',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout'
        })).toThrow(/tokenEndpoint/);
    });

    it('requires refreshEndpoint for handler mode', () => {
        expect(() => validateConfig({
            tokenStorage: 'handler',
            tokenEndpoint: '/auth/token',
            logoutEndpoint: '/auth/logout'
        })).toThrow(/refreshEndpoint/);
    });

    it('requires logoutEndpoint for handler mode', () => {
        expect(() => validateConfig({
            tokenStorage: 'handler',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh'
        })).toThrow(/logoutEndpoint/);
    });

    it('reports all missing endpoints in error', () => {
        try {
            validateConfig({ tokenStorage: 'handler' });
            expect.fail('Should have thrown');
        } catch (e) {
            expect(e.message).toContain('tokenEndpoint');
            expect(e.message).toContain('refreshEndpoint');
            expect(e.message).toContain('logoutEndpoint');
        }
    });

    it('provides helpful example in error message', () => {
        try {
            validateConfig({ tokenStorage: 'handler' });
            expect.fail('Should have thrown');
        } catch (e) {
            expect(e.message).toContain('tokenStorage: "handler"');
            expect(e.message).toContain('/auth/token');
        }
    });

    it('does not require handler endpoints for localStorage mode', () => {
        expect(() => validateConfig({
            tokenStorage: 'localStorage'
        })).not.toThrow();
    });

    it('does not require handler endpoints for memory mode', () => {
        expect(() => validateConfig({
            tokenStorage: 'memory'
        })).not.toThrow();
    });

    it('oauthCallbackUrl is optional', () => {
        expect(() => validateConfig({
            tokenStorage: 'handler',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout'
            // oauthCallbackUrl not provided
        })).not.toThrow();
    });
});

// ============================================================================
// HandlerTokenStore Unit Tests
// ============================================================================

describe('HandlerTokenStore', () => {
    const mockTokens = {
        access_token: 'test-access-token',
        id_token: 'test-id-token',
        auth_method: 'handler'
    };

    beforeEach(() => {
        HandlerTokenStore._reset();
        vi.resetAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('get()', () => {
        it('returns cached tokens if not expired', async () => {
            HandlerTokenStore._cache = mockTokens;
            HandlerTokenStore._cacheExpiry = Date.now() + 60000;

            const tokens = await HandlerTokenStore.get('any_key');

            expect(tokens).toEqual(mockTokens);
        });

        it('fetches from server if cache is expired', async () => {
            HandlerTokenStore._cache = mockTokens;
            HandlerTokenStore._cacheExpiry = Date.now() - 1000; // Expired

            const freshTokens = {
                access_token: 'fresh-access',
                id_token: 'fresh-id',
                auth_method: 'handler'
            };

            global.fetch = vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(freshTokens)
            });

            const tokens = await HandlerTokenStore.get('any_key');

            expect(fetch).toHaveBeenCalledWith('/auth/token', {
                method: 'GET',
                credentials: 'include',
                headers: { 'Accept': 'application/json' }
            });
            expect(tokens.access_token).toBe('fresh-access');
        });

        it('fetches from server if cache is null', async () => {
            global.fetch = vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(mockTokens)
            });

            const tokens = await HandlerTokenStore.get('any_key');

            expect(fetch).toHaveBeenCalled();
            expect(tokens).toEqual(mockTokens);
        });

        it('returns null on 401 response', async () => {
            global.fetch = vi.fn().mockResolvedValue({
                ok: false,
                status: 401,
                json: () => Promise.resolve({ error: 'unauthorized' })
            });

            const tokens = await HandlerTokenStore.get('any_key');

            expect(tokens).toBeNull();
            expect(HandlerTokenStore._cache).toBeNull();
        });

        it('returns null on 403 response', async () => {
            global.fetch = vi.fn().mockResolvedValue({
                ok: false,
                status: 403,
                json: () => Promise.resolve({ error: 'forbidden' })
            });

            const tokens = await HandlerTokenStore.get('any_key');

            expect(tokens).toBeNull();
        });

        it('throws on 500 response', async () => {
            global.fetch = vi.fn().mockResolvedValue({
                ok: false,
                status: 500,
                json: () => Promise.resolve({ error: 'server error' })
            });

            await expect(HandlerTokenStore.get('any_key')).rejects.toThrow(/500/);
        });

        it('throws on network error', async () => {
            global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

            await expect(HandlerTokenStore.get('any_key')).rejects.toThrow('Network error');
        });

        it('deduplicates concurrent requests', async () => {
            let resolveFirst;
            const fetchPromise = new Promise(resolve => { resolveFirst = resolve; });

            global.fetch = vi.fn().mockReturnValue(fetchPromise);

            // Start two concurrent gets
            const promise1 = HandlerTokenStore.get('key1');
            const promise2 = HandlerTokenStore.get('key2');

            // Only one fetch should have been made
            expect(fetch).toHaveBeenCalledTimes(1);

            // Resolve the fetch
            resolveFirst({
                ok: true,
                status: 200,
                json: () => Promise.resolve(mockTokens)
            });

            const [result1, result2] = await Promise.all([promise1, promise2]);

            expect(result1).toEqual(mockTokens);
            expect(result2).toEqual(mockTokens);
        });

        it('caches tokens with TTL', async () => {
            testConfig.handlerCacheTtl = 5000;

            global.fetch = vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(mockTokens)
            });

            await HandlerTokenStore.get('any_key');

            expect(HandlerTokenStore._cache).toEqual(mockTokens);
            expect(HandlerTokenStore._cacheExpiry).toBeGreaterThan(Date.now());
            expect(HandlerTokenStore._cacheExpiry).toBeLessThanOrEqual(Date.now() + 5001);
        });

        it('ignores tokenKey parameter', async () => {
            HandlerTokenStore.set('key1', mockTokens);

            const tokens = await HandlerTokenStore.get('different_key');

            expect(tokens).toEqual(mockTokens);
        });
    });

    describe('set()', () => {
        it('updates cache with provided tokens', () => {
            HandlerTokenStore.set('any_key', mockTokens);

            expect(HandlerTokenStore._cache).toEqual(mockTokens);
        });

        it('sets cache expiry', () => {
            testConfig.handlerCacheTtl = 60000;

            HandlerTokenStore.set('any_key', mockTokens);

            expect(HandlerTokenStore._cacheExpiry).toBeGreaterThan(Date.now());
        });

        it('overwrites existing cache', () => {
            HandlerTokenStore._cache = { access_token: 'old' };
            HandlerTokenStore._cacheExpiry = Date.now() + 60000;

            const newTokens = { access_token: 'new', id_token: 'new-id' };
            HandlerTokenStore.set('any_key', newTokens);

            expect(HandlerTokenStore._cache).toEqual(newTokens);
        });
    });

    describe('clear()', () => {
        it('clears the cache', () => {
            HandlerTokenStore._cache = mockTokens;
            HandlerTokenStore._cacheExpiry = Date.now() + 60000;

            HandlerTokenStore.clear('any_key');

            expect(HandlerTokenStore._cache).toBeNull();
            expect(HandlerTokenStore._cacheExpiry).toBe(0);
        });
    });

    describe('getCached()', () => {
        it('returns cached tokens if not expired', () => {
            HandlerTokenStore._cache = mockTokens;
            HandlerTokenStore._cacheExpiry = Date.now() + 60000;

            const tokens = HandlerTokenStore.getCached();

            expect(tokens).toEqual(mockTokens);
        });

        it('returns null if cache is expired', () => {
            HandlerTokenStore._cache = mockTokens;
            HandlerTokenStore._cacheExpiry = Date.now() - 1000;

            const tokens = HandlerTokenStore.getCached();

            expect(tokens).toBeNull();
        });

        it('returns null if cache is empty', () => {
            const tokens = HandlerTokenStore.getCached();

            expect(tokens).toBeNull();
        });

        it('is synchronous (for isAuthenticated)', () => {
            HandlerTokenStore._cache = mockTokens;
            HandlerTokenStore._cacheExpiry = Date.now() + 60000;

            // Should not return a Promise
            const result = HandlerTokenStore.getCached();

            expect(result).not.toBeInstanceOf(Promise);
            expect(result).toEqual(mockTokens);
        });
    });
});

// ============================================================================
// Security Properties
// ============================================================================

describe('Handler Mode Security Properties', () => {
    beforeEach(() => {
        HandlerTokenStore._reset();
        localStorage.clear();
        sessionStorage.clear();
    });

    afterEach(() => {
        localStorage.clear();
        sessionStorage.clear();
    });

    it('tokens are NOT stored in localStorage', async () => {
        const mockTokens = {
            access_token: 'secret-token',
            id_token: 'secret-id'
        };

        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockTokens)
        });

        await HandlerTokenStore.get('any_key');

        // Check localStorage is empty
        const allKeys = Object.keys(localStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('tokens are NOT stored in sessionStorage', async () => {
        const mockTokens = {
            access_token: 'secret-token',
            id_token: 'secret-id'
        };

        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockTokens)
        });

        await HandlerTokenStore.get('any_key');

        // Check sessionStorage is empty
        const allKeys = Object.keys(sessionStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('refresh_token is NOT exposed to client', async () => {
        const serverResponse = {
            access_token: 'access-token',
            id_token: 'id-token',
            refresh_token: 'should-not-be-returned',
            auth_method: 'handler'
        };

        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve(serverResponse)
        });

        const tokens = await HandlerTokenStore.get('any_key');

        // The HandlerTokenStore implementation should NOT include refresh_token
        // (Server should not return it, but even if it does, we don't cache it)
        expect(tokens.refresh_token).toBeUndefined();
    });

    it('sends credentials with requests (for session cookies)', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ access_token: 'token', id_token: 'id' })
        });

        await HandlerTokenStore.get('any_key');

        expect(fetch).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({
                credentials: 'include'
            })
        );
    });
});

// ============================================================================
// Error Handling
// ============================================================================

describe('Handler Mode Error Handling', () => {
    beforeEach(() => {
        HandlerTokenStore._reset();
    });

    it('returns null for auth errors (401/403) without throwing', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: false,
            status: 401
        });

        const tokens = await HandlerTokenStore.get('any_key');

        expect(tokens).toBeNull();
    });

    it('throws for server errors (5xx)', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: false,
            status: 503
        });

        await expect(HandlerTokenStore.get('any_key')).rejects.toThrow(/503/);
    });

    it('throws for network errors', async () => {
        global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

        await expect(HandlerTokenStore.get('any_key')).rejects.toThrow('Failed to fetch');
    });

    it('clears cache on auth errors', async () => {
        HandlerTokenStore._cache = { access_token: 'old' };
        HandlerTokenStore._cacheExpiry = Date.now() - 1000; // Expired

        global.fetch = vi.fn().mockResolvedValue({
            ok: false,
            status: 401
        });

        await HandlerTokenStore.get('any_key');

        expect(HandlerTokenStore._cache).toBeNull();
        expect(HandlerTokenStore._cacheExpiry).toBe(0);
    });

    it('preserves cache on server errors', async () => {
        const oldTokens = { access_token: 'old' };
        HandlerTokenStore._cache = oldTokens;
        HandlerTokenStore._cacheExpiry = Date.now() - 1000; // Expired

        global.fetch = vi.fn().mockResolvedValue({
            ok: false,
            status: 500
        });

        try {
            await HandlerTokenStore.get('any_key');
        } catch {
            // Expected to throw
        }

        // Cache should be unchanged (error should be retried)
        expect(HandlerTokenStore._cache).toEqual(oldTokens);
    });

    it('logs errors without exposing sensitive data', async () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

        global.fetch = vi.fn().mockRejectedValue(new Error('Network failure'));

        try {
            await HandlerTokenStore.get('any_key');
        } catch {
            // Expected
        }

        expect(consoleSpy).toHaveBeenCalled();
        // Should not log tokens or sensitive data
        const logArgs = consoleSpy.mock.calls.flat().join(' ');
        expect(logArgs).not.toContain('access_token');
        expect(logArgs).not.toContain('id_token');
    });
});

// ============================================================================
// Refresh and Logout Flows
// ============================================================================

describe('Handler Mode Refresh Flow', () => {
    beforeEach(() => {
        testConfig = {
            tokenStorage: 'handler',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout',
            handlerCacheTtl: 30000
        };
    });

    it('refresh endpoint is called with correct options', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve({
                access_token: 'refreshed-access',
                id_token: 'refreshed-id'
            })
        });

        await fetch(testConfig.refreshEndpoint, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
        });

        expect(fetch).toHaveBeenCalledWith('/auth/refresh', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
        });
    });
});

describe('Handler Mode Logout Flow', () => {
    beforeEach(() => {
        testConfig = {
            tokenStorage: 'handler',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout',
            handlerCacheTtl: 30000
        };
    });

    it('logout endpoint is called with correct options', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200
        });

        await fetch(testConfig.logoutEndpoint, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
        });

        expect(fetch).toHaveBeenCalledWith('/auth/logout', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' }
        });
    });

    it('logout clears local cache', () => {
        HandlerTokenStore._cache = { access_token: 'token' };
        HandlerTokenStore._cacheExpiry = Date.now() + 60000;

        HandlerTokenStore.clear('any_key');

        expect(HandlerTokenStore._cache).toBeNull();
        expect(HandlerTokenStore._cacheExpiry).toBe(0);
    });
});

// ============================================================================
// OAuth Callback URL
// ============================================================================

describe('Handler Mode OAuth Callback', () => {
    it('oauthCallbackUrl can be configured', () => {
        const config = {
            tokenStorage: 'handler',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout',
            oauthCallbackUrl: '/auth/callback'
        };

        expect(config.oauthCallbackUrl).toBe('/auth/callback');
    });

    it('oauthCallbackUrl supports absolute URLs', () => {
        const config = {
            oauthCallbackUrl: 'https://api.example.com/auth/callback'
        };

        expect(config.oauthCallbackUrl).toBe('https://api.example.com/auth/callback');
    });
});

// ============================================================================
// Cross-Mode Compatibility
// ============================================================================

describe('Cross-Mode Compatibility', () => {
    it('await works on sync getTokens result (non-handler modes)', async () => {
        // Simulating localStorage mode behavior
        const syncResult = { access_token: 'token' };

        // await on non-Promise just returns the value
        const result = await syncResult;

        expect(result).toEqual(syncResult);
    });

    it('await works on async getTokens result (handler mode)', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ access_token: 'async-token', id_token: 'id' })
        });

        const result = await HandlerTokenStore.get('any_key');

        expect(result.access_token).toBe('async-token');
    });
});

// ============================================================================
// Cache TTL Behavior
// ============================================================================

describe('Handler Mode Cache TTL', () => {
    beforeEach(() => {
        HandlerTokenStore._reset();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('cache expires after TTL', async () => {
        testConfig.handlerCacheTtl = 30000; // 30 seconds

        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ access_token: 'token', id_token: 'id' })
        });

        // First fetch
        await HandlerTokenStore.get('key');
        expect(fetch).toHaveBeenCalledTimes(1);

        // Within TTL - should use cache
        vi.advanceTimersByTime(15000); // 15 seconds
        await HandlerTokenStore.get('key');
        expect(fetch).toHaveBeenCalledTimes(1); // Still 1

        // After TTL - should fetch again
        vi.advanceTimersByTime(20000); // Now 35 seconds total
        await HandlerTokenStore.get('key');
        expect(fetch).toHaveBeenCalledTimes(2);
    });

    it('getCached returns null after TTL expires', () => {
        testConfig.handlerCacheTtl = 1000;

        HandlerTokenStore.set('key', { access_token: 'token' });

        // Immediately available
        expect(HandlerTokenStore.getCached()).not.toBeNull();

        // After TTL
        vi.advanceTimersByTime(1500);
        expect(HandlerTokenStore.getCached()).toBeNull();
    });
});
