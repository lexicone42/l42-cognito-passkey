/**
 * L42 Cognito Passkey - Handler Token Store Tests
 *
 * Tests for Token Handler mode (v0.8.0):
 * - Configuration validation (REAL auth.js configure())
 * - Token storage via real setTokens/clearTokens/getTokens
 * - Server endpoint integration
 * - Security properties (real functions, no localStorage/sessionStorage leaks)
 * - Cache TTL behavior
 * - Session persistence
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    configure,
    isConfigured,
    setTokens,
    clearTokens,
    getTokens,
    isAuthenticated,
    logout,
    _resetForTesting
} from '../../src/auth.js';

// ============================================================================
// Test Helpers
// ============================================================================

/** Standard test config with all required endpoints. */
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

/** Create a properly-structured JWT for testing. */
function createTestJwt(claims) {
    const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const payload = btoa(JSON.stringify(claims))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return `${header}.${payload}.test-signature`;
}

/** Mock tokens with valid JWT structure (passes validateTokenClaims). */
function createMockTokens() {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    return {
        access_token: createTestJwt({ sub: 'user1', client_id: 'test-client', exp }),
        id_token: createTestJwt({
            sub: 'user1',
            aud: 'test-client',
            iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test',
            exp
        }),
        auth_method: 'handler'
    };
}

const mockTokens = createMockTokens();

// ============================================================================
// Configuration Validation — using REAL configure()
// ============================================================================

describe('Handler Mode Configuration', () => {
    beforeEach(() => {
        _resetForTesting();
    });

    it('accepts valid handler config with all endpoints', () => {
        expect(() => configureForTest()).not.toThrow();
        expect(isConfigured()).toBe(true);
    });

    it('requires tokenEndpoint', () => {
        expect(() => configure({
            clientId: 'test',
            cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout'
        })).toThrow(/tokenEndpoint/);
    });

    it('requires refreshEndpoint', () => {
        expect(() => configure({
            clientId: 'test',
            cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
            tokenEndpoint: '/auth/token',
            logoutEndpoint: '/auth/logout'
        })).toThrow(/refreshEndpoint/);
    });

    it('requires logoutEndpoint', () => {
        expect(() => configure({
            clientId: 'test',
            cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh'
        })).toThrow(/logoutEndpoint/);
    });

    it('reports all missing endpoints in error', () => {
        try {
            configure({
                clientId: 'test',
                cognitoDomain: 'test.auth.us-west-2.amazoncognito.com'
            });
            expect.fail('Should have thrown');
        } catch (e) {
            expect(e.message).toContain('tokenEndpoint');
            expect(e.message).toContain('refreshEndpoint');
            expect(e.message).toContain('logoutEndpoint');
        }
    });

    it('rejects deprecated localStorage mode', () => {
        expect(() => configure({
            clientId: 'test',
            cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
            tokenStorage: 'localStorage',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout'
        })).toThrow(/removed in v0\.15\.0/);
    });

    it('rejects deprecated memory mode', () => {
        expect(() => configure({
            clientId: 'test',
            cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
            tokenStorage: 'memory',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout'
        })).toThrow(/removed in v0\.15\.0/);
    });

    it('oauthCallbackUrl is optional', () => {
        expect(() => configureForTest({
            oauthCallbackUrl: undefined
        })).not.toThrow();
    });
});

// ============================================================================
// Token Store — using REAL setTokens/clearTokens/isAuthenticated
// ============================================================================

describe('HandlerTokenStore via public API', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
        vi.resetAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('setTokens + isAuthenticated', () => {
        it('isAuthenticated returns false when no tokens set', () => {
            expect(isAuthenticated()).toBe(false);
        });

        it('isAuthenticated returns true after setTokens', () => {
            setTokens(mockTokens);
            expect(isAuthenticated()).toBe(true);
        });

        it('clearTokens makes isAuthenticated return false', () => {
            setTokens(mockTokens);
            expect(isAuthenticated()).toBe(true);

            clearTokens();
            expect(isAuthenticated()).toBe(false);
        });

        it('setTokens overwrites existing tokens', () => {
            setTokens(createMockTokens());
            setTokens(createMockTokens());
            // isAuthenticated still works after overwrite
            expect(isAuthenticated()).toBe(true);
        });
    });

    describe('getTokens (async, fetch-based)', () => {
        it('returns cached tokens without fetching if recently set', async () => {
            global.fetch = vi.fn();
            setTokens(mockTokens);

            const tokens = await getTokens();

            expect(tokens).toEqual(mockTokens);
            expect(fetch).not.toHaveBeenCalled();
        });

        it('fetches from server when no cache', async () => {
            const serverTokens = {
                access_token: 'server-access',
                id_token: 'server-id',
                auth_method: 'handler'
            };

            global.fetch = vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(serverTokens)
            });

            const tokens = await getTokens();

            expect(fetch).toHaveBeenCalled();
            expect(tokens.access_token).toBe('server-access');
        });

        it('returns null on 401 response', async () => {
            global.fetch = vi.fn().mockResolvedValue({
                ok: false,
                status: 401,
                json: () => Promise.resolve({ error: 'unauthorized' })
            });

            const tokens = await getTokens();
            expect(tokens).toBeNull();
        });

        it('returns null on 403 response', async () => {
            global.fetch = vi.fn().mockResolvedValue({
                ok: false,
                status: 403,
                json: () => Promise.resolve({ error: 'forbidden' })
            });

            const tokens = await getTokens();
            expect(tokens).toBeNull();
        });

        it('throws on 500 response', async () => {
            global.fetch = vi.fn().mockResolvedValue({
                ok: false,
                status: 500,
                json: () => Promise.resolve({ error: 'server error' })
            });

            await expect(getTokens()).rejects.toThrow(/500/);
        });

        it('throws on network error', async () => {
            global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

            await expect(getTokens()).rejects.toThrow('Network error');
        });

        it('deduplicates concurrent requests', async () => {
            let resolveFirst;
            const fetchPromise = new Promise(resolve => { resolveFirst = resolve; });

            global.fetch = vi.fn().mockReturnValue(fetchPromise);

            const promise1 = getTokens();
            const promise2 = getTokens();

            // Only one fetch should have been made
            expect(fetch).toHaveBeenCalledTimes(1);

            resolveFirst({
                ok: true,
                status: 200,
                json: () => Promise.resolve(mockTokens)
            });

            const [result1, result2] = await Promise.all([promise1, promise2]);
            expect(result1).toEqual(mockTokens);
            expect(result2).toEqual(mockTokens);
        });

        it('sends credentials: include for session cookies', async () => {
            global.fetch = vi.fn().mockResolvedValue({
                ok: true,
                status: 200,
                json: () => Promise.resolve(mockTokens)
            });

            await getTokens();

            expect(fetch).toHaveBeenCalledWith(
                expect.any(String),
                expect.objectContaining({
                    credentials: 'include'
                })
            );
        });
    });
});

// ============================================================================
// Security Properties — using REAL functions
// ============================================================================

describe('Handler Mode Security Properties', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
        localStorage.clear();
        sessionStorage.clear();
    });

    afterEach(() => {
        localStorage.clear();
        sessionStorage.clear();
    });

    it('tokens are NOT stored in localStorage', () => {
        setTokens({
            access_token: 'secret-token',
            id_token: 'secret-id'
        });

        const allKeys = Object.keys(localStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('tokens are NOT stored in sessionStorage', () => {
        setTokens({
            access_token: 'secret-token',
            id_token: 'secret-id'
        });

        const allKeys = Object.keys(sessionStorage);
        expect(allKeys).toHaveLength(0);
    });

    it('refresh_token is NOT exposed to client via getTokens', async () => {
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

        const tokens = await getTokens();

        // refresh_token should NOT be in the client-side response
        expect(tokens.refresh_token).toBeUndefined();
    });

    it('isAuthenticated is synchronous (uses cache)', () => {
        setTokens(createMockTokens());

        // Should not return a Promise
        const result = isAuthenticated();
        expect(result).not.toBeInstanceOf(Promise);
        expect(result).toBe(true);
    });
});

// ============================================================================
// Error Handling — using REAL getTokens
// ============================================================================

describe('Handler Mode Error Handling', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    it('returns null for auth errors (401/403) without throwing', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: false,
            status: 401
        });

        const tokens = await getTokens();
        expect(tokens).toBeNull();
    });

    it('throws for server errors (5xx)', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: false,
            status: 503
        });

        await expect(getTokens()).rejects.toThrow(/503/);
    });

    it('throws for network errors', async () => {
        global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

        await expect(getTokens()).rejects.toThrow('Failed to fetch');
    });

    it('clears cache on auth errors', async () => {
        setTokens(createMockTokens());
        expect(isAuthenticated()).toBe(true);

        // Simulate cache expiry by clearing, then fetching returns 401
        clearTokens();
        global.fetch = vi.fn().mockResolvedValue({
            ok: false,
            status: 401
        });

        await getTokens();
        expect(isAuthenticated()).toBe(false);
    });

    it('logs errors without exposing sensitive data', async () => {
        const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

        global.fetch = vi.fn().mockRejectedValue(new Error('Network failure'));

        try {
            await getTokens();
        } catch {
            // Expected
        }

        expect(consoleSpy).toHaveBeenCalled();
        const logArgs = consoleSpy.mock.calls.flat().join(' ');
        expect(logArgs).not.toContain('access_token');
        expect(logArgs).not.toContain('id_token');
    });
});

// ============================================================================
// Logout Flow — using REAL logout()
// ============================================================================

describe('Handler Mode Logout Flow', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('logout clears local cache', async () => {
        setTokens(createMockTokens());
        expect(isAuthenticated()).toBe(true);

        global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        await logout();

        expect(isAuthenticated()).toBe(false);
    });

    it('logout calls server endpoint', async () => {
        setTokens(createMockTokens());

        global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        await logout();

        expect(fetch).toHaveBeenCalledWith(
            '/auth/logout',
            expect.objectContaining({
                method: 'POST',
                credentials: 'include'
            })
        );
    });
});

// ============================================================================
// OAuth Callback URL — config property
// ============================================================================

describe('Handler Mode OAuth Callback', () => {
    beforeEach(() => {
        _resetForTesting();
    });

    it('oauthCallbackUrl can be configured', () => {
        expect(() => configureForTest({
            oauthCallbackUrl: '/auth/callback'
        })).not.toThrow();
    });

    it('oauthCallbackUrl supports absolute URLs', () => {
        expect(() => configureForTest({
            oauthCallbackUrl: 'https://api.example.com/auth/callback'
        })).not.toThrow();
    });
});

// ============================================================================
// Cross-Mode Compatibility
// ============================================================================

describe('Cross-Mode Compatibility', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    it('await works on sync cached result', async () => {
        setTokens(mockTokens);

        // getTokens returns from cache (which is still async/Promise)
        const result = await getTokens();
        expect(result).toEqual(mockTokens);
    });

    it('await works on async server fetch result', async () => {
        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ access_token: 'async-token', id_token: 'id' })
        });

        const result = await getTokens();
        expect(result.access_token).toBe('async-token');
    });
});

// ============================================================================
// Cache TTL Behavior — using REAL functions with fake timers
// ============================================================================

describe('Handler Mode Cache TTL', () => {
    beforeEach(() => {
        _resetForTesting();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('cache expires after TTL', async () => {
        configureForTest({ handlerCacheTtl: 30000 });

        global.fetch = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ access_token: 'token', id_token: 'id' })
        });

        // First fetch
        await getTokens();
        expect(fetch).toHaveBeenCalledTimes(1);

        // Within TTL — should use cache
        vi.advanceTimersByTime(15000);
        await getTokens();
        expect(fetch).toHaveBeenCalledTimes(1);

        // After TTL — should fetch again
        vi.advanceTimersByTime(20000);
        await getTokens();
        expect(fetch).toHaveBeenCalledTimes(2);
    });

    it('isAuthenticated returns false after TTL expires without refresh', () => {
        configureForTest({ handlerCacheTtl: 1000 });

        setTokens(createMockTokens());
        expect(isAuthenticated()).toBe(true);

        vi.advanceTimersByTime(1500);
        expect(isAuthenticated()).toBe(false);
    });
});

// ============================================================================
// Session Persistence (v0.15.0) — Fix for #12
// Kept as isolated mock test since _persistHandlerSession is private.
// ============================================================================

describe('Session Persistence (_persistHandlerSession)', () => {
    /**
     * Mirrors the _persistHandlerSession function from auth.js.
     * This tests the contract, not the real function (which is private).
     * TODO: Convert once loginWithPassword/loginWithPasskey are testable.
     */
    async function _persistHandlerSession(tokens, cfg) {
        if (cfg.tokenStorage !== 'handler' || !cfg.sessionEndpoint) {
            return;
        }

        const response = await fetch(cfg.sessionEndpoint, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-L42-CSRF': '1'
            },
            body: JSON.stringify({
                access_token: tokens.access_token,
                id_token: tokens.id_token,
                refresh_token: tokens.refresh_token,
                auth_method: tokens.auth_method
            })
        });

        if (!response.ok) {
            throw new Error(`Session persist failed: ${response.status}`);
        }
    }

    beforeEach(() => {
        vi.restoreAllMocks();
        global.fetch = vi.fn();
    });

    afterEach(() => {
        delete global.fetch;
    });

    const handlerConfig = {
        tokenStorage: 'handler',
        sessionEndpoint: '/auth/session',
        tokenEndpoint: '/auth/token',
        refreshEndpoint: '/auth/refresh',
        logoutEndpoint: '/auth/logout'
    };

    const sampleTokens = {
        access_token: 'access-abc',
        id_token: 'id-xyz',
        refresh_token: 'refresh-123',
        auth_method: 'passkey'
    };

    it('POSTs tokens to sessionEndpoint in handler mode', async () => {
        global.fetch.mockResolvedValue({ ok: true, status: 200 });

        await _persistHandlerSession(sampleTokens, handlerConfig);

        expect(fetch).toHaveBeenCalledTimes(1);
        expect(fetch).toHaveBeenCalledWith('/auth/session', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-L42-CSRF': '1'
            },
            body: JSON.stringify({
                access_token: 'access-abc',
                id_token: 'id-xyz',
                refresh_token: 'refresh-123',
                auth_method: 'passkey'
            })
        });
    });

    it('sends CSRF header for cross-origin protection', async () => {
        global.fetch.mockResolvedValue({ ok: true, status: 200 });

        await _persistHandlerSession(sampleTokens, handlerConfig);

        const callHeaders = fetch.mock.calls[0][1].headers;
        expect(callHeaders['X-L42-CSRF']).toBe('1');
    });

    it('sends credentials: include for session cookies', async () => {
        global.fetch.mockResolvedValue({ ok: true, status: 200 });

        await _persistHandlerSession(sampleTokens, handlerConfig);

        expect(fetch.mock.calls[0][1].credentials).toBe('include');
    });

    it('does NOT call sessionEndpoint when not configured', async () => {
        const configWithout = { ...handlerConfig, sessionEndpoint: null };

        await _persistHandlerSession(sampleTokens, configWithout);

        expect(fetch).not.toHaveBeenCalled();
    });

    it('does NOT call sessionEndpoint in non-handler mode', async () => {
        const localStorageConfig = {
            ...handlerConfig,
            tokenStorage: 'localStorage',
            sessionEndpoint: '/auth/session'
        };

        await _persistHandlerSession(sampleTokens, localStorageConfig);

        expect(fetch).not.toHaveBeenCalled();
    });

    it('throws on non-OK response', async () => {
        global.fetch.mockResolvedValue({ ok: false, status: 500 });

        await expect(_persistHandlerSession(sampleTokens, handlerConfig))
            .rejects.toThrow('Session persist failed: 500');
    });

    it('throws on 403 (CSRF/audience mismatch)', async () => {
        global.fetch.mockResolvedValue({ ok: false, status: 403 });

        await expect(_persistHandlerSession(sampleTokens, handlerConfig))
            .rejects.toThrow('Session persist failed: 403');
    });

    it('throws on network error', async () => {
        global.fetch.mockRejectedValue(new TypeError('Failed to fetch'));

        await expect(_persistHandlerSession(sampleTokens, handlerConfig))
            .rejects.toThrow('Failed to fetch');
    });

    it('includes auth_method in POST body for password login', async () => {
        global.fetch.mockResolvedValue({ ok: true, status: 200 });

        const passwordTokens = { ...sampleTokens, auth_method: 'password' };
        await _persistHandlerSession(passwordTokens, handlerConfig);

        const body = JSON.parse(fetch.mock.calls[0][1].body);
        expect(body.auth_method).toBe('password');
    });

    it('includes refresh_token in POST body (server stores it)', async () => {
        global.fetch.mockResolvedValue({ ok: true, status: 200 });

        await _persistHandlerSession(sampleTokens, handlerConfig);

        const body = JSON.parse(fetch.mock.calls[0][1].body);
        expect(body.refresh_token).toBe('refresh-123');
    });

    it('works with custom sessionEndpoint path', async () => {
        global.fetch.mockResolvedValue({ ok: true, status: 200 });

        const customConfig = { ...handlerConfig, sessionEndpoint: '/api/v2/auth/session' };
        await _persistHandlerSession(sampleTokens, customConfig);

        expect(fetch.mock.calls[0][0]).toBe('/api/v2/auth/session');
    });
});
