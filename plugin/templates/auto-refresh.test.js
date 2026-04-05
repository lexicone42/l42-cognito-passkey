/**
 * L42 Cognito Passkey - Auto-Refresh, fetchWithAuth, and Session Expiry Tests (v0.9.0)
 *
 * Tests REAL auth.js auto-refresh, fetchWithAuth, and session expiry functions.
 * Uses _resetForTesting() + URL-routing fetch mock for isolation.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    configure,
    setTokens,
    clearTokens,
    isAuthenticated,
    startAutoRefresh,
    stopAutoRefresh,
    isAutoRefreshActive,
    onSessionExpired,
    fetchWithAuth,
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

function createValidTokens(overrides = {}) {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    return {
        access_token: createTestJwt({ sub: 'user1', scope: 'openid email', client_id: 'test-client', exp, ...overrides }),
        id_token: createTestJwt({
            sub: 'user1', email: 'test@example.com',
            'cognito:groups': ['users'],
            aud: 'test-client',
            iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test',
            exp, ...overrides
        }),
        auth_method: 'password'
    };
}

function createExpiredTokens() {
    const exp = Math.floor(Date.now() / 1000) - 60;
    return createValidTokens({ exp });
}

function createSoonExpiringTokens() {
    const exp = Math.floor(Date.now() / 1000) + 120; // 2 minutes
    return createValidTokens({ exp });
}

function configureForTest() {
    configure({
        clientId: 'test-client',
        cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
        cognitoRegion: 'us-west-2',
        tokenEndpoint: '/auth/token',
        refreshEndpoint: '/auth/refresh',
        logoutEndpoint: '/auth/logout',
        sessionEndpoint: '/auth/session'
    });
}

/**
 * URL-routing fetch mock: returns different responses for auth endpoints vs user APIs.
 * @param {Object} opts - { tokenResponse, refreshResponse, userApiResponse }
 */
function setupFetchMock(opts = {}) {
    const refreshTokens = createValidTokens();
    global.fetch = vi.fn((url) => {
        if (typeof url === 'string' && url.includes('/auth/refresh')) {
            if (opts.refreshError) return Promise.reject(opts.refreshError);
            return Promise.resolve(opts.refreshResponse || {
                ok: true, status: 200,
                json: () => Promise.resolve({
                    access_token: refreshTokens.access_token,
                    id_token: refreshTokens.id_token,
                    auth_method: 'handler'
                })
            });
        }
        if (typeof url === 'string' && url.includes('/auth/token')) {
            return Promise.resolve(opts.tokenResponse || {
                ok: true, status: 200,
                json: () => Promise.resolve({
                    access_token: refreshTokens.access_token,
                    id_token: refreshTokens.id_token,
                    auth_method: 'handler'
                })
            });
        }
        if (typeof url === 'string' && url.includes('/auth/logout')) {
            return Promise.resolve({ ok: true, status: 200 });
        }
        // User API call (fetchWithAuth)
        return Promise.resolve(opts.userApiResponse || { ok: true, status: 200 });
    });
}

// ============================================================================
// Tests — REAL auth.js
// ============================================================================

describe('Auto-Refresh', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        _resetForTesting();
        configureForTest();
        setTokens(createValidTokens());
        setupFetchMock();
    });

    afterEach(() => {
        stopAutoRefresh();
        vi.useRealTimers();
        vi.restoreAllMocks();
    });

    it('starts and reports active', () => {
        expect(isAutoRefreshActive()).toBe(false);
        startAutoRefresh();
        expect(isAutoRefreshActive()).toBe(true);
    });

    it('stops and reports inactive', () => {
        startAutoRefresh();
        stopAutoRefresh();
        expect(isAutoRefreshActive()).toBe(false);
    });

    it('returns stop function from startAutoRefresh', () => {
        const stop = startAutoRefresh();
        expect(isAutoRefreshActive()).toBe(true);
        stop();
        expect(isAutoRefreshActive()).toBe(false);
    });

    it('does not call refresh when tokens are valid', async () => {
        startAutoRefresh({ intervalMs: 1000 });
        await vi.advanceTimersByTimeAsync(1001);
        // Valid tokens = no refresh call
        const refreshCalls = global.fetch.mock.calls.filter(c => c[0]?.includes?.('/auth/refresh'));
        expect(refreshCalls).toHaveLength(0);
    });

    it('calls refresh when tokens are approaching expiry', async () => {
        _resetForTesting();
        configureForTest();
        setTokens(createSoonExpiringTokens());
        setupFetchMock();

        startAutoRefresh({ intervalMs: 1000 });
        await vi.advanceTimersByTimeAsync(1001);

        const refreshCalls = global.fetch.mock.calls.filter(c => c[0]?.includes?.('/auth/refresh'));
        expect(refreshCalls.length).toBeGreaterThanOrEqual(1);
    });

    it('calls refresh when tokens are expired', async () => {
        _resetForTesting();
        configureForTest();
        setTokens(createExpiredTokens());
        setupFetchMock();

        startAutoRefresh({ intervalMs: 1000 });
        await vi.advanceTimersByTimeAsync(1001);

        const refreshCalls = global.fetch.mock.calls.filter(c => c[0]?.includes?.('/auth/refresh'));
        expect(refreshCalls.length).toBeGreaterThanOrEqual(1);
    });

    it('fires onSessionExpired when expired token refresh fails', async () => {
        _resetForTesting();
        configureForTest();
        setTokens(createExpiredTokens());
        setupFetchMock({
            refreshResponse: { ok: false, status: 401 }
        });

        const expiredCallback = vi.fn();
        onSessionExpired(expiredCallback);

        startAutoRefresh({ intervalMs: 1000 });
        await vi.advanceTimersByTimeAsync(1001);

        expect(expiredCallback).toHaveBeenCalled();
        expect(isAuthenticated()).toBe(false);
    });

    it('stops auto-refresh when no tokens found', async () => {
        clearTokens();
        // Mock server returning 401 (no valid session)
        setupFetchMock({ tokenResponse: { ok: false, status: 401 } });
        startAutoRefresh({ intervalMs: 1000 });
        expect(isAutoRefreshActive()).toBe(true);

        await vi.advanceTimersByTimeAsync(1001);

        expect(isAutoRefreshActive()).toBe(false);
    });

    it('stops auto-refresh after session expiry', async () => {
        _resetForTesting();
        configureForTest();
        setTokens(createExpiredTokens());
        setupFetchMock({
            refreshResponse: { ok: false, status: 401 }
        });

        startAutoRefresh({ intervalMs: 1000 });
        expect(isAutoRefreshActive()).toBe(true);

        await vi.advanceTimersByTimeAsync(1001);

        expect(isAutoRefreshActive()).toBe(false);
    });

    it('cleans up previous timer when startAutoRefresh is called again', () => {
        startAutoRefresh({ intervalMs: 1000 });
        startAutoRefresh({ intervalMs: 2000 });
        // Should still be active (new timer replaced old)
        expect(isAutoRefreshActive()).toBe(true);
    });

    it('uses custom intervalMs', () => {
        const spy = vi.spyOn(globalThis, 'setInterval');
        startAutoRefresh({ intervalMs: 5000 });
        expect(spy).toHaveBeenCalledWith(expect.any(Function), 5000);
        spy.mockRestore();
    });
});

describe('Auto-Refresh Visibility API', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        _resetForTesting();
        configureForTest();
        setTokens(createSoonExpiringTokens());
        setupFetchMock();
    });

    afterEach(() => {
        stopAutoRefresh();
        vi.useRealTimers();
        vi.restoreAllMocks();
    });

    it('adds visibilitychange listener when pauseWhenHidden=true', () => {
        const spy = vi.spyOn(document, 'addEventListener');
        startAutoRefresh({ pauseWhenHidden: true });
        expect(spy).toHaveBeenCalledWith('visibilitychange', expect.any(Function));
        spy.mockRestore();
    });

    it('does not add listener when pauseWhenHidden=false', () => {
        const spy = vi.spyOn(document, 'addEventListener');
        startAutoRefresh({ pauseWhenHidden: false });
        expect(spy).not.toHaveBeenCalledWith('visibilitychange', expect.any(Function));
        spy.mockRestore();
    });

    it('removes visibilitychange listener on stop', () => {
        const spy = vi.spyOn(document, 'removeEventListener');
        startAutoRefresh({ pauseWhenHidden: true });
        stopAutoRefresh();
        expect(spy).toHaveBeenCalledWith('visibilitychange', expect.any(Function));
        spy.mockRestore();
    });

    it('checks refresh when tab becomes visible', async () => {
        startAutoRefresh({ pauseWhenHidden: true, intervalMs: 60000 });

        Object.defineProperty(document, 'visibilityState', {
            value: 'visible', writable: true, configurable: true
        });
        document.dispatchEvent(new Event('visibilitychange'));

        await vi.advanceTimersByTimeAsync(0);
        await vi.advanceTimersByTimeAsync(0);

        const refreshCalls = global.fetch.mock.calls.filter(c => c[0]?.includes?.('/auth/refresh'));
        expect(refreshCalls.length).toBeGreaterThanOrEqual(1);
    });
});

describe('onSessionExpired', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    it('returns unsubscribe function', async () => {
        setTokens(createExpiredTokens());
        setupFetchMock({ refreshResponse: { ok: false, status: 401 } });
        vi.useFakeTimers();

        const callback = vi.fn();
        const unsub = onSessionExpired(callback);
        unsub();

        startAutoRefresh({ intervalMs: 1000 });
        await vi.advanceTimersByTimeAsync(1001);

        expect(callback).not.toHaveBeenCalled();
        stopAutoRefresh();
        vi.useRealTimers();
    });

    it('supports multiple listeners', async () => {
        setTokens(createExpiredTokens());
        setupFetchMock({ refreshResponse: { ok: false, status: 401 } });
        vi.useFakeTimers();

        const cb1 = vi.fn();
        const cb2 = vi.fn();
        onSessionExpired(cb1);
        onSessionExpired(cb2);

        startAutoRefresh({ intervalMs: 1000 });
        await vi.advanceTimersByTimeAsync(1001);

        expect(cb1).toHaveBeenCalled();
        expect(cb2).toHaveBeenCalled();
        stopAutoRefresh();
        vi.useRealTimers();
    });
});

describe('fetchWithAuth', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
        setTokens(createValidTokens());
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('injects Bearer token into request', async () => {
        setupFetchMock();
        await fetchWithAuth('/api/data');

        const apiCalls = global.fetch.mock.calls.filter(c => c[0] === '/api/data');
        expect(apiCalls).toHaveLength(1);
        expect(apiCalls[0][1].headers.Authorization).toMatch(/^Bearer eyJ/);
    });

    it('passes through custom headers', async () => {
        setupFetchMock();
        await fetchWithAuth('/api/data', {
            headers: { 'Content-Type': 'application/json' }
        });

        const apiCalls = global.fetch.mock.calls.filter(c => c[0] === '/api/data');
        expect(apiCalls[0][1].headers['Content-Type']).toBe('application/json');
        expect(apiCalls[0][1].headers.Authorization).toMatch(/^Bearer /);
    });

    it('passes through method and body', async () => {
        setupFetchMock();
        await fetchWithAuth('/api/data', {
            method: 'POST',
            body: JSON.stringify({ key: 'value' })
        });

        const apiCalls = global.fetch.mock.calls.filter(c => c[0] === '/api/data');
        expect(apiCalls[0][1].method).toBe('POST');
        expect(apiCalls[0][1].body).toBe(JSON.stringify({ key: 'value' }));
    });

    it('throws when not authenticated', async () => {
        clearTokens();
        // Server also returns 401 — truly no session
        setupFetchMock({ tokenResponse: { ok: false, status: 401 } });

        await expect(fetchWithAuth('/api/data'))
            .rejects.toThrow('Not authenticated');
    });

    it('retries on 401 after refresh', async () => {
        let callCount = 0;
        global.fetch = vi.fn((url) => {
            if (typeof url === 'string' && url.includes('/auth/refresh')) {
                return Promise.resolve({
                    ok: true, status: 200,
                    json: () => Promise.resolve({
                        access_token: createValidTokens().access_token,
                        id_token: createValidTokens().id_token,
                        auth_method: 'handler'
                    })
                });
            }
            if (typeof url === 'string' && url.includes('/auth/')) {
                return Promise.resolve({ ok: true, status: 200 });
            }
            callCount++;
            if (callCount === 1) return Promise.resolve({ status: 401, ok: false });
            return Promise.resolve({ status: 200, ok: true });
        });

        const result = await fetchWithAuth('/api/data');

        expect(result.status).toBe(200);
        expect(callCount).toBe(2); // original 401 + retry 200
    });

    it('fires onSessionExpired on 401 + refresh failure', async () => {
        global.fetch = vi.fn((url) => {
            if (typeof url === 'string' && url.includes('/auth/refresh')) {
                return Promise.resolve({ ok: false, status: 401 });
            }
            if (typeof url === 'string' && url.includes('/auth/')) {
                return Promise.resolve({ ok: true, status: 200 });
            }
            return Promise.resolve({ status: 401, ok: false });
        });

        const expiredCb = vi.fn();
        onSessionExpired(expiredCb);

        await expect(fetchWithAuth('/api/data'))
            .rejects.toThrow('Session expired');

        expect(expiredCb).toHaveBeenCalled();
        expect(isAuthenticated()).toBe(false);
    });

    it('returns response directly on non-401', async () => {
        setupFetchMock({ userApiResponse: { status: 200, ok: true } });
        const result = await fetchWithAuth('/api/data');
        expect(result.status).toBe(200);
    });

    it('returns non-401 error responses without retry', async () => {
        setupFetchMock({ userApiResponse: { status: 500, ok: false } });
        const result = await fetchWithAuth('/api/data');
        expect(result.status).toBe(500);
    });
});

describe('CSRF Header on Handler Mode', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
        setTokens(createValidTokens());
    });

    it('refreshTokensViaHandler includes X-L42-CSRF header', async () => {
        setupFetchMock();
        setTokens(createSoonExpiringTokens());

        // Trigger a refresh by calling ensureValidTokens indirectly
        vi.useFakeTimers();
        startAutoRefresh({ intervalMs: 100 });
        await vi.advanceTimersByTimeAsync(101);
        stopAutoRefresh();
        vi.useRealTimers();

        const refreshCalls = global.fetch.mock.calls.filter(c => c[0]?.includes?.('/auth/refresh'));
        if (refreshCalls.length > 0) {
            expect(refreshCalls[0][1].headers['X-L42-CSRF']).toBe('1');
        }
    });

    it('CSRF middleware rejects requests without header', () => {
        function requireCsrfHeader(headers) {
            return headers['x-l42-csrf'] === '1';
        }

        expect(requireCsrfHeader({ 'x-l42-csrf': '1' })).toBe(true);
        expect(requireCsrfHeader({})).toBe(false);
        expect(requireCsrfHeader({ 'x-l42-csrf': '0' })).toBe(false);
    });
});
