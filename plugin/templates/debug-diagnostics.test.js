/**
 * L42 Cognito Passkey - Debug Logging & Diagnostics Tests (v0.11.0)
 *
 * Tests the REAL auth.js debug/diagnostics implementation.
 * Uses _resetForTesting() for isolation between tests.
 *
 * Tests:
 * - debugLog() ring buffer behavior (via getDebugHistory)
 * - getDebugHistory() returns copy, not reference
 * - clearDebugHistory() empties buffer
 * - getDiagnostics() returns correct shape and reflects state
 * - debug: true mode — console.debug with [l42-auth] prefix
 * - debug: 'verbose' mode — includes data payload
 * - debug: function mode — custom callback receives events
 * - Debug callback errors don't break auth flow
 * - Integration: setTokens/clearTokens/configure generate events
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    VERSION,
    configure,
    isConfigured,
    isAuthenticated,
    setTokens,
    clearTokens,
    getDebugHistory,
    clearDebugHistory,
    getDiagnostics,
    isAutoRefreshActive,
    startAutoRefresh,
    stopAutoRefresh,
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
    const claims = {
        sub: 'user1',
        email: 'test@example.com',
        'cognito:groups': ['admin'],
        aud: 'test-client',
        iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_testPool',
        exp,
        ...overrides
    };
    return {
        access_token: createTestJwt({
            sub: claims.sub,
            scope: 'openid email',
            client_id: claims.aud,
            exp: claims.exp
        }),
        id_token: createTestJwt(claims),
        refresh_token: 'refresh-token-123',
        auth_method: 'password'
    };
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

// ============================================================================
// Tests — using REAL auth.js functions
// ============================================================================

describe('Debug Logging & Diagnostics', () => {
    beforeEach(() => {
        _resetForTesting();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    // ========================================================================
    // debugLog() — Ring buffer behavior (tested via getDebugHistory)
    // ========================================================================

    describe('debugLog() via getDebugHistory()', () => {
        it('adds events to history when debug is enabled', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            clearDebugHistory(); // clear the "configured" event

            setTokens(createValidTokens());

            const history = getDebugHistory();
            expect(history.length).toBeGreaterThanOrEqual(1);
            const tokenEvent = history.find(e => e.message === 'setTokens');
            expect(tokenEvent).toBeDefined();
            expect(tokenEvent.category).toBe('token');
            expect(tokenEvent.data.auth_method).toBe('password');
            expect(tokenEvent.version).toBe(VERSION);
        });

        it('does NOT add events when debug is false', () => {
            configureForTest({ debug: false });

            setTokens(createValidTokens());

            expect(getDebugHistory()).toHaveLength(0);
        });

        it('includes timestamp on every event', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            const before = Date.now();
            configureForTest({ debug: true });
            const after = Date.now();

            const event = getDebugHistory()[0];
            expect(event.timestamp).toBeGreaterThanOrEqual(before);
            expect(event.timestamp).toBeLessThanOrEqual(after);
        });

        it('caps history at 100 events (ring buffer)', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });

            // Generate >100 events by repeatedly setting/clearing tokens
            for (let i = 0; i < 60; i++) {
                setTokens(createValidTokens());
                clearTokens();
            }
            // 1 configure + 60 * (setTokens + clearTokens) = 121 events

            const history = getDebugHistory();
            expect(history).toHaveLength(100);
        });
    });

    // ========================================================================
    // getDebugHistory() — Returns copy
    // ========================================================================

    describe('getDebugHistory()', () => {
        it('returns a copy, not a reference to internal array', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });

            const history1 = getDebugHistory();
            setTokens(createValidTokens());
            const history2 = getDebugHistory();

            // history1 should NOT have been mutated
            expect(history2.length).toBeGreaterThan(history1.length);
        });

        it('returns empty array when debug disabled', () => {
            configureForTest({ debug: false });
            setTokens(createValidTokens());
            expect(getDebugHistory()).toEqual([]);
        });
    });

    // ========================================================================
    // clearDebugHistory()
    // ========================================================================

    describe('clearDebugHistory()', () => {
        it('empties the buffer', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            setTokens(createValidTokens());
            expect(getDebugHistory().length).toBeGreaterThan(0);

            clearDebugHistory();
            expect(getDebugHistory()).toHaveLength(0);
        });

        it('new events still accumulate after clearing', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            clearDebugHistory();

            setTokens(createValidTokens());

            const history = getDebugHistory();
            expect(history.length).toBeGreaterThan(0);
        });
    });

    // ========================================================================
    // getDiagnostics()
    // ========================================================================

    describe('getDiagnostics()', () => {
        it('returns correct shape when not configured', () => {
            const diag = getDiagnostics();
            expect(diag.configured).toBe(false);
            expect(diag.hasTokens).toBe(false);
            expect(diag.isAuthenticated).toBe(false);
            expect(diag.tokenExpiry).toBe(null);
            expect(diag.authMethod).toBe(null);
            expect(diag.userEmail).toBe(null);
            expect(diag.userGroups).toEqual([]);
            expect(diag.isAdmin).toBe(false);
            expect(diag.isReadonly).toBe(false);
            expect(diag.autoRefreshActive).toBe(false);
            expect(diag.version).toBe(VERSION);
        });

        it('reflects authenticated state with admin user', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            setTokens(createValidTokens());

            const diag = getDiagnostics();
            expect(diag.configured).toBe(true);
            expect(diag.hasTokens).toBe(true);
            expect(diag.isAuthenticated).toBe(true);
            expect(diag.authMethod).toBe('password');
            expect(diag.userEmail).toBe('test@example.com');
            expect(diag.userGroups).toEqual(['admin']);
            expect(diag.isAdmin).toBe(true);
            expect(diag.isReadonly).toBe(false);
            expect(diag.tokenExpiry).toBeInstanceOf(Date);
            expect(diag.debug).toBe(true);
        });

        it('reflects readonly user state', () => {
            configureForTest({ debug: false });
            setTokens(createValidTokens({ 'cognito:groups': ['readonly'] }));

            const diag = getDiagnostics();
            expect(diag.isAdmin).toBe(false);
            expect(diag.isReadonly).toBe(true);
        });

        it('reflects handler mode storage', () => {
            configureForTest();
            const diag = getDiagnostics();
            expect(diag.tokenStorage).toBe('handler');
        });

        it('reflects auto-refresh state', () => {
            vi.useFakeTimers();
            configureForTest();
            expect(getDiagnostics().autoRefreshActive).toBe(false);

            // Mock fetch for auto-refresh token checks
            global.fetch = vi.fn().mockResolvedValue({
                ok: true, status: 200,
                json: () => Promise.resolve({ access_token: 'x', id_token: 'y' })
            });
            setTokens(createValidTokens());
            startAutoRefresh();
            expect(getDiagnostics().autoRefreshActive).toBe(true);

            stopAutoRefresh();
            expect(getDiagnostics().autoRefreshActive).toBe(false);
            vi.useRealTimers();
        });

        it('handles null tokens gracefully after logout', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            setTokens(createValidTokens());
            clearTokens();

            const diag = getDiagnostics();
            expect(diag.hasTokens).toBe(false);
            expect(diag.isAuthenticated).toBe(false);
            expect(diag.authMethod).toBe(null);
            expect(diag.tokenExpiry).toBe(null);
        });
    });

    // ========================================================================
    // debug: true — console.debug with prefix
    // ========================================================================

    describe('debug: true', () => {
        it('calls console.debug with [l42-auth] prefix', () => {
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });

            // configure() itself logs — check that call
            expect(spy).toHaveBeenCalledWith('[l42-auth]', 'config', 'configured');
        });

        it('does NOT include data payload in non-verbose console output', () => {
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            clearDebugHistory();

            setTokens(createValidTokens());

            // Find the setTokens call — should have category + message, not data
            const setTokensCall = spy.mock.calls.find(c => c[2] === 'setTokens');
            expect(setTokensCall).toBeDefined();
            expect(setTokensCall).toHaveLength(3); // [prefix, category, message]
        });
    });

    // ========================================================================
    // debug: 'verbose' — includes data payload
    // ========================================================================

    describe("debug: 'verbose'", () => {
        it('calls console.debug with data payload', () => {
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: 'verbose' });

            // configure() logs with data — check it includes the payload
            const configCall = spy.mock.calls.find(c => c[2] === 'configured');
            expect(configCall).toBeDefined();
            expect(configCall.length).toBeGreaterThanOrEqual(4); // prefix + category + message + data
        });
    });

    // ========================================================================
    // debug: function — custom callback
    // ========================================================================

    describe('debug: function', () => {
        it('receives debug events', () => {
            const events = [];
            configureForTest({ debug: (event) => events.push(event) });

            expect(events.length).toBeGreaterThanOrEqual(1);
            const configEvent = events.find(e => e.message === 'configured');
            expect(configEvent).toBeDefined();
            expect(configEvent.category).toBe('config');
            expect(configEvent.version).toBe(VERSION);
            expect(typeof configEvent.timestamp).toBe('number');
        });

        it('callback errors do NOT break auth flow', () => {
            // Configure with a throwing callback
            expect(() => {
                configureForTest({ debug: () => { throw new Error('Callback boom!'); } });
            }).not.toThrow();

            // Events should still be recorded
            expect(getDebugHistory().length).toBeGreaterThan(0);
        });

        it('does NOT call console.debug when using function mode', () => {
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: () => {} });

            setTokens(createValidTokens());

            expect(spy).not.toHaveBeenCalled();
        });
    });

    // ========================================================================
    // Integration: configure/setTokens/clearTokens generate events
    // ========================================================================

    describe('integration with auth operations', () => {
        it('configure() logs config event', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });

            const history = getDebugHistory();
            const configEvent = history.find(e => e.message === 'configured');
            expect(configEvent).toBeDefined();
            expect(configEvent.category).toBe('config');
        });

        it('setTokens() logs token event with auth_method', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            clearDebugHistory();

            setTokens(createValidTokens());

            const history = getDebugHistory();
            const setEvent = history.find(e => e.message === 'setTokens');
            expect(setEvent).toBeDefined();
            expect(setEvent.category).toBe('token');
            expect(setEvent.data.auth_method).toBe('password');
            expect(setEvent.data.isRefresh).toBe(false);
        });

        it('setTokens() with isRefresh flag is reflected in data', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            clearDebugHistory();

            setTokens(createValidTokens(), { isRefresh: true });

            const event = getDebugHistory().find(e => e.message === 'setTokens');
            expect(event.data.isRefresh).toBe(true);
        });

        it('clearTokens() logs token clear event', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            clearDebugHistory();

            clearTokens();

            const history = getDebugHistory();
            const clearEvent = history.find(e => e.message === 'clearTokens');
            expect(clearEvent).toBeDefined();
            expect(clearEvent.category).toBe('token');
        });

        it('full auth lifecycle generates sequential events', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            setTokens(createValidTokens());
            clearTokens();

            const history = getDebugHistory();
            const messages = history.map(e => e.message);
            expect(messages).toContain('configured');
            expect(messages).toContain('setTokens');
            expect(messages).toContain('clearTokens');
            // Verify order
            expect(messages.indexOf('configured')).toBeLessThan(messages.indexOf('setTokens'));
            expect(messages.indexOf('setTokens')).toBeLessThan(messages.indexOf('clearTokens'));
        });

        it('events accumulate across multiple operations', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });

            for (let i = 0; i < 5; i++) {
                setTokens(createValidTokens());
                clearTokens();
            }

            // 1 configure + possible sessionEndpoint warning + 5*(setTokens+clearTokens)
            expect(getDebugHistory().length).toBeGreaterThanOrEqual(11);
        });
    });

    // ========================================================================
    // Additional edge cases
    // ========================================================================

    describe('edge cases', () => {
        it('switching debug mode mid-session works correctly', () => {
            // Start with debug: true
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            const count1 = getDebugHistory().length;

            // Reconfigure with debug: false — new events shouldn't be logged
            // (note: reconfigure itself won't log since debug is now false)
            _resetForTesting();
            configureForTest({ debug: false });
            setTokens(createValidTokens());
            expect(getDebugHistory()).toHaveLength(0);
        });

        it('getDiagnostics works even when debug is a function', () => {
            configureForTest({ debug: () => {} });

            const diag = getDiagnostics();
            expect(typeof diag.debug).toBe('function');
        });

        it('version field matches on all events', () => {
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            configureForTest({ debug: true });
            setTokens(createValidTokens());
            clearTokens();

            const history = getDebugHistory();
            history.forEach(e => {
                expect(e.version).toBe(VERSION);
            });
        });
    });
});
