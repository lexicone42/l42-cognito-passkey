/**
 * L42 Cognito Passkey - Debug Logging & Diagnostics Tests (v0.11.0)
 *
 * Tests:
 * - debugLog() ring buffer behavior
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

function createValidTokens(overrides = {}) {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    return {
        access_token: createTestJwt({ sub: 'user1', scope: 'openid email', exp, ...overrides }),
        id_token: createTestJwt({
            sub: 'user1',
            email: 'test@example.com',
            'cognito:groups': ['admin'],
            exp,
            ...overrides
        }),
        refresh_token: 'refresh-token-123',
        auth_method: 'password'
    };
}

// ============================================================================
// Simulated auth.js debug internals
// ============================================================================

const VERSION = '0.11.0';
const DEBUG_HISTORY_MAX = 100;
let _debugHistory = [];
let config = {
    debug: false,
    tokenStorage: 'handler',
    tokenKey: 'l42_auth_tokens',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    clientId: 'test-client',
    cognitoDomain: 'test.auth.us-west-2.amazoncognito.com'
};
let _configured = false;
let _storedTokens = null;
let _autoRefreshTimer = null;

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
    if (_debugHistory.length > DEBUG_HISTORY_MAX) {
        _debugHistory.shift();
    }

    if (config.debug === true) {
        console.debug('[l42-auth]', category, message);
    } else if (config.debug === 'verbose') {
        console.debug('[l42-auth]', category, message, data !== undefined ? data : '');
    } else if (typeof config.debug === 'function') {
        try {
            config.debug(event);
        } catch {
            // Don't let debug callback errors break auth flow
        }
    }
}

function getDebugHistory() {
    return [..._debugHistory];
}

function clearDebugHistory() {
    _debugHistory.length = 0;
}

function isAutoRefreshActive() {
    return _autoRefreshTimer !== null;
}

function isTokenExpired(tokens) {
    try {
        return Date.now() >= UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
    } catch {
        return true;
    }
}

function isAuthenticated() {
    if (!_configured) return false;
    const tokens = _storedTokens;
    return tokens !== null && !isTokenExpired(tokens);
}

function getUserEmail() {
    if (!_configured || !_storedTokens) return null;
    try {
        return UNSAFE_decodeJwtPayload(_storedTokens.id_token).email || null;
    } catch {
        return null;
    }
}

function getUserGroups() {
    if (!_configured || !_storedTokens) return [];
    try {
        return UNSAFE_decodeJwtPayload(_storedTokens.id_token)['cognito:groups'] || [];
    } catch {
        return [];
    }
}

function isAdmin() {
    const groups = getUserGroups().map(g => g.toLowerCase());
    return groups.some(g => ['admin', 'admins', 'administrators'].includes(g));
}

function isReadonly() {
    if (isAdmin()) return false;
    const groups = getUserGroups().map(g => g.toLowerCase());
    return groups.some(g => ['readonly', 'read-only', 'viewer', 'viewers'].includes(g));
}

function getDiagnostics() {
    const tokens = _configured ? _storedTokens : null;
    let tokenExpiry = null;
    if (tokens && tokens.id_token) {
        try {
            tokenExpiry = new Date(UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000);
        } catch {
            // Invalid token
        }
    }

    return {
        configured: _configured,
        tokenStorage: config.tokenStorage,
        hasTokens: tokens !== null,
        isAuthenticated: _configured ? isAuthenticated() : false,
        tokenExpiry,
        authMethod: tokens ? (tokens.auth_method || null) : null,
        userEmail: _configured ? getUserEmail() : null,
        userGroups: _configured ? getUserGroups() : [],
        isAdmin: _configured ? isAdmin() : false,
        isReadonly: _configured ? isReadonly() : false,
        autoRefreshActive: isAutoRefreshActive(),
        debug: config.debug,
        version: VERSION
    };
}

// Simulated configure/setTokens/clearTokens with debug logging
function configure(options) {
    config = { ...config, ...options };
    _configured = true;
    debugLog('config', 'configured', { tokenStorage: config.tokenStorage });
}

function setTokens(tokens, options = {}) {
    debugLog('token', 'setTokens', { auth_method: tokens?.auth_method, isRefresh: !!options.isRefresh });
    _storedTokens = tokens;
}

function clearTokens() {
    debugLog('token', 'clearTokens');
    _storedTokens = null;
}

// ============================================================================
// Tests
// ============================================================================

describe('Debug Logging & Diagnostics', () => {
    beforeEach(() => {
        _debugHistory = [];
        _storedTokens = null;
        _configured = false;
        _autoRefreshTimer = null;
        config = {
            debug: false,
            tokenStorage: 'handler',
            tokenKey: 'l42_auth_tokens',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout',
            clientId: 'test-client',
            cognitoDomain: 'test.auth.us-west-2.amazoncognito.com'
        };
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    // ========================================================================
    // debugLog() — Ring buffer behavior
    // ========================================================================

    describe('debugLog()', () => {
        it('adds events to history when debug is enabled', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('token', 'setTokens', { auth_method: 'password' });

            const history = getDebugHistory();
            expect(history).toHaveLength(1);
            expect(history[0].category).toBe('token');
            expect(history[0].message).toBe('setTokens');
            expect(history[0].data).toEqual({ auth_method: 'password' });
            expect(history[0].version).toBe(VERSION);
        });

        it('does NOT add events when debug is false', () => {
            config.debug = false;
            debugLog('token', 'setTokens');

            expect(getDebugHistory()).toHaveLength(0);
        });

        it('includes timestamp on every event', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            const before = Date.now();
            debugLog('config', 'configured');
            const after = Date.now();

            const event = getDebugHistory()[0];
            expect(event.timestamp).toBeGreaterThanOrEqual(before);
            expect(event.timestamp).toBeLessThanOrEqual(after);
        });

        it('caps history at 100 events (ring buffer)', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            for (let i = 0; i < 110; i++) {
                debugLog('test', `event-${i}`);
            }

            const history = getDebugHistory();
            expect(history).toHaveLength(100);
            // Oldest events should have been shifted off
            expect(history[0].message).toBe('event-10');
            expect(history[99].message).toBe('event-109');
        });

        it('omits data field when no data provided', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('auth', 'logout');

            const event = getDebugHistory()[0];
            expect(event).not.toHaveProperty('data');
        });

        it('includes data field when data is provided', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('auth', 'login', { method: 'password' });

            const event = getDebugHistory()[0];
            expect(event.data).toEqual({ method: 'password' });
        });
    });

    // ========================================================================
    // getDebugHistory() — Returns copy
    // ========================================================================

    describe('getDebugHistory()', () => {
        it('returns a copy, not a reference to internal array', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('test', 'event1');
            const history1 = getDebugHistory();

            debugLog('test', 'event2');
            const history2 = getDebugHistory();

            // history1 should NOT have been mutated by the second debugLog
            expect(history1).toHaveLength(1);
            expect(history2).toHaveLength(2);
        });

        it('returns empty array when debug disabled', () => {
            config.debug = false;
            debugLog('test', 'event');
            expect(getDebugHistory()).toEqual([]);
        });
    });

    // ========================================================================
    // clearDebugHistory()
    // ========================================================================

    describe('clearDebugHistory()', () => {
        it('empties the buffer', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('test', 'event1');
            debugLog('test', 'event2');
            expect(getDebugHistory()).toHaveLength(2);

            clearDebugHistory();
            expect(getDebugHistory()).toHaveLength(0);
        });

        it('new events still accumulate after clearing', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('test', 'before');
            clearDebugHistory();
            debugLog('test', 'after');

            const history = getDebugHistory();
            expect(history).toHaveLength(1);
            expect(history[0].message).toBe('after');
        });
    });

    // ========================================================================
    // getDiagnostics()
    // ========================================================================

    describe('getDiagnostics()', () => {
        it('returns correct shape when not configured', () => {
            const diag = getDiagnostics();
            expect(diag).toEqual({
                configured: false,
                tokenStorage: 'handler',
                hasTokens: false,
                isAuthenticated: false,
                tokenExpiry: null,
                authMethod: null,
                userEmail: null,
                userGroups: [],
                isAdmin: false,
                isReadonly: false,
                autoRefreshActive: false,
                debug: false,
                version: VERSION
            });
        });

        it('reflects authenticated state with admin user', () => {
            configure({ debug: true });
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            const tokens = createValidTokens();
            setTokens(tokens);

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
            configure({ debug: false });
            const tokens = createValidTokens({ 'cognito:groups': ['readonly'] });
            setTokens(tokens);

            const diag = getDiagnostics();
            expect(diag.isAdmin).toBe(false);
            expect(diag.isReadonly).toBe(true);
        });

        it('reflects handler mode storage', () => {
            config.tokenStorage = 'handler';
            _configured = true;

            const diag = getDiagnostics();
            expect(diag.tokenStorage).toBe('handler');
        });

        it('reflects auto-refresh state', () => {
            _configured = true;
            expect(getDiagnostics().autoRefreshActive).toBe(false);

            _autoRefreshTimer = 12345; // simulate active timer
            expect(getDiagnostics().autoRefreshActive).toBe(true);
        });

        it('handles null tokens gracefully after logout', () => {
            configure({ debug: true });
            vi.spyOn(console, 'debug').mockImplementation(() => {});

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
            config.debug = true;
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('token', 'setTokens');

            expect(spy).toHaveBeenCalledWith('[l42-auth]', 'token', 'setTokens');
        });

        it('does NOT include data payload in console output', () => {
            config.debug = true;
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('auth', 'login', { method: 'password' });

            // With debug: true, only category + message are logged (not data)
            expect(spy).toHaveBeenCalledWith('[l42-auth]', 'auth', 'login');
        });
    });

    // ========================================================================
    // debug: 'verbose' — includes data payload
    // ========================================================================

    describe("debug: 'verbose'", () => {
        it('calls console.debug with data payload', () => {
            config.debug = 'verbose';
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('auth', 'login', { method: 'password' });

            expect(spy).toHaveBeenCalledWith('[l42-auth]', 'auth', 'login', { method: 'password' });
        });

        it('passes empty string when no data provided', () => {
            config.debug = 'verbose';
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('auth', 'logout');

            expect(spy).toHaveBeenCalledWith('[l42-auth]', 'auth', 'logout', '');
        });
    });

    // ========================================================================
    // debug: function — custom callback
    // ========================================================================

    describe('debug: function', () => {
        it('receives debug events', () => {
            const events = [];
            config.debug = (event) => events.push(event);

            debugLog('config', 'configured', { tokenStorage: 'handler' });

            expect(events).toHaveLength(1);
            expect(events[0].category).toBe('config');
            expect(events[0].message).toBe('configured');
            expect(events[0].data).toEqual({ tokenStorage: 'handler' });
            expect(events[0].version).toBe(VERSION);
            expect(typeof events[0].timestamp).toBe('number');
        });

        it('callback errors do NOT break auth flow', () => {
            config.debug = () => { throw new Error('Callback boom!'); };

            // Should not throw
            expect(() => debugLog('auth', 'login')).not.toThrow();

            // Event should still be recorded in history
            expect(getDebugHistory()).toHaveLength(1);
        });

        it('does NOT call console.debug', () => {
            const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
            config.debug = () => {};

            debugLog('test', 'event');

            expect(spy).not.toHaveBeenCalled();
        });
    });

    // ========================================================================
    // Integration: configure/setTokens/clearTokens generate events
    // ========================================================================

    describe('integration with auth operations', () => {
        it('configure() logs config event', () => {
            configure({ debug: true });
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            const history = getDebugHistory();
            expect(history).toHaveLength(1);
            expect(history[0].category).toBe('config');
            expect(history[0].message).toBe('configured');
            expect(history[0].data.tokenStorage).toBe('handler');
        });

        it('setTokens() logs token event with auth_method', () => {
            configure({ debug: true });
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            clearDebugHistory();

            const tokens = createValidTokens();
            setTokens(tokens);

            const history = getDebugHistory();
            expect(history).toHaveLength(1);
            expect(history[0].category).toBe('token');
            expect(history[0].message).toBe('setTokens');
            expect(history[0].data.auth_method).toBe('password');
            expect(history[0].data.isRefresh).toBe(false);
        });

        it('setTokens() with isRefresh flag is reflected in data', () => {
            configure({ debug: true });
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            clearDebugHistory();

            setTokens(createValidTokens(), { isRefresh: true });

            const event = getDebugHistory()[0];
            expect(event.data.isRefresh).toBe(true);
        });

        it('clearTokens() logs token clear event', () => {
            configure({ debug: true });
            vi.spyOn(console, 'debug').mockImplementation(() => {});
            clearDebugHistory();

            clearTokens();

            const history = getDebugHistory();
            expect(history).toHaveLength(1);
            expect(history[0].category).toBe('token');
            expect(history[0].message).toBe('clearTokens');
        });

        it('full auth lifecycle generates sequential events', () => {
            configure({ debug: true });
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            const tokens = createValidTokens();
            setTokens(tokens);
            clearTokens();

            const history = getDebugHistory();
            const messages = history.map(e => e.message);
            expect(messages).toEqual(['configured', 'setTokens', 'clearTokens']);
        });

        it('events accumulate across multiple operations', () => {
            configure({ debug: true });
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            // Simulate multiple login/logout cycles
            for (let i = 0; i < 5; i++) {
                setTokens(createValidTokens());
                clearTokens();
            }

            // 1 configure + 5 * (setTokens + clearTokens) = 11 events
            expect(getDebugHistory()).toHaveLength(11);
        });
    });

    // ========================================================================
    // Additional edge cases
    // ========================================================================

    describe('edge cases', () => {
        it('debugLog with undefined data does not include data field', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('test', 'no-data', undefined);

            const event = getDebugHistory()[0];
            expect(event).not.toHaveProperty('data');
        });

        it('debugLog with null data includes data field as null', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('test', 'null-data', null);

            const event = getDebugHistory()[0];
            expect(event.data).toBe(null);
        });

        it('switching debug mode mid-session works correctly', () => {
            // Start with debug: true
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('test', 'while-true');
            expect(getDebugHistory()).toHaveLength(1);

            // Switch to false — new events are not logged
            config.debug = false;
            debugLog('test', 'while-false');
            expect(getDebugHistory()).toHaveLength(1);

            // Switch to function — events resume
            const events = [];
            config.debug = (e) => events.push(e);
            debugLog('test', 'while-function');
            expect(getDebugHistory()).toHaveLength(2);
            expect(events).toHaveLength(1);
        });

        it('getDiagnostics works even when debug is a function', () => {
            config.debug = () => {};
            _configured = true;

            const diag = getDiagnostics();
            // debug field in diagnostics reflects the function type
            expect(typeof diag.debug).toBe('function');
        });

        it('version field matches on all events', () => {
            config.debug = true;
            vi.spyOn(console, 'debug').mockImplementation(() => {});

            debugLog('a', '1');
            debugLog('b', '2');
            debugLog('c', '3');

            const history = getDebugHistory();
            history.forEach(e => {
                expect(e.version).toBe(VERSION);
            });
        });
    });
});
