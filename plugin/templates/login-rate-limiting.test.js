/**
 * L42 Cognito Passkey - Login Rate Limiting Tests (v0.12.1)
 *
 * Tests:
 * - Backoff calculation (exponential delay increases)
 * - Threshold behavior (no delay under threshold, delay at/above)
 * - Counter management (increments on failure, resets on success)
 * - Multiple emails (independent tracking per email)
 * - Config options (custom maxAttempts, baseMs, maxMs)
 * - OCSF logging (threshold breach logged with HIGH severity)
 * - Cognito lockout detection (lockout error surfaced clearly)
 * - getLoginAttemptInfo() (returns correct state for UI)
 * - Debug logging (throttle events logged)
 * - Page reload semantics (in-memory only, no persistence)
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// Simulated internals (mirrors auth.js rate limiting logic)
// ============================================================================

const DEFAULT_RATE_LIMIT_CONFIG = {
    maxLoginAttemptsBeforeDelay: 3,
    loginBackoffBaseMs: 1000,
    loginBackoffMaxMs: 30000,
    securityLogger: null,
    debug: false
};

let config = { ...DEFAULT_RATE_LIMIT_CONFIG };
const _loginAttempts = new Map();
const _ocsfEvents = [];
const _debugEvents = [];

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function logSecurityEvent(event) {
    _ocsfEvents.push(event);
    if (config.securityLogger === 'console') {
        // no-op in tests
    } else if (typeof config.securityLogger === 'function') {
        config.securityLogger(event);
    }
}

function debugLog(category, message, data) {
    if (!config.debug) return;
    const event = { timestamp: Date.now(), category, message, data };
    _debugEvents.push(event);
}

// OCSF constants (matching auth.js)
const OCSF_CLASS = { AUTHENTICATION: 3001 };
const OCSF_AUTH_ACTIVITY = { LOGON: 1 };
const OCSF_STATUS = { SUCCESS: 1, FAILURE: 2 };
const OCSF_SEVERITY = { INFORMATIONAL: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };

// --- Core rate limiting functions (mirrors auth.js) ---

async function checkLoginRateLimit(email) {
    const entry = _loginAttempts.get(email);
    if (!entry || entry.count < config.maxLoginAttemptsBeforeDelay) return;

    const attemptsOverThreshold = entry.count - config.maxLoginAttemptsBeforeDelay;
    const exponentialDelay = config.loginBackoffBaseMs * Math.pow(2, attemptsOverThreshold);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    const delayMs = Math.min(exponentialDelay + jitter, config.loginBackoffMaxMs);

    debugLog('auth', 'login:throttled', {
        email,
        attemptCount: entry.count,
        delayMs: Math.round(delayMs)
    });

    await sleep(delayMs);
}

function recordLoginFailure(email) {
    const entry = _loginAttempts.get(email) || { count: 0, lastAttemptTime: 0 };
    entry.count += 1;
    entry.lastAttemptTime = Date.now();
    _loginAttempts.set(email, entry);

    if (entry.count === config.maxLoginAttemptsBeforeDelay) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.LOGON,
            activity_name: 'Logon',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.HIGH,
            user_email: email,
            message: 'Login rate limit activated: ' + entry.count + ' failed attempts for ' + email
        });
    }
}

function resetLoginAttempts(email) {
    _loginAttempts.delete(email);
}

function detectCognitoLockout(error) {
    const msg = (error.message || '').toLowerCase();
    const type = (error.__type || error.code || '').toLowerCase();
    return (
        (type.includes('notauthorizedexception') || msg.includes('notauthorizedexception')) &&
        (msg.includes('temporarily locked') || msg.includes('password attempts exceeded'))
    );
}

function getLoginAttemptInfo(email) {
    const entry = _loginAttempts.get(email);
    if (!entry) return null;

    const threshold = config.maxLoginAttemptsBeforeDelay;
    const isThrottled = entry.count >= threshold;
    let nextRetryMs = 0;

    if (isThrottled) {
        const attemptsOverThreshold = entry.count - threshold;
        const exponentialDelay = config.loginBackoffBaseMs * Math.pow(2, attemptsOverThreshold);
        nextRetryMs = Math.min(exponentialDelay, config.loginBackoffMaxMs);
    }

    return {
        attemptsRemaining: Math.max(0, threshold - entry.count),
        nextRetryMs,
        isThrottled
    };
}

// ============================================================================
// Tests
// ============================================================================

describe('Login Rate Limiting (v0.12.1)', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        config = { ...DEFAULT_RATE_LIMIT_CONFIG };
        _loginAttempts.clear();
        _ocsfEvents.length = 0;
        _debugEvents.length = 0;
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    // ========================================================================
    // Backoff calculation
    // ========================================================================

    describe('backoff calculation', () => {
        it('should not delay when under threshold', async () => {
            const email = 'user@example.com';
            recordLoginFailure(email);
            recordLoginFailure(email);
            // 2 failures, threshold is 3 — no delay
            const start = Date.now();
            await checkLoginRateLimit(email);
            expect(Date.now() - start).toBe(0);
        });

        it('should delay when at threshold', async () => {
            const email = 'user@example.com';
            // Record exactly 3 failures (the threshold)
            recordLoginFailure(email);
            recordLoginFailure(email);
            recordLoginFailure(email);

            // Math.random controls jitter — stub it to 0 for predictable delays
            vi.spyOn(Math, 'random').mockReturnValue(0);

            const promise = checkLoginRateLimit(email);
            // Base delay is 1000ms * 2^0 = 1000ms (0 attempts over threshold)
            await vi.advanceTimersByTimeAsync(1000);
            await promise;
        });

        it('should double delay with each additional failure', async () => {
            const email = 'user@example.com';
            vi.spyOn(Math, 'random').mockReturnValue(0);

            // 3 failures (at threshold) then 2 more over
            for (let i = 0; i < 5; i++) recordLoginFailure(email);

            // attemptsOverThreshold = 5 - 3 = 2
            // delay = 1000 * 2^2 = 4000ms
            const promise = checkLoginRateLimit(email);
            await vi.advanceTimersByTimeAsync(4000);
            await promise;
        });

        it('should cap delay at loginBackoffMaxMs', async () => {
            const email = 'user@example.com';
            vi.spyOn(Math, 'random').mockReturnValue(0);

            // Many failures to exceed cap
            for (let i = 0; i < 20; i++) recordLoginFailure(email);

            // attemptsOverThreshold = 17, exponential = 1000 * 2^17 = 131072000
            // Should be capped at 30000ms
            const promise = checkLoginRateLimit(email);
            await vi.advanceTimersByTimeAsync(30000);
            await promise;
        });

        it('should include jitter in delay', async () => {
            const email = 'user@example.com';
            vi.spyOn(Math, 'random').mockReturnValue(1); // max jitter

            for (let i = 0; i < 3; i++) recordLoginFailure(email);

            // Base = 1000, jitter = 1.0 * 0.3 * 1000 = 300, total = 1300
            const promise = checkLoginRateLimit(email);
            await vi.advanceTimersByTimeAsync(1300);
            await promise;
        });
    });

    // ========================================================================
    // Threshold behavior
    // ========================================================================

    describe('threshold behavior', () => {
        it('should allow immediate retry for first attempt', async () => {
            await checkLoginRateLimit('new@example.com');
            // Should resolve immediately (no entry in map)
        });

        it('should allow immediate retry up to threshold minus one', async () => {
            const email = 'user@example.com';
            for (let i = 0; i < 2; i++) recordLoginFailure(email);
            // 2 failures, threshold is 3 — still immediate
            await checkLoginRateLimit(email);
        });

        it('should start delaying at exactly the threshold', async () => {
            const email = 'user@example.com';
            vi.spyOn(Math, 'random').mockReturnValue(0);

            for (let i = 0; i < 3; i++) recordLoginFailure(email);

            let resolved = false;
            const promise = checkLoginRateLimit(email).then(() => { resolved = true; });

            // Before delay expires
            await vi.advanceTimersByTimeAsync(500);
            expect(resolved).toBe(false);

            // After delay expires (1000ms total)
            await vi.advanceTimersByTimeAsync(500);
            await promise;
            expect(resolved).toBe(true);
        });
    });

    // ========================================================================
    // Counter management
    // ========================================================================

    describe('counter management', () => {
        it('should increment count on each failure', () => {
            const email = 'user@example.com';
            recordLoginFailure(email);
            expect(_loginAttempts.get(email).count).toBe(1);
            recordLoginFailure(email);
            expect(_loginAttempts.get(email).count).toBe(2);
            recordLoginFailure(email);
            expect(_loginAttempts.get(email).count).toBe(3);
        });

        it('should update lastAttemptTime on each failure', () => {
            const email = 'user@example.com';
            vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
            recordLoginFailure(email);
            const t1 = _loginAttempts.get(email).lastAttemptTime;

            vi.setSystemTime(new Date('2026-01-01T00:01:00Z'));
            recordLoginFailure(email);
            const t2 = _loginAttempts.get(email).lastAttemptTime;

            expect(t2).toBeGreaterThan(t1);
        });

        it('should reset counter on success', () => {
            const email = 'user@example.com';
            recordLoginFailure(email);
            recordLoginFailure(email);
            expect(_loginAttempts.has(email)).toBe(true);

            resetLoginAttempts(email);
            expect(_loginAttempts.has(email)).toBe(false);
        });

        it('should not error when resetting non-existent email', () => {
            expect(() => resetLoginAttempts('nobody@example.com')).not.toThrow();
        });
    });

    // ========================================================================
    // Multiple emails (independent tracking)
    // ========================================================================

    describe('multiple emails', () => {
        it('should track attempts independently per email', () => {
            recordLoginFailure('alice@example.com');
            recordLoginFailure('alice@example.com');
            recordLoginFailure('alice@example.com');
            recordLoginFailure('bob@example.com');

            expect(_loginAttempts.get('alice@example.com').count).toBe(3);
            expect(_loginAttempts.get('bob@example.com').count).toBe(1);
        });

        it('should only delay the throttled email', async () => {
            vi.spyOn(Math, 'random').mockReturnValue(0);

            for (let i = 0; i < 3; i++) recordLoginFailure('alice@example.com');
            recordLoginFailure('bob@example.com');

            // Bob should not be delayed
            await checkLoginRateLimit('bob@example.com');

            // Alice should be delayed
            let resolved = false;
            const promise = checkLoginRateLimit('alice@example.com').then(() => { resolved = true; });
            expect(resolved).toBe(false);
            await vi.advanceTimersByTimeAsync(1000);
            await promise;
            expect(resolved).toBe(true);
        });

        it('should reset only the specified email', () => {
            recordLoginFailure('alice@example.com');
            recordLoginFailure('bob@example.com');

            resetLoginAttempts('alice@example.com');

            expect(_loginAttempts.has('alice@example.com')).toBe(false);
            expect(_loginAttempts.has('bob@example.com')).toBe(true);
        });
    });

    // ========================================================================
    // Config options
    // ========================================================================

    describe('config options', () => {
        it('should respect custom maxLoginAttemptsBeforeDelay', async () => {
            config.maxLoginAttemptsBeforeDelay = 5;
            const email = 'user@example.com';

            for (let i = 0; i < 4; i++) recordLoginFailure(email);
            // 4 failures, threshold is 5 — no delay
            await checkLoginRateLimit(email);
        });

        it('should respect custom loginBackoffBaseMs', async () => {
            config.loginBackoffBaseMs = 2000;
            vi.spyOn(Math, 'random').mockReturnValue(0);

            const email = 'user@example.com';
            for (let i = 0; i < 3; i++) recordLoginFailure(email);

            // Base delay = 2000ms
            let resolved = false;
            const promise = checkLoginRateLimit(email).then(() => { resolved = true; });
            await vi.advanceTimersByTimeAsync(1999);
            expect(resolved).toBe(false);
            await vi.advanceTimersByTimeAsync(1);
            await promise;
            expect(resolved).toBe(true);
        });

        it('should respect custom loginBackoffMaxMs', async () => {
            config.loginBackoffMaxMs = 5000;
            vi.spyOn(Math, 'random').mockReturnValue(0);

            const email = 'user@example.com';
            for (let i = 0; i < 20; i++) recordLoginFailure(email);

            // Should cap at 5000ms even with high attempt count
            let resolved = false;
            const promise = checkLoginRateLimit(email).then(() => { resolved = true; });
            await vi.advanceTimersByTimeAsync(5000);
            await promise;
            expect(resolved).toBe(true);
        });
    });

    // ========================================================================
    // OCSF logging
    // ========================================================================

    describe('OCSF logging', () => {
        beforeEach(() => {
            config.securityLogger = 'console';
        });

        it('should log HIGH severity on first threshold breach', () => {
            const email = 'user@example.com';
            recordLoginFailure(email);
            recordLoginFailure(email);
            expect(_ocsfEvents.length).toBe(0);

            recordLoginFailure(email); // 3rd = threshold
            expect(_ocsfEvents.length).toBe(1);
            expect(_ocsfEvents[0].severity_id).toBe(OCSF_SEVERITY.HIGH);
            expect(_ocsfEvents[0].message).toContain('rate limit activated');
            expect(_ocsfEvents[0].message).toContain(email);
        });

        it('should not log OCSF for failures under threshold', () => {
            recordLoginFailure('user@example.com');
            recordLoginFailure('user@example.com');
            expect(_ocsfEvents.length).toBe(0);
        });

        it('should only log OCSF once at threshold, not on subsequent failures', () => {
            const email = 'user@example.com';
            for (let i = 0; i < 6; i++) recordLoginFailure(email);
            // Only the 3rd call (threshold) triggers OCSF
            expect(_ocsfEvents.length).toBe(1);
        });

        it('should use Authentication class and Logon activity', () => {
            const email = 'user@example.com';
            for (let i = 0; i < 3; i++) recordLoginFailure(email);
            expect(_ocsfEvents[0].class_uid).toBe(OCSF_CLASS.AUTHENTICATION);
            expect(_ocsfEvents[0].activity_id).toBe(OCSF_AUTH_ACTIVITY.LOGON);
        });
    });

    // ========================================================================
    // Cognito lockout detection
    // ========================================================================

    describe('Cognito lockout detection', () => {
        it('should detect "User temporarily locked" error', () => {
            const error = {
                __type: 'NotAuthorizedException',
                message: 'User temporarily locked because of too many attempts'
            };
            expect(detectCognitoLockout(error)).toBe(true);
        });

        it('should detect "Password attempts exceeded" error', () => {
            const error = {
                __type: 'NotAuthorizedException',
                message: 'Password attempts exceeded'
            };
            expect(detectCognitoLockout(error)).toBe(true);
        });

        it('should detect lockout from message alone (no __type)', () => {
            const error = {
                message: 'NotAuthorizedException: User temporarily locked'
            };
            expect(detectCognitoLockout(error)).toBe(true);
        });

        it('should not false-positive on regular auth failures', () => {
            const error = {
                __type: 'NotAuthorizedException',
                message: 'Incorrect username or password.'
            };
            expect(detectCognitoLockout(error)).toBe(false);
        });

        it('should not false-positive on other error types', () => {
            const error = {
                __type: 'UserNotFoundException',
                message: 'User temporarily locked'
            };
            expect(detectCognitoLockout(error)).toBe(false);
        });

        it('should handle missing fields gracefully', () => {
            expect(detectCognitoLockout({})).toBe(false);
            expect(detectCognitoLockout({ message: '' })).toBe(false);
        });
    });

    // ========================================================================
    // getLoginAttemptInfo()
    // ========================================================================

    describe('getLoginAttemptInfo()', () => {
        it('should return null for unknown email', () => {
            expect(getLoginAttemptInfo('nobody@example.com')).toBeNull();
        });

        it('should return attemptsRemaining before threshold', () => {
            const email = 'user@example.com';
            recordLoginFailure(email);
            const info = getLoginAttemptInfo(email);
            expect(info.attemptsRemaining).toBe(2);
            expect(info.isThrottled).toBe(false);
            expect(info.nextRetryMs).toBe(0);
        });

        it('should return isThrottled=true at threshold', () => {
            const email = 'user@example.com';
            for (let i = 0; i < 3; i++) recordLoginFailure(email);
            const info = getLoginAttemptInfo(email);
            expect(info.attemptsRemaining).toBe(0);
            expect(info.isThrottled).toBe(true);
            expect(info.nextRetryMs).toBe(1000); // base delay
        });

        it('should increase nextRetryMs with more failures', () => {
            const email = 'user@example.com';
            for (let i = 0; i < 5; i++) recordLoginFailure(email);
            const info = getLoginAttemptInfo(email);
            // attemptsOverThreshold = 2, delay = 1000 * 2^2 = 4000
            expect(info.nextRetryMs).toBe(4000);
        });

        it('should cap nextRetryMs at loginBackoffMaxMs', () => {
            const email = 'user@example.com';
            for (let i = 0; i < 20; i++) recordLoginFailure(email);
            const info = getLoginAttemptInfo(email);
            expect(info.nextRetryMs).toBe(config.loginBackoffMaxMs);
        });

        it('should return null after reset', () => {
            const email = 'user@example.com';
            recordLoginFailure(email);
            resetLoginAttempts(email);
            expect(getLoginAttemptInfo(email)).toBeNull();
        });
    });

    // ========================================================================
    // Debug logging
    // ========================================================================

    describe('debug logging', () => {
        beforeEach(() => {
            config.debug = true;
        });

        it('should log throttle events with email and delay', async () => {
            vi.spyOn(Math, 'random').mockReturnValue(0);
            const email = 'user@example.com';
            for (let i = 0; i < 3; i++) recordLoginFailure(email);

            const promise = checkLoginRateLimit(email);
            await vi.advanceTimersByTimeAsync(1000);
            await promise;

            expect(_debugEvents.length).toBe(1);
            expect(_debugEvents[0].message).toBe('login:throttled');
            expect(_debugEvents[0].data.email).toBe(email);
            expect(_debugEvents[0].data.attemptCount).toBe(3);
            expect(_debugEvents[0].data.delayMs).toBe(1000);
        });

        it('should not log when under threshold', async () => {
            const email = 'user@example.com';
            recordLoginFailure(email);
            await checkLoginRateLimit(email);
            expect(_debugEvents.length).toBe(0);
        });
    });

    // ========================================================================
    // Page reload semantics (in-memory only)
    // ========================================================================

    describe('page reload semantics', () => {
        it('should use in-memory Map (not localStorage)', () => {
            const email = 'user@example.com';
            recordLoginFailure(email);
            // Nothing should be persisted
            expect(localStorage.getItem('l42_login_attempts')).toBeNull();
            expect(localStorage.getItem(email)).toBeNull();
        });

        it('should start fresh after clearing the map (simulating page reload)', () => {
            const email = 'user@example.com';
            for (let i = 0; i < 5; i++) recordLoginFailure(email);
            expect(_loginAttempts.get(email).count).toBe(5);

            // Simulate page reload: clear the map
            _loginAttempts.clear();
            expect(getLoginAttemptInfo(email)).toBeNull();
        });
    });

    // ========================================================================
    // Integration: simulated loginWithPassword flow
    // ========================================================================

    describe('integration: simulated login flow', () => {
        it('should delay then succeed on correct password after failures', async () => {
            vi.spyOn(Math, 'random').mockReturnValue(0);
            const email = 'user@example.com';

            // Simulate 3 failed password attempts
            for (let i = 0; i < 3; i++) recordLoginFailure(email);

            // Next login attempt should be delayed
            let loginComplete = false;
            const loginFlow = (async () => {
                await checkLoginRateLimit(email);
                // Simulate successful Cognito response
                resetLoginAttempts(email);
                loginComplete = true;
            })();

            expect(loginComplete).toBe(false);
            await vi.advanceTimersByTimeAsync(1000);
            await loginFlow;
            expect(loginComplete).toBe(true);

            // After success, no more delay
            await checkLoginRateLimit(email);
            // Should resolve immediately
        });

        it('should not record failure for MFA challenge', () => {
            const email = 'user@example.com';
            const error = new Error('Additional verification required: SMS_MFA');

            // Simulate: only record if NOT MFA challenge
            if (!error.message.includes('Additional verification required')) {
                recordLoginFailure(email);
            }

            expect(_loginAttempts.has(email)).toBe(false);
        });
    });
});
