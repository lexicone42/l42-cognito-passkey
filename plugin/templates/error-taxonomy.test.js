/**
 * L42 Cognito Passkey - Error Taxonomy Tests
 *
 * Tests the AuthError contract: stable `.code`, backward-compatible messages,
 * and correct classification of failure kinds. Design review #4.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
    AuthError,
    AuthErrorCode,
    configure,
    fetchWithAuth,
    _resetForTesting
} from '../../src/auth.js';

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

describe('AuthError shape', () => {
    it('is an Error subclass carrying a stable code', () => {
        const e = new AuthError(AuthErrorCode.NETWORK, 'boom');
        expect(e).toBeInstanceOf(Error);
        expect(e).toBeInstanceOf(AuthError);
        expect(e.name).toBe('AuthError');
        expect(e.code).toBe('NETWORK');
        expect(e.message).toBe('boom');
    });

    it('defaults to UNKNOWN when no code given', () => {
        const e = new AuthError(undefined, 'x');
        expect(e.code).toBe(AuthErrorCode.UNKNOWN);
    });

    it('carries cause and details when provided', () => {
        const cause = new Error('root');
        const e = new AuthError(AuthErrorCode.MFA_REQUIRED, 'mfa', {
            cause,
            details: { challengeName: 'SMS_MFA' }
        });
        expect(e.cause).toBe(cause);
        expect(e.details.challengeName).toBe('SMS_MFA');
    });

    it('exposes a complete, stable code set', () => {
        // These codes are a public contract — removing/renaming is breaking.
        for (const code of [
            'NOT_CONFIGURED', 'INVALID_CONFIG', 'NETWORK', 'SESSION_EXPIRED',
            'MFA_REQUIRED', 'LOCKED_OUT', 'USER_CANCELLED', 'CREDENTIAL_REJECTED',
            'RATE_LIMITED', 'PASSKEY_NOT_AVAILABLE', 'OAUTH_STATE_MISMATCH',
            'TOKEN_EXCHANGE_FAILED', 'NOT_AUTHENTICATED', 'AUTH_FAILED', 'UNKNOWN'
        ]) {
            expect(AuthErrorCode[code]).toBe(code);
        }
    });
});

describe('configure() throws INVALID_CONFIG', () => {
    beforeEach(() => _resetForTesting());

    it('missing clientId', () => {
        try {
            configure({ cognitoDomain: 'x.auth.us-west-2.amazoncognito.com' });
            expect.fail('should throw');
        } catch (e) {
            expect(e).toBeInstanceOf(AuthError);
            expect(e.code).toBe(AuthErrorCode.INVALID_CONFIG);
        }
    });

    it('deprecated tokenStorage', () => {
        try {
            configureForTest({ tokenStorage: 'localStorage' });
            expect.fail('should throw');
        } catch (e) {
            expect(e.code).toBe(AuthErrorCode.INVALID_CONFIG);
            // Message contract preserved for humans
            expect(e.message).toMatch(/removed in v0\.15\.0/);
        }
    });

    it('missing handler endpoints', () => {
        try {
            configure({
                clientId: 'x',
                cognitoDomain: 'x.auth.us-west-2.amazoncognito.com'
            });
            expect.fail('should throw');
        } catch (e) {
            expect(e.code).toBe(AuthErrorCode.INVALID_CONFIG);
        }
    });
});

describe('operations requiring auth throw NOT_AUTHENTICATED', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    afterEach(() => vi.restoreAllMocks());

    it('fetchWithAuth without a session', async () => {
        // No tokens; token endpoint returns 401 so ensureValidTokens yields null.
        global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 401 });
        try {
            await fetchWithAuth('/api/data');
            expect.fail('should throw');
        } catch (e) {
            expect(e).toBeInstanceOf(AuthError);
            expect(e.code).toBe(AuthErrorCode.NOT_AUTHENTICATED);
        }
    });

    it('fetchWithAuth surfaces SESSION_EXPIRED on 401 + failed refresh', async () => {
        // Seed a valid cached session, then have the API 401 and refresh 401.
        const { setTokens } = await import('../../src/auth.js');
        const exp = Math.floor(Date.now() / 1000) + 3600;
        const jwt = (claims) => {
            const h = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            const p = btoa(JSON.stringify(claims))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            return `${h}.${p}.sig`;
        };
        setTokens({
            access_token: jwt({ sub: 'u', client_id: 'test-client', exp }),
            id_token: jwt({
                sub: 'u', aud: 'test-client',
                iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_t', exp
            }),
            auth_method: 'password'
        });

        global.fetch = vi.fn((url) => {
            if (typeof url === 'string' && url.includes('/auth/refresh')) {
                return Promise.resolve({ ok: false, status: 401 });
            }
            if (typeof url === 'string' && url.includes('/auth/')) {
                return Promise.resolve({ ok: true, status: 200 });
            }
            return Promise.resolve({ status: 401, ok: false });
        });

        try {
            await fetchWithAuth('/api/data');
            expect.fail('should throw');
        } catch (e) {
            expect(e.code).toBe(AuthErrorCode.SESSION_EXPIRED);
        }
    });
});
