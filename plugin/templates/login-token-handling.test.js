/**
 * L42 Cognito Passkey - Login token-handling tests
 *
 * Exercises the REAL loginWithPassword flow end-to-end (design review #14 flagged
 * that no test ever calls it). Verifies the Token Handler invariant (design
 * review #5) and login ordering (#16):
 *   - the refresh_token is handed to the server but never returned/cached/broadcast
 *   - the server session is persisted BEFORE auth-state is broadcast
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
    configure,
    loginWithPassword,
    onLogin,
    onAuthStateChange,
    getUserEmail,
    _resetForTesting
} from '../../src/auth.js';

function jwt(claims) {
    const enc = (o) => btoa(JSON.stringify(o))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return `${enc({ alg: 'RS256', typ: 'JWT' })}.${enc(claims)}.sig`;
}

function cognitoTokens() {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    return {
        AccessToken: jwt({ sub: 'u', client_id: 'test-client', exp }),
        IdToken: jwt({
            sub: 'u', email: 'user@example.com',
            aud: 'test-client',
            iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_t', exp
        }),
        RefreshToken: 'super-secret-refresh-token'
    };
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

describe('loginWithPassword token handling', () => {
    beforeEach(() => {
        _resetForTesting();
        configureForTest();
    });

    afterEach(() => vi.restoreAllMocks());

    it('hands refresh_token to the server but never returns it', async () => {
        let sessionBody = null;
        global.fetch = vi.fn((url, opts) => {
            if (typeof url === 'string' && url.includes('cognito-idp')) {
                return Promise.resolve({
                    ok: true, status: 200,
                    json: () => Promise.resolve({ AuthenticationResult: cognitoTokens() })
                });
            }
            if (typeof url === 'string' && url.includes('/auth/session')) {
                sessionBody = JSON.parse(opts.body);
                return Promise.resolve({ ok: true, status: 200 });
            }
            return Promise.resolve({ ok: true, status: 200 });
        });

        const result = await loginWithPassword('user@example.com', 'pw');

        // Returned tokens: access + id, but NO refresh_token
        expect(result.access_token).toBeTruthy();
        expect(result.id_token).toBeTruthy();
        expect(result.refresh_token).toBeUndefined();

        // Server DID receive the refresh_token (persisted server-side)
        expect(sessionBody.refresh_token).toBe('super-secret-refresh-token');
    });

    it('does not leak refresh_token to onLogin listeners', async () => {
        global.fetch = vi.fn((url) => {
            if (typeof url === 'string' && url.includes('cognito-idp')) {
                return Promise.resolve({
                    ok: true, status: 200,
                    json: () => Promise.resolve({ AuthenticationResult: cognitoTokens() })
                });
            }
            return Promise.resolve({ ok: true, status: 200 });
        });

        let received = null;
        onLogin((tokens) => { received = tokens; });

        await loginWithPassword('user@example.com', 'pw');

        expect(received).toBeTruthy();
        expect(received.refresh_token).toBeUndefined();
        expect(received.access_token).toBeTruthy();
    });

    it('persists the server session before broadcasting auth-state', async () => {
        const order = [];
        global.fetch = vi.fn((url) => {
            if (typeof url === 'string' && url.includes('cognito-idp')) {
                return Promise.resolve({
                    ok: true, status: 200,
                    json: () => Promise.resolve({ AuthenticationResult: cognitoTokens() })
                });
            }
            if (typeof url === 'string' && url.includes('/auth/session')) {
                order.push('persist');
                return Promise.resolve({ ok: true, status: 200 });
            }
            return Promise.resolve({ ok: true, status: 200 });
        });

        onAuthStateChange((isAuth) => { if (isAuth) order.push('authState'); });

        await loginWithPassword('user@example.com', 'pw');

        // Session persisted before the authenticated-state broadcast
        expect(order).toEqual(['persist', 'authState']);
    });

    it('does not cache a login when the server session fails to persist', async () => {
        global.fetch = vi.fn((url) => {
            if (typeof url === 'string' && url.includes('cognito-idp')) {
                return Promise.resolve({
                    ok: true, status: 200,
                    json: () => Promise.resolve({ AuthenticationResult: cognitoTokens() })
                });
            }
            if (typeof url === 'string' && url.includes('/auth/session')) {
                return Promise.resolve({ ok: false, status: 500 });
            }
            return Promise.resolve({ ok: true, status: 200 });
        });

        await expect(loginWithPassword('user@example.com', 'pw')).rejects.toThrow();

        // Persist failed before caching — no half-logged-in state
        expect(getUserEmail()).toBeNull();
    });
});
