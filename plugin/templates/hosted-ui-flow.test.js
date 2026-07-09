/**
 * L42 Cognito Passkey - Hosted UI (OAuth) flow selection tests
 *
 * Design review #2/#6/#11: the backend-callback OAuth flow was broken (the
 * client sent a PKCE challenge the backend could never complete, and state was
 * never validated). loginWithHostedUI now has two coherent flows:
 *   - loginEndpoint set  -> redirect to the backend, which owns state + PKCE
 *   - loginEndpoint unset -> client-owned PKCE flow, direct to Cognito
 * and it refuses the known-broken oauthCallbackUrl-without-loginEndpoint combo.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
    configure,
    loginWithHostedUI,
    AuthError,
    AuthErrorCode,
    _resetForTesting
} from '../../src/auth.js';

const BASE = {
    clientId: 'test-client',
    cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
    cognitoRegion: 'us-west-2',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    sessionEndpoint: '/auth/session'
};

describe('loginWithHostedUI flow selection', () => {
    let assignedHref;

    beforeEach(() => {
        _resetForTesting();
        assignedHref = null;
        // jsdom: intercept navigation
        delete window.location;
        window.location = { origin: 'https://app.example.com', href: '' };
        Object.defineProperty(window.location, 'href', {
            set: (v) => { assignedHref = v; },
            get: () => assignedHref || ''
        });
    });

    afterEach(() => vi.restoreAllMocks());

    it('backend-owned: redirects to loginEndpoint, carries no PKCE challenge', async () => {
        configure({ ...BASE, oauthCallbackUrl: '/auth/callback', loginEndpoint: '/auth/login' });

        await loginWithHostedUI('user@example.com');

        expect(assignedHref).toContain('/auth/login');
        expect(assignedHref).toContain('email=user%40example.com');
        // The client must NOT build a Cognito URL or a code_challenge here
        expect(assignedHref).not.toContain('cognito');
        expect(assignedHref).not.toContain('code_challenge');
    });

    it('client-owned: redirects to Cognito with a PKCE challenge when no loginEndpoint', async () => {
        configure({ ...BASE });

        await loginWithHostedUI();

        expect(assignedHref).toContain('test.auth.us-west-2.amazoncognito.com/oauth2/authorize');
        expect(assignedHref).toContain('code_challenge=');
        expect(assignedHref).toContain('code_challenge_method=S256');
        expect(assignedHref).toContain('state=');
    });

    it('refuses oauthCallbackUrl without loginEndpoint (the known-broken combo)', async () => {
        configure({ ...BASE, oauthCallbackUrl: '/auth/callback' });

        await expect(loginWithHostedUI()).rejects.toMatchObject({
            code: AuthErrorCode.INVALID_CONFIG
        });
    });
});
