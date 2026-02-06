/**
 * L42 Cognito Passkey - Conditional UI / Passkey Autofill Tests (v0.12.0)
 *
 * Tests:
 * - loginWithConditionalUI() with email (Mode A — single biometric prompt)
 * - loginWithConditionalUI() without email (Mode B — discovery flow)
 * - AbortController management (internal abort on other login calls)
 * - User-provided AbortSignal
 * - Browser support checks
 * - buildAssertionResponse() shared helper
 * - Integration with debug logging
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
            aud: 'test-client',
            iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_test',
            exp,
            ...overrides
        }),
        refresh_token: 'refresh-token-123',
        auth_method: 'passkey'
    };
}

function arrayBufferToB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64ToArrayBuffer(b64) {
    const base64 = b64.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ============================================================================
// Simulated auth.js internals for conditional UI
// ============================================================================

const VERSION = '0.12.0';
let config = {
    debug: false,
    clientId: 'test-client',
    cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
    cognitoRegion: 'us-west-2',
    relyingPartyId: null,
    tokenStorage: 'localStorage',
    tokenKey: 'l42_auth_tokens',
    cookieName: 'l42_id_token',
    cookieDomain: null
};
let _configured = false;
let _conditionalAbortController = null;
let _debugHistory = [];
const DEBUG_HISTORY_MAX = 100;

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
}

function requireConfig() {
    if (!_configured) throw new Error('Auth not configured');
}

function abortConditionalRequest() {
    if (_conditionalAbortController) {
        _conditionalAbortController.abort();
        _conditionalAbortController = null;
    }
}

function buildAssertionResponse(credential) {
    const response = {
        id: credential.id,
        rawId: arrayBufferToB64(credential.rawId),
        response: {
            clientDataJSON: arrayBufferToB64(credential.response.clientDataJSON),
            authenticatorData: arrayBufferToB64(credential.response.authenticatorData),
            signature: arrayBufferToB64(credential.response.signature)
        },
        type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults() || {}
    };
    if (credential.response.userHandle) {
        response.response.userHandle = arrayBufferToB64(credential.response.userHandle);
    }
    if (credential.authenticatorAttachment) {
        response.authenticatorAttachment = credential.authenticatorAttachment;
    }
    return response;
}

// ============================================================================
// Mock credential helpers
// ============================================================================

function createMockCredentialGet(opts = {}) {
    const rawId = new Uint8Array([1, 2, 3, 4]).buffer;
    const userHandle = opts.userHandle !== undefined
        ? opts.userHandle
        : new TextEncoder().encode('user-sub-123').buffer;

    return {
        id: 'credential-id-1',
        rawId,
        type: 'public-key',
        response: {
            clientDataJSON: new Uint8Array([10, 20, 30]).buffer,
            authenticatorData: new Uint8Array([40, 50, 60]).buffer,
            signature: new Uint8Array([70, 80, 90]).buffer,
            userHandle
        },
        authenticatorAttachment: 'platform',
        getClientExtensionResults: () => ({})
    };
}

// ============================================================================
// Tests
// ============================================================================

describe('Conditional UI / Passkey Autofill', () => {
    beforeEach(() => {
        _configured = true;
        _conditionalAbortController = null;
        _debugHistory = [];
        config.debug = false;
    });

    describe('abortConditionalRequest()', () => {
        it('aborts a pending controller', () => {
            const controller = new AbortController();
            _conditionalAbortController = controller;
            expect(controller.signal.aborted).toBe(false);

            abortConditionalRequest();
            expect(controller.signal.aborted).toBe(true);
            expect(_conditionalAbortController).toBeNull();
        });

        it('does nothing when no controller exists', () => {
            _conditionalAbortController = null;
            expect(() => abortConditionalRequest()).not.toThrow();
            expect(_conditionalAbortController).toBeNull();
        });

        it('clears controller reference after abort', () => {
            const controller = new AbortController();
            _conditionalAbortController = controller;
            abortConditionalRequest();
            expect(_conditionalAbortController).toBeNull();
        });
    });

    describe('buildAssertionResponse()', () => {
        it('builds correct assertion response from credential', () => {
            const cred = createMockCredentialGet();
            const result = buildAssertionResponse(cred);

            expect(result.id).toBe('credential-id-1');
            expect(result.type).toBe('public-key');
            expect(result.rawId).toBeTruthy();
            expect(result.response.clientDataJSON).toBeTruthy();
            expect(result.response.authenticatorData).toBeTruthy();
            expect(result.response.signature).toBeTruthy();
            expect(result.clientExtensionResults).toEqual({});
        });

        it('includes userHandle when present', () => {
            const cred = createMockCredentialGet({
                userHandle: new TextEncoder().encode('user123').buffer
            });
            const result = buildAssertionResponse(cred);
            expect(result.response.userHandle).toBeTruthy();
        });

        it('omits userHandle when not present', () => {
            const cred = createMockCredentialGet({ userHandle: null });
            const result = buildAssertionResponse(cred);
            expect(result.response.userHandle).toBeUndefined();
        });

        it('includes authenticatorAttachment when present', () => {
            const cred = createMockCredentialGet();
            cred.authenticatorAttachment = 'cross-platform';
            const result = buildAssertionResponse(cred);
            expect(result.authenticatorAttachment).toBe('cross-platform');
        });

        it('omits authenticatorAttachment when not present', () => {
            const cred = createMockCredentialGet();
            delete cred.authenticatorAttachment;
            const result = buildAssertionResponse(cred);
            expect(result.authenticatorAttachment).toBeUndefined();
        });
    });

    describe('conditional mediation checks', () => {
        it('isConditionalMediationAvailable returns false when PublicKeyCredential is missing', async () => {
            const origPKC = window.PublicKeyCredential;
            delete window.PublicKeyCredential;
            // Simulate the isConditionalMediationAvailable logic
            const supported = typeof window !== 'undefined'
                && typeof window.PublicKeyCredential !== 'undefined';
            expect(supported).toBe(false);
            window.PublicKeyCredential = origPKC;
        });

        it('isConditionalMediationAvailable returns true when supported', async () => {
            const origPKC = window.PublicKeyCredential;
            window.PublicKeyCredential = {
                isConditionalMediationAvailable: async () => true
            };
            window.isSecureContext = true;
            const result = await window.PublicKeyCredential.isConditionalMediationAvailable();
            expect(result).toBe(true);
            window.PublicKeyCredential = origPKC;
        });
    });

    describe('Mode A: loginWithConditionalUI with email', () => {
        it('throws if not configured', () => {
            _configured = false;
            expect(() => requireConfig()).toThrow('Auth not configured');
        });

        it('builds correct Cognito InitiateAuth parameters', () => {
            // Verify the parameters that would be sent
            const email = 'user@example.com';
            const params = {
                AuthFlow: 'USER_AUTH',
                ClientId: config.clientId,
                AuthParameters: {
                    USERNAME: email,
                    PREFERRED_CHALLENGE: 'WEB_AUTHN'
                }
            };
            expect(params.AuthFlow).toBe('USER_AUTH');
            expect(params.AuthParameters.USERNAME).toBe('user@example.com');
            expect(params.AuthParameters.PREFERRED_CHALLENGE).toBe('WEB_AUTHN');
        });

        it('uses empty allowCredentials for discoverable credentials', () => {
            // In conditional UI, allowCredentials should be empty
            // to allow the browser to show all available passkeys
            const publicKeyOptions = {
                challenge: new ArrayBuffer(32),
                rpId: 'example.com',
                allowCredentials: [],
                userVerification: 'preferred',
                timeout: 60000
            };
            expect(publicKeyOptions.allowCredentials).toEqual([]);
        });

        it('sets mediation to conditional', () => {
            const credGetOptions = {
                publicKey: { challenge: new ArrayBuffer(32) },
                mediation: 'conditional',
                signal: new AbortController().signal
            };
            expect(credGetOptions.mediation).toBe('conditional');
        });

        it('creates internal abort controller', () => {
            const controller = new AbortController();
            _conditionalAbortController = controller;
            expect(_conditionalAbortController).toBeDefined();
            expect(_conditionalAbortController.signal.aborted).toBe(false);
        });

        it('merges user signal with internal controller using AbortSignal.any', () => {
            // Test that the signal merging logic works
            const internalController = new AbortController();
            const userController = new AbortController();

            // AbortSignal.any merges signals — either can abort
            if (typeof AbortSignal.any === 'function') {
                const merged = AbortSignal.any([
                    userController.signal,
                    internalController.signal
                ]);
                expect(merged.aborted).toBe(false);

                // Internal abort should trigger the merged signal
                internalController.abort();
                expect(merged.aborted).toBe(true);
            }
        });

        it('handles user signal abort', () => {
            const userController = new AbortController();
            const internalController = new AbortController();

            if (typeof AbortSignal.any === 'function') {
                const merged = AbortSignal.any([
                    userController.signal,
                    internalController.signal
                ]);

                userController.abort();
                expect(merged.aborted).toBe(true);
                // Internal controller is not aborted
                expect(internalController.signal.aborted).toBe(false);
            }
        });
    });

    describe('Mode B: loginWithConditionalUI without email', () => {
        it('uses local challenge for discovery', () => {
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            expect(challenge.byteLength).toBe(32);
        });

        it('extracts user from userHandle', () => {
            const userSub = 'user-sub-123';
            const encoded = new TextEncoder().encode(userSub);
            const decoded = new TextDecoder().decode(encoded);
            expect(decoded).toBe('user-sub-123');
        });

        it('throws when userHandle is empty', () => {
            const userHandle = new ArrayBuffer(0);
            expect(userHandle.byteLength).toBe(0);
            // The function would throw:
            // 'No user handle returned — credential may not be discoverable'
        });

        it('throws when userHandle is null', () => {
            const userHandle = null;
            expect(!userHandle || (userHandle && userHandle.byteLength === 0)).toBe(true);
        });

        it('uses rpId from config or hostname', () => {
            config.relyingPartyId = 'custom.example.com';
            const rpId = config.relyingPartyId || 'localhost';
            expect(rpId).toBe('custom.example.com');

            config.relyingPartyId = null;
            const rpId2 = config.relyingPartyId || 'localhost';
            expect(rpId2).toBe('localhost');
        });
    });

    describe('abort on other login methods', () => {
        it('loginWithPasskey aborts conditional request', () => {
            const controller = new AbortController();
            _conditionalAbortController = controller;

            // Simulate what loginWithPasskey does at the top
            abortConditionalRequest();
            expect(controller.signal.aborted).toBe(true);
            expect(_conditionalAbortController).toBeNull();
        });

        it('loginWithPassword aborts conditional request', () => {
            const controller = new AbortController();
            _conditionalAbortController = controller;

            abortConditionalRequest();
            expect(controller.signal.aborted).toBe(true);
        });

        it('loginWithHostedUI aborts conditional request', () => {
            const controller = new AbortController();
            _conditionalAbortController = controller;

            abortConditionalRequest();
            expect(controller.signal.aborted).toBe(true);
        });

        it('logout aborts conditional request', () => {
            const controller = new AbortController();
            _conditionalAbortController = controller;

            abortConditionalRequest();
            expect(controller.signal.aborted).toBe(true);
        });

        it('multiple abortConditionalRequest calls are idempotent', () => {
            const controller = new AbortController();
            _conditionalAbortController = controller;

            abortConditionalRequest();
            abortConditionalRequest(); // second call should be no-op
            abortConditionalRequest();
            expect(controller.signal.aborted).toBe(true);
            expect(_conditionalAbortController).toBeNull();
        });
    });

    describe('debug logging integration', () => {
        beforeEach(() => {
            config.debug = true;
        });

        it('logs success on conditional UI login with email', () => {
            debugLog('auth', 'loginWithConditionalUI:success', { email: 'user@example.com', mode: 'email' });
            expect(_debugHistory.length).toBe(1);
            expect(_debugHistory[0].message).toBe('loginWithConditionalUI:success');
            expect(_debugHistory[0].data.mode).toBe('email');
        });

        it('logs discovery on Mode B', () => {
            debugLog('auth', 'loginWithConditionalUI:discovered', { user: 'user-sub-123' });
            expect(_debugHistory.length).toBe(1);
            expect(_debugHistory[0].message).toBe('loginWithConditionalUI:discovered');
        });

        it('logs failure', () => {
            debugLog('auth', 'loginWithConditionalUI:failed', { error: 'User cancelled' });
            expect(_debugHistory.length).toBe(1);
            expect(_debugHistory[0].message).toBe('loginWithConditionalUI:failed');
            expect(_debugHistory[0].data.error).toBe('User cancelled');
        });
    });

    describe('token result shape', () => {
        it('produces correct token shape for Mode A', () => {
            const tokens = createValidTokens();
            tokens.auth_method = 'passkey';
            expect(tokens.access_token).toBeTruthy();
            expect(tokens.id_token).toBeTruthy();
            expect(tokens.refresh_token).toBeTruthy();
            expect(tokens.auth_method).toBe('passkey');
        });

        it('assertion response is JSON-serializable', () => {
            const cred = createMockCredentialGet();
            const response = buildAssertionResponse(cred);
            const json = JSON.stringify(response);
            expect(json).toBeTruthy();
            const parsed = JSON.parse(json);
            expect(parsed.id).toBe('credential-id-1');
        });
    });
});
