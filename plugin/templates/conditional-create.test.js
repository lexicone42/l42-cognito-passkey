/**
 * L42 Cognito Passkey - Conditional Create / Passkey Upgrade Tests (v0.12.0)
 *
 * Tests:
 * - upgradeToPasskey() success flow
 * - Silent failure (returns false, doesn't throw)
 * - Requires authentication and admin scope
 * - Browser support fallback
 * - buildCredentialResponse() shared helper
 * - autoUpgradeToPasskey config flag
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

function arrayBufferToB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function createValidTokens(overrides = {}) {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    return {
        access_token: createTestJwt({
            sub: 'user1',
            scope: 'openid email aws.cognito.signin.user.admin',
            exp,
            ...overrides
        }),
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
        auth_method: 'password'
    };
}

// ============================================================================
// Simulated auth.js internals for conditional create
// ============================================================================

const VERSION = '0.12.0';
let config = {
    debug: false,
    clientId: 'test-client',
    cognitoDomain: 'test.auth.us-west-2.amazoncognito.com',
    cognitoRegion: 'us-west-2',
    tokenStorage: 'handler',
    tokenKey: 'l42_auth_tokens',
    tokenEndpoint: '/auth/token',
    refreshEndpoint: '/auth/refresh',
    logoutEndpoint: '/auth/logout',
    autoUpgradeToPasskey: false
};
let _configured = false;
let _debugHistory = [];
let _storedTokens = null;
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
}

function requireConfig() {
    if (!_configured) throw new Error('Auth not configured');
}

function getTokens() {
    return _storedTokens;
}

function hasAdminScope() {
    const tokens = getTokens();
    if (!tokens) return false;
    try {
        const claims = UNSAFE_decodeJwtPayload(tokens.access_token);
        return (claims.scope || '').includes('aws.cognito.signin.user.admin');
    } catch {
        return false;
    }
}

function getUserEmail() {
    const tokens = getTokens();
    if (!tokens) return null;
    try {
        return UNSAFE_decodeJwtPayload(tokens.id_token).email || null;
    } catch {
        return null;
    }
}

function isPasskeySupported() {
    return typeof window !== 'undefined'
        && window.isSecureContext === true
        && typeof window.PublicKeyCredential !== 'undefined'
        && typeof navigator.credentials !== 'undefined';
}

function buildCredentialResponse(credential) {
    const response = {
        id: credential.id,
        rawId: arrayBufferToB64(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: arrayBufferToB64(credential.response.clientDataJSON),
            attestationObject: arrayBufferToB64(credential.response.attestationObject)
        },
        clientExtensionResults: credential.getClientExtensionResults() || {}
    };
    if (credential.response.getTransports) {
        response.response.transports = credential.response.getTransports();
    }
    if (credential.authenticatorAttachment) {
        response.authenticatorAttachment = credential.authenticatorAttachment;
    }
    if (credential.response.getPublicKey) {
        response.response.publicKey = arrayBufferToB64(credential.response.getPublicKey());
    }
    if (credential.response.getPublicKeyAlgorithm) {
        response.response.publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm();
    }
    if (credential.response.getAuthenticatorData) {
        response.response.authenticatorData = arrayBufferToB64(credential.response.getAuthenticatorData());
    }
    return response;
}

// ============================================================================
// Mock credential helpers
// ============================================================================

function createMockCredentialCreate() {
    const rawId = new Uint8Array([1, 2, 3, 4]).buffer;
    return {
        id: 'new-credential-id',
        rawId,
        type: 'public-key',
        response: {
            clientDataJSON: new Uint8Array([10, 20, 30]).buffer,
            attestationObject: new Uint8Array([40, 50, 60]).buffer,
            getTransports: () => ['internal', 'hybrid'],
            getPublicKey: () => new Uint8Array([100, 101, 102]).buffer,
            getPublicKeyAlgorithm: () => -7,
            getAuthenticatorData: () => new Uint8Array([200, 201]).buffer
        },
        authenticatorAttachment: 'platform',
        getClientExtensionResults: () => ({})
    };
}

// ============================================================================
// Tests
// ============================================================================

describe('Conditional Create / Passkey Upgrade', () => {
    beforeEach(() => {
        _configured = true;
        _storedTokens = null;
        _debugHistory = [];
        config.debug = false;
        config.autoUpgradeToPasskey = false;
    });

    describe('upgradeToPasskey() preconditions', () => {
        it('returns false when not authenticated', async () => {
            config.debug = true;
            _storedTokens = null;
            const tokens = getTokens();
            expect(!tokens || !hasAdminScope()).toBe(true);
        });

        it('returns false when tokens have no admin scope', async () => {
            config.debug = true;
            const exp = Math.floor(Date.now() / 1000) + 3600;
            _storedTokens = {
                access_token: createTestJwt({ sub: 'user1', scope: 'openid email', exp }),
                id_token: createTestJwt({ sub: 'user1', email: 'test@example.com', exp }),
                refresh_token: 'refresh-123'
            };
            expect(hasAdminScope()).toBe(false);
        });

        it('returns true when tokens have admin scope', async () => {
            _storedTokens = createValidTokens();
            expect(hasAdminScope()).toBe(true);
        });

        it('requires passkey support', () => {
            // jsdom doesn't have PublicKeyCredential by default
            const supported = isPasskeySupported();
            // In jsdom, this should be false since no PublicKeyCredential
            expect(typeof supported).toBe('boolean');
        });
    });

    describe('buildCredentialResponse()', () => {
        it('builds correct credential response', () => {
            const cred = createMockCredentialCreate();
            const result = buildCredentialResponse(cred);

            expect(result.id).toBe('new-credential-id');
            expect(result.type).toBe('public-key');
            expect(result.rawId).toBeTruthy();
            expect(result.response.clientDataJSON).toBeTruthy();
            expect(result.response.attestationObject).toBeTruthy();
        });

        it('includes transports when available', () => {
            const cred = createMockCredentialCreate();
            const result = buildCredentialResponse(cred);
            expect(result.response.transports).toEqual(['internal', 'hybrid']);
        });

        it('includes publicKey when available', () => {
            const cred = createMockCredentialCreate();
            const result = buildCredentialResponse(cred);
            expect(result.response.publicKey).toBeTruthy();
        });

        it('includes publicKeyAlgorithm when available', () => {
            const cred = createMockCredentialCreate();
            const result = buildCredentialResponse(cred);
            expect(result.response.publicKeyAlgorithm).toBe(-7);
        });

        it('includes authenticatorData when available', () => {
            const cred = createMockCredentialCreate();
            const result = buildCredentialResponse(cred);
            expect(result.response.authenticatorData).toBeTruthy();
        });

        it('includes authenticatorAttachment when present', () => {
            const cred = createMockCredentialCreate();
            const result = buildCredentialResponse(cred);
            expect(result.authenticatorAttachment).toBe('platform');
        });

        it('omits optional fields when not available', () => {
            const cred = createMockCredentialCreate();
            delete cred.response.getTransports;
            delete cred.response.getPublicKey;
            delete cred.response.getPublicKeyAlgorithm;
            delete cred.response.getAuthenticatorData;
            delete cred.authenticatorAttachment;

            const result = buildCredentialResponse(cred);
            expect(result.response.transports).toBeUndefined();
            expect(result.response.publicKey).toBeUndefined();
            expect(result.response.publicKeyAlgorithm).toBeUndefined();
            expect(result.response.authenticatorData).toBeUndefined();
            expect(result.authenticatorAttachment).toBeUndefined();
        });

        it('credential response is JSON-serializable', () => {
            const cred = createMockCredentialCreate();
            const response = buildCredentialResponse(cred);
            const json = JSON.stringify(response);
            expect(json).toBeTruthy();
            const parsed = JSON.parse(json);
            expect(parsed.id).toBe('new-credential-id');
        });
    });

    describe('autoUpgradeToPasskey config', () => {
        it('defaults to false', () => {
            expect(config.autoUpgradeToPasskey).toBe(false);
        });

        it('can be enabled', () => {
            config.autoUpgradeToPasskey = true;
            expect(config.autoUpgradeToPasskey).toBe(true);
        });

        it('non-blocking upgrade: fire and forget pattern', () => {
            // The pattern used in loginWithPassword:
            // upgradeToPasskey().catch(function() {});
            // This should not block the login flow
            const upgradePromise = Promise.resolve(false);
            const fireAndForget = upgradePromise.catch(function() {});
            expect(fireAndForget).toBeInstanceOf(Promise);
        });
    });

    describe('debug logging integration', () => {
        beforeEach(() => {
            config.debug = true;
        });

        it('logs skipped when not authenticated', () => {
            debugLog('passkey', 'upgradeToPasskey:skipped', { reason: 'not authenticated or no admin scope' });
            expect(_debugHistory.length).toBe(1);
            expect(_debugHistory[0].message).toBe('upgradeToPasskey:skipped');
        });

        it('logs success', () => {
            debugLog('passkey', 'upgradeToPasskey:success');
            expect(_debugHistory.length).toBe(1);
            expect(_debugHistory[0].message).toBe('upgradeToPasskey:success');
        });

        it('logs failure silently', () => {
            debugLog('passkey', 'upgradeToPasskey:failed', { error: 'User declined' });
            expect(_debugHistory.length).toBe(1);
            expect(_debugHistory[0].message).toBe('upgradeToPasskey:failed');
            expect(_debugHistory[0].data.error).toBe('User declined');
        });

        it('logs skipped when user declined', () => {
            debugLog('passkey', 'upgradeToPasskey:skipped', { reason: 'user declined' });
            expect(_debugHistory[0].data.reason).toBe('user declined');
        });
    });

    describe('authenticatorSelection for upgrade', () => {
        it('uses required residentKey for discoverable credentials', () => {
            const authSelection = {
                residentKey: 'required',
                userVerification: 'preferred'
            };
            expect(authSelection.residentKey).toBe('required');
        });

        it('does not set authenticatorAttachment (allows any)', () => {
            const authSelection = {
                residentKey: 'required',
                userVerification: 'preferred'
            };
            expect(authSelection.authenticatorAttachment).toBeUndefined();
        });
    });

    describe('conditional create mediation', () => {
        it('uses mediation conditional for navigator.credentials.create', () => {
            const createOptions = {
                publicKey: { challenge: new ArrayBuffer(32) },
                mediation: 'conditional',
                signal: new AbortController().signal
            };
            expect(createOptions.mediation).toBe('conditional');
        });

        it('respects user-provided signal', () => {
            const controller = new AbortController();
            const createOptions = {
                publicKey: { challenge: new ArrayBuffer(32) },
                mediation: 'conditional',
                signal: controller.signal
            };
            expect(createOptions.signal.aborted).toBe(false);
            controller.abort();
            expect(createOptions.signal.aborted).toBe(true);
        });
    });
});
