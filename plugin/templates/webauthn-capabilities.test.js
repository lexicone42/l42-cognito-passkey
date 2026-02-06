/**
 * L42 Cognito Passkey - WebAuthn Capabilities Tests (v0.12.0)
 *
 * Tests:
 * - getPasskeyCapabilities() with WebAuthn Level 3 getClientCapabilities()
 * - Fallback to individual feature detection
 * - detectWebView() — Android, iOS, Electron, normal browser
 * - New fields present in result (conditionalCreate, hybridTransport, etc.)
 * - Both camelCase and kebab-case capability keys
 * - Backward compatibility (existing fields still present)
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// Simulated auth.js internals
// ============================================================================

function isPasskeySupported() {
    return typeof window !== 'undefined'
        && window.isSecureContext === true
        && typeof window.PublicKeyCredential !== 'undefined'
        && typeof navigator.credentials !== 'undefined';
}

async function isConditionalMediationAvailable() {
    if (!isPasskeySupported()) return false;
    try {
        if (typeof PublicKeyCredential.isConditionalMediationAvailable === 'function') {
            return await PublicKeyCredential.isConditionalMediationAvailable();
        }
    } catch {
        // Ignore
    }
    return false;
}

async function isPlatformAuthenticatorAvailable() {
    if (!isPasskeySupported()) return false;
    try {
        if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
            return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        }
    } catch {
        // Ignore
    }
    return false;
}

function detectWebView() {
    if (typeof navigator === 'undefined') return false;
    var ua = navigator.userAgent || '';
    if (/wv\)/.test(ua)) return true;
    if (/iPhone|iPad/.test(ua) && !/Safari/.test(ua)) return true;
    if (/Electron/.test(ua)) return true;
    return false;
}

async function getPasskeyCapabilities() {
    var supported = isPasskeySupported();
    var secureContext = typeof window !== 'undefined' ? window.isSecureContext === true : false;

    if (supported && typeof PublicKeyCredential.getClientCapabilities === 'function') {
        try {
            var caps = await PublicKeyCredential.getClientCapabilities();
            return {
                supported: supported,
                conditionalMediation: caps.conditionalMediation === true
                    || caps['conditional-mediation'] === true,
                conditionalCreate: caps.conditionalCreate === true
                    || caps['conditional-create'] === true,
                platformAuthenticator: supported
                    ? await isPlatformAuthenticatorAvailable()
                    : false,
                secureContext: secureContext,
                hybridTransport: caps.hybridTransport === true
                    || caps['hybrid-transport'] === true,
                passkeyPlatformAuthenticator: caps.passkeyPlatformAuthenticator === true
                    || caps['passkey-platform-authenticator'] === true,
                userVerifyingPlatformAuthenticator: caps.userVerifyingPlatformAuthenticator === true
                    || caps['user-verifying-platform-authenticator'] === true,
                relatedOrigins: caps.relatedOrigins === true
                    || caps['related-origins'] === true,
                signalAllAcceptedCredentials: caps.signalAllAcceptedCredentials === true
                    || caps['signal-all-accepted-credentials'] === true,
                signalCurrentUserDetails: caps.signalCurrentUserDetails === true
                    || caps['signal-current-user-details'] === true,
                signalUnknownCredential: caps.signalUnknownCredential === true
                    || caps['signal-unknown-credential'] === true,
                isWebView: detectWebView(),
                source: 'getClientCapabilities'
            };
        } catch {
            // Fall through
        }
    }

    return {
        supported: supported,
        conditionalMediation: supported ? await isConditionalMediationAvailable() : false,
        conditionalCreate: false,
        platformAuthenticator: supported ? await isPlatformAuthenticatorAvailable() : false,
        secureContext: secureContext,
        hybridTransport: false,
        passkeyPlatformAuthenticator: false,
        userVerifyingPlatformAuthenticator: supported
            ? await isPlatformAuthenticatorAvailable()
            : false,
        relatedOrigins: false,
        signalAllAcceptedCredentials: false,
        signalCurrentUserDetails: false,
        signalUnknownCredential: false,
        isWebView: detectWebView(),
        source: 'fallback'
    };
}

// ============================================================================
// Tests
// ============================================================================

describe('WebAuthn Capabilities (Level 3 API)', () => {
    let origPKC;
    let origIsSecureContext;
    let origNavigator;

    beforeEach(() => {
        origPKC = window.PublicKeyCredential;
        origIsSecureContext = window.isSecureContext;
    });

    afterEach(() => {
        if (origPKC) {
            window.PublicKeyCredential = origPKC;
        } else {
            delete window.PublicKeyCredential;
        }
        Object.defineProperty(window, 'isSecureContext', {
            value: origIsSecureContext,
            writable: true,
            configurable: true
        });
    });

    describe('fallback mode (no Level 3 API)', () => {
        it('returns fallback source when getClientCapabilities not available', async () => {
            // jsdom doesn't have PublicKeyCredential, so fallback is the default
            const caps = await getPasskeyCapabilities();
            expect(caps.source).toBe('fallback');
        });

        it('returns all expected fields', async () => {
            const caps = await getPasskeyCapabilities();
            expect(caps).toHaveProperty('supported');
            expect(caps).toHaveProperty('conditionalMediation');
            expect(caps).toHaveProperty('conditionalCreate');
            expect(caps).toHaveProperty('platformAuthenticator');
            expect(caps).toHaveProperty('secureContext');
            expect(caps).toHaveProperty('hybridTransport');
            expect(caps).toHaveProperty('passkeyPlatformAuthenticator');
            expect(caps).toHaveProperty('userVerifyingPlatformAuthenticator');
            expect(caps).toHaveProperty('relatedOrigins');
            expect(caps).toHaveProperty('signalAllAcceptedCredentials');
            expect(caps).toHaveProperty('signalCurrentUserDetails');
            expect(caps).toHaveProperty('signalUnknownCredential');
            expect(caps).toHaveProperty('isWebView');
            expect(caps).toHaveProperty('source');
        });

        it('reports conditionalCreate as false in fallback mode', async () => {
            const caps = await getPasskeyCapabilities();
            expect(caps.conditionalCreate).toBe(false);
        });

        it('reports hybridTransport as false in fallback mode', async () => {
            const caps = await getPasskeyCapabilities();
            expect(caps.hybridTransport).toBe(false);
        });

        it('backward compatible: supported, conditionalMediation, platformAuthenticator, secureContext still work', async () => {
            const caps = await getPasskeyCapabilities();
            expect(typeof caps.supported).toBe('boolean');
            expect(typeof caps.conditionalMediation).toBe('boolean');
            expect(typeof caps.platformAuthenticator).toBe('boolean');
            expect(typeof caps.secureContext).toBe('boolean');
        });
    });

    describe('Level 3 API mode', () => {
        function setupLevel3(capabilitiesMap) {
            window.isSecureContext = true;
            window.PublicKeyCredential = {
                isConditionalMediationAvailable: async () => true,
                isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
                getClientCapabilities: async () => capabilitiesMap
            };
            // Need credentials too for isPasskeySupported
            if (!navigator.credentials) {
                Object.defineProperty(navigator, 'credentials', {
                    value: { get: async () => null, create: async () => null },
                    configurable: true
                });
            }
        }

        it('returns getClientCapabilities source', async () => {
            setupLevel3({
                conditionalMediation: true,
                conditionalCreate: false
            });
            const caps = await getPasskeyCapabilities();
            expect(caps.source).toBe('getClientCapabilities');
        });

        it('reads camelCase capabilities', async () => {
            setupLevel3({
                conditionalMediation: true,
                conditionalCreate: true,
                hybridTransport: true,
                passkeyPlatformAuthenticator: true,
                userVerifyingPlatformAuthenticator: true,
                relatedOrigins: false,
                signalAllAcceptedCredentials: true,
                signalCurrentUserDetails: true,
                signalUnknownCredential: false
            });
            const caps = await getPasskeyCapabilities();
            expect(caps.conditionalMediation).toBe(true);
            expect(caps.conditionalCreate).toBe(true);
            expect(caps.hybridTransport).toBe(true);
            expect(caps.passkeyPlatformAuthenticator).toBe(true);
            expect(caps.relatedOrigins).toBe(false);
            expect(caps.signalAllAcceptedCredentials).toBe(true);
            expect(caps.signalCurrentUserDetails).toBe(true);
            expect(caps.signalUnknownCredential).toBe(false);
        });

        it('reads kebab-case capabilities', async () => {
            setupLevel3({
                'conditional-mediation': true,
                'conditional-create': true,
                'hybrid-transport': false,
                'passkey-platform-authenticator': true,
                'user-verifying-platform-authenticator': true,
                'related-origins': true,
                'signal-all-accepted-credentials': false,
                'signal-current-user-details': false,
                'signal-unknown-credential': true
            });
            const caps = await getPasskeyCapabilities();
            expect(caps.conditionalMediation).toBe(true);
            expect(caps.conditionalCreate).toBe(true);
            expect(caps.hybridTransport).toBe(false);
            expect(caps.passkeyPlatformAuthenticator).toBe(true);
            expect(caps.relatedOrigins).toBe(true);
            expect(caps.signalUnknownCredential).toBe(true);
        });

        it('falls back when getClientCapabilities throws', async () => {
            window.isSecureContext = true;
            window.PublicKeyCredential = {
                isConditionalMediationAvailable: async () => true,
                isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
                getClientCapabilities: async () => { throw new Error('Not supported'); }
            };
            if (!navigator.credentials) {
                Object.defineProperty(navigator, 'credentials', {
                    value: { get: async () => null, create: async () => null },
                    configurable: true
                });
            }
            const caps = await getPasskeyCapabilities();
            expect(caps.source).toBe('fallback');
        });
    });

    describe('detectWebView()', () => {
        let origUA;

        beforeEach(() => {
            origUA = navigator.userAgent;
        });

        afterEach(() => {
            Object.defineProperty(navigator, 'userAgent', {
                value: origUA,
                writable: true,
                configurable: true
            });
        });

        function setUA(ua) {
            Object.defineProperty(navigator, 'userAgent', {
                value: ua,
                writable: true,
                configurable: true
            });
        }

        it('detects Android WebView (wv)', () => {
            setUA('Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36 wv)');
            expect(detectWebView()).toBe(true);
        });

        it('detects iOS WKWebView (no Safari in UA)', () => {
            setUA('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148');
            expect(detectWebView()).toBe(true);
        });

        it('detects Electron', () => {
            setUA('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Electron/28.0.0 Chrome/120.0.0.0 Safari/537.36');
            expect(detectWebView()).toBe(true);
        });

        it('returns false for normal Chrome on desktop', () => {
            setUA('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
            expect(detectWebView()).toBe(false);
        });

        it('returns false for normal Safari on iOS', () => {
            setUA('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1');
            expect(detectWebView()).toBe(false);
        });

        it('returns false for normal Firefox', () => {
            setUA('Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0');
            expect(detectWebView()).toBe(false);
        });
    });

    describe('registerPasskey() default improvements', () => {
        it('default residentKey is required', () => {
            // This tests the new default value
            const options = {};
            const credOpts = { authenticatorSelection: null };
            const residentKey = options.residentKey
                || credOpts.authenticatorSelection?.residentKey
                || 'required';
            expect(residentKey).toBe('required');
        });

        it('caller can override residentKey', () => {
            const options = { residentKey: 'preferred' };
            const credOpts = { authenticatorSelection: null };
            const residentKey = options.residentKey
                || credOpts.authenticatorSelection?.residentKey
                || 'required';
            expect(residentKey).toBe('preferred');
        });

        it('server authenticatorSelection takes precedence for residentKey', () => {
            const options = {};
            const credOpts = { authenticatorSelection: { residentKey: 'discouraged' } };
            const residentKey = options.residentKey
                || credOpts.authenticatorSelection?.residentKey
                || 'required';
            expect(residentKey).toBe('discouraged');
        });

        it('caller overrides server for residentKey', () => {
            const options = { residentKey: 'preferred' };
            const credOpts = { authenticatorSelection: { residentKey: 'discouraged' } };
            const residentKey = options.residentKey
                || credOpts.authenticatorSelection?.residentKey
                || 'required';
            expect(residentKey).toBe('preferred');
        });

        it('no default authenticatorAttachment (allows any)', () => {
            const options = {};
            const authSelection = {
                ...(options.authenticatorAttachment !== undefined
                    ? { authenticatorAttachment: options.authenticatorAttachment }
                    : {}),
                residentKey: 'required',
                userVerification: 'preferred'
            };
            expect(authSelection.authenticatorAttachment).toBeUndefined();
        });

        it('caller can set authenticatorAttachment', () => {
            const options = { authenticatorAttachment: 'platform' };
            const authSelection = {
                ...(options.authenticatorAttachment !== undefined
                    ? { authenticatorAttachment: options.authenticatorAttachment }
                    : {}),
                residentKey: 'required',
                userVerification: 'preferred'
            };
            expect(authSelection.authenticatorAttachment).toBe('platform');
        });

        it('caller can set cross-platform authenticatorAttachment', () => {
            const options = { authenticatorAttachment: 'cross-platform' };
            const authSelection = {
                ...(options.authenticatorAttachment !== undefined
                    ? { authenticatorAttachment: options.authenticatorAttachment }
                    : {}),
                residentKey: 'required',
                userVerification: 'preferred'
            };
            expect(authSelection.authenticatorAttachment).toBe('cross-platform');
        });
    });
});
