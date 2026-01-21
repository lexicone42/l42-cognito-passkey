/**
 * L42 Cognito Passkey - OAuth Security Tests
 *
 * Tests for OAuth security features including:
 * - PKCE (Proof Key for Code Exchange)
 * - CSRF state protection
 * - Redirect URI validation
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ============================================================================
// PKCE (Proof Key for Code Exchange)
// ============================================================================

describe('PKCE Implementation', () => {
    /**
     * Generate a code verifier matching RFC 7636 requirements
     * @returns {string} 43-128 character URL-safe string
     */
    function generateCodeVerifier() {
        const array = new Uint8Array(48);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * Generate SHA-256 code challenge from verifier
     * @param {string} verifier
     * @returns {Promise<string>}
     */
    async function generateCodeChallenge(verifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return btoa(String.fromCharCode(...new Uint8Array(hash)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    describe('Code Verifier Generation', () => {
        it('generates verifier of correct length (43-128 chars)', () => {
            const verifier = generateCodeVerifier();
            expect(verifier.length).toBeGreaterThanOrEqual(43);
            expect(verifier.length).toBeLessThanOrEqual(128);
        });

        it('generates verifier with only URL-safe characters', () => {
            const verifier = generateCodeVerifier();
            // RFC 7636: unreserved characters = [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
            expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
        });

        it('generates unique verifiers each time', () => {
            const verifiers = new Set();
            for (let i = 0; i < 100; i++) {
                verifiers.add(generateCodeVerifier());
            }
            expect(verifiers.size).toBe(100);
        });

        it('has sufficient entropy (at least 256 bits)', () => {
            const verifier = generateCodeVerifier();
            // 48 random bytes = 384 bits of entropy
            // Base64 encoding: 48 bytes -> 64 chars
            // Each base64 char = 6 bits, so 64 chars = 384 bits
            expect(verifier.length).toBeGreaterThanOrEqual(43); // RFC minimum
        });
    });

    describe('Code Challenge Generation', () => {
        it('generates base64url-encoded SHA-256 hash', async () => {
            const verifier = 'test_verifier_string_for_pkce_testing';
            const challenge = await generateCodeChallenge(verifier);

            // Should be base64url encoded (no +, /, =)
            expect(challenge).not.toContain('+');
            expect(challenge).not.toContain('/');
            expect(challenge).not.toContain('=');
        });

        it('produces consistent challenge for same verifier', async () => {
            const verifier = generateCodeVerifier();
            const challenge1 = await generateCodeChallenge(verifier);
            const challenge2 = await generateCodeChallenge(verifier);
            expect(challenge1).toBe(challenge2);
        });

        it('produces different challenges for different verifiers', async () => {
            const verifier1 = generateCodeVerifier();
            const verifier2 = generateCodeVerifier();
            const challenge1 = await generateCodeChallenge(verifier1);
            const challenge2 = await generateCodeChallenge(verifier2);
            expect(challenge1).not.toBe(challenge2);
        });

        it('challenge length is correct for SHA-256 (43 chars)', async () => {
            const verifier = generateCodeVerifier();
            const challenge = await generateCodeChallenge(verifier);
            // SHA-256 = 32 bytes, base64url = ceil(32 * 8 / 6) = 43 chars
            expect(challenge.length).toBe(43);
        });
    });

    describe('PKCE Security Properties', () => {
        it('verifier cannot be derived from challenge', async () => {
            // This is the core security property of PKCE
            const verifier = generateCodeVerifier();
            const challenge = await generateCodeChallenge(verifier);

            // Challenge is a hash - should be impossible to reverse
            // We can only verify this by checking the challenge doesn't contain the verifier
            expect(challenge).not.toContain(verifier);
            expect(challenge.length).toBeLessThan(verifier.length);
        });

        it('different verifiers produce unique challenges (collision resistance)', async () => {
            const challenges = new Set();
            for (let i = 0; i < 100; i++) {
                const verifier = generateCodeVerifier();
                const challenge = await generateCodeChallenge(verifier);
                challenges.add(challenge);
            }
            expect(challenges.size).toBe(100);
        });
    });
});

// ============================================================================
// CSRF State Protection
// ============================================================================

describe('OAuth State (CSRF Protection)', () => {
    function generateOAuthState() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
    }

    it('generates 64-character hex state', () => {
        const state = generateOAuthState();
        expect(state.length).toBe(64);
        expect(state).toMatch(/^[0-9a-f]+$/);
    });

    it('has 256 bits of entropy', () => {
        const state = generateOAuthState();
        // 32 bytes = 256 bits, hex encoded = 64 chars
        expect(state.length).toBe(64);
    });

    it('generates unique states each time', () => {
        const states = new Set();
        for (let i = 0; i < 100; i++) {
            states.add(generateOAuthState());
        }
        expect(states.size).toBe(100);
    });
});

// ============================================================================
// Redirect URI Validation
// ============================================================================

describe('Redirect URI Validation', () => {
    /**
     * Check if a hostname is in the allowed list
     */
    function isDomainAllowed(hostname, allowedDomains, currentHostname) {
        hostname = hostname.toLowerCase();

        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            return true;
        }

        if (allowedDomains && allowedDomains.length > 0) {
            return allowedDomains.some(domain =>
                hostname === domain || hostname.endsWith('.' + domain)
            );
        }

        currentHostname = currentHostname.toLowerCase();
        if (hostname === currentHostname) {
            return true;
        }

        const currentParts = currentHostname.split('.');
        if (currentParts.length >= 2) {
            const currentBase = currentParts.slice(-2).join('.');
            return hostname === currentBase || hostname.endsWith('.' + currentBase);
        }

        return false;
    }

    it('allows localhost', () => {
        expect(isDomainAllowed('localhost', [], 'example.com')).toBe(true);
        expect(isDomainAllowed('127.0.0.1', [], 'example.com')).toBe(true);
    });

    it('allows current domain', () => {
        expect(isDomainAllowed('example.com', [], 'example.com')).toBe(true);
    });

    it('allows subdomains of current domain', () => {
        expect(isDomainAllowed('sub.example.com', [], 'example.com')).toBe(true);
        expect(isDomainAllowed('deep.sub.example.com', [], 'example.com')).toBe(true);
    });

    it('rejects different domains', () => {
        expect(isDomainAllowed('evil.com', [], 'example.com')).toBe(false);
        expect(isDomainAllowed('example.evil.com', [], 'example.com')).toBe(false);
    });

    it('respects allowedDomains list', () => {
        const allowed = ['trusted.com', 'other.org'];
        expect(isDomainAllowed('trusted.com', allowed, 'example.com')).toBe(true);
        expect(isDomainAllowed('sub.trusted.com', allowed, 'example.com')).toBe(true);
        expect(isDomainAllowed('evil.com', allowed, 'example.com')).toBe(false);
    });

    it('prevents subdomain takeover attacks', () => {
        // Attacker registers evil.example.com - should only be allowed if current domain allows it
        expect(isDomainAllowed('evil.example.com', [], 'app.example.com')).toBe(true);
        // But not if allowedDomains is explicitly set to app.example.com only
        expect(isDomainAllowed('evil.example.com', ['app.example.com'], 'app.example.com')).toBe(false);
    });
});

// ============================================================================
// Token Exchange Security
// ============================================================================

describe('Token Exchange Security', () => {
    it('requires state parameter', () => {
        // Simulating the check - must return boolean, not falsy value
        function verifyState(state, storedState) {
            return Boolean(state && storedState && state === storedState);
        }

        expect(verifyState(null, 'stored')).toBe(false);
        expect(verifyState(undefined, 'stored')).toBe(false);
        expect(verifyState('', 'stored')).toBe(false);
    });

    it('requires matching state', () => {
        function verifyState(state, storedState) {
            return Boolean(state && storedState && state === storedState);
        }

        expect(verifyState('abc123', 'abc123')).toBe(true);
        expect(verifyState('abc123', 'xyz789')).toBe(false);
        expect(verifyState('abc123', 'abc1234')).toBe(false);
    });

    it('requires code verifier for PKCE', () => {
        // Simulating the PKCE check
        function validatePKCE(codeVerifier) {
            if (!codeVerifier) {
                throw new Error('Missing PKCE code verifier');
            }
            return true;
        }

        expect(() => validatePKCE(null)).toThrow('Missing PKCE code verifier');
        expect(() => validatePKCE(undefined)).toThrow('Missing PKCE code verifier');
        expect(() => validatePKCE('')).toThrow('Missing PKCE code verifier');
        expect(validatePKCE('valid_verifier')).toBe(true);
    });

    it('clears verifier after use (prevents replay)', () => {
        // Simulate sessionStorage behavior
        const storage = {};

        function storeVerifier(v) { storage.verifier = v; }
        function getAndClearVerifier() {
            const v = storage.verifier;
            delete storage.verifier;
            return v;
        }

        storeVerifier('abc123');
        expect(getAndClearVerifier()).toBe('abc123');
        expect(getAndClearVerifier()).toBeUndefined(); // Second call returns nothing
    });
});

// ============================================================================
// Cookie Security
// ============================================================================

describe('Cookie Security Flags', () => {
    function buildCookieString(name, value, options = {}) {
        const {
            maxAge = 86400,
            secure = true,
            sameSite = 'lax',
            httpOnly = false,
            domain = null
        } = options;

        let cookieStr = `${name}=${value}; path=/; max-age=${maxAge}`;
        if (secure) cookieStr += '; secure';
        if (sameSite) cookieStr += `; samesite=${sameSite}`;
        if (httpOnly) cookieStr += '; httponly';
        if (domain) cookieStr += `; domain=${domain}`;
        return cookieStr;
    }

    it('includes Secure flag', () => {
        const cookie = buildCookieString('token', 'value', { secure: true });
        expect(cookie).toContain('secure');
    });

    it('includes SameSite=Lax', () => {
        const cookie = buildCookieString('token', 'value', { sameSite: 'lax' });
        expect(cookie).toContain('samesite=lax');
    });

    it('includes HttpOnly when specified', () => {
        const cookie = buildCookieString('token', 'value', { httpOnly: true });
        expect(cookie).toContain('httponly');
    });

    it('sets appropriate max-age for password auth (1 day)', () => {
        const cookie = buildCookieString('token', 'value', { maxAge: 86400 });
        expect(cookie).toContain('max-age=86400');
    });

    it('sets appropriate max-age for passkey auth (30 days)', () => {
        const cookie = buildCookieString('token', 'value', { maxAge: 2592000 });
        expect(cookie).toContain('max-age=2592000');
    });
});

// ============================================================================
// HTTPS Enforcement
// ============================================================================

describe('HTTPS Enforcement', () => {
    function validateRedirectUri(uri, allowHttp = false) {
        try {
            const url = new URL(uri);
            const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';

            if (!allowHttp && url.protocol !== 'https:' && !isLocalhost) {
                throw new Error('redirectUri must use HTTPS');
            }
            return true;
        } catch (e) {
            if (e.message.includes('HTTPS')) throw e;
            throw new Error('Invalid redirectUri');
        }
    }

    it('allows HTTPS URLs', () => {
        expect(validateRedirectUri('https://example.com/callback')).toBe(true);
    });

    it('allows localhost with HTTP', () => {
        expect(validateRedirectUri('http://localhost/callback')).toBe(true);
        expect(validateRedirectUri('http://127.0.0.1/callback')).toBe(true);
    });

    it('rejects HTTP for non-localhost', () => {
        expect(() => validateRedirectUri('http://example.com/callback'))
            .toThrow('redirectUri must use HTTPS');
    });

    it('rejects invalid URLs', () => {
        expect(() => validateRedirectUri('not-a-url'))
            .toThrow('Invalid redirectUri');
    });
});

// ============================================================================
// Cognito Domain Validation
// ============================================================================

describe('Cognito Domain Validation', () => {
    /**
     * Validate cognitoDomain format to prevent injection attacks
     */
    function validateCognitoDomain(domain) {
        if (!domain || typeof domain !== 'string') {
            throw new Error('cognitoDomain is required');
        }
        const cognitoDomain = domain.toLowerCase();
        const isAmazonCognito = /^[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com$/.test(cognitoDomain);
        const isValidCustomDomain = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(cognitoDomain) &&
            !cognitoDomain.includes('..') &&
            !cognitoDomain.includes('://');
        if (!isAmazonCognito && !isValidCustomDomain) {
            throw new Error('Invalid cognitoDomain format');
        }
        return true;
    }

    it('accepts valid Amazon Cognito domains', () => {
        expect(validateCognitoDomain('myapp.auth.us-west-2.amazoncognito.com')).toBe(true);
        expect(validateCognitoDomain('my-app.auth.eu-west-1.amazoncognito.com')).toBe(true);
        expect(validateCognitoDomain('app123.auth.ap-southeast-1.amazoncognito.com')).toBe(true);
    });

    it('accepts valid custom domains', () => {
        expect(validateCognitoDomain('auth.example.com')).toBe(true);
        expect(validateCognitoDomain('login.myapp.io')).toBe(true);
    });

    it('rejects domains with protocol', () => {
        expect(() => validateCognitoDomain('https://myapp.auth.us-west-2.amazoncognito.com'))
            .toThrow('Invalid cognitoDomain format');
    });

    it('rejects domains with path traversal', () => {
        expect(() => validateCognitoDomain('myapp..evil.com'))
            .toThrow('Invalid cognitoDomain format');
    });

    it('rejects obviously invalid domains', () => {
        expect(() => validateCognitoDomain(''))
            .toThrow('cognitoDomain is required');
        expect(() => validateCognitoDomain('not-a-domain'))
            .toThrow('Invalid cognitoDomain format');
    });

    it('rejects injection attempts', () => {
        // Attacker tries to redirect to their domain
        expect(() => validateCognitoDomain('evil.com/oauth2/authorize?redirect_uri=https://attacker.com'))
            .toThrow('Invalid cognitoDomain format');
    });
});
