/**
 * L42 Cognito Passkey - Auth Module Property-Based Tests
 *
 * Property-based tests for core auth.js invariants using fast-check.
 * These complement the RBAC property tests by testing authentication
 * primitives that should hold for ALL possible inputs.
 *
 * Properties tested:
 * 1. Token expiry: isTokenExpired → shouldRefreshToken (implication)
 * 2. isAdmin / isReadonly mutual exclusion
 * 3. (Removed: cookie domain tests — getCookieDomain removed in v0.15.0)
 * 4. OAuth state uniqueness (no collisions)
 * 5. UI_ONLY_hasRole singular/plural normalization consistency
 * 6. UNSAFE_decodeJwtPayload roundtrip
 *
 * Run with: npx vitest run plugin/templates/auth-properties.test.js
 *
 * @vitest-environment jsdom
 * @module auth-property-tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fc from 'fast-check';
import {
    UNSAFE_decodeJwtPayload,
    isTokenExpired,
    shouldRefreshToken,
    generateCodeVerifier,
    generateCodeChallenge
} from '../../src/auth.js';

// ============================================================================
// Test helpers
// ============================================================================

function createTestJwt(claims) {
    const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const payload = btoa(JSON.stringify(claims))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return `${header}.${payload}.test-signature`;
}

// isTokenExpired, shouldRefreshToken, UNSAFE_decodeJwtPayload, UI_ONLY_hasRole,
// generateCodeVerifier, generateCodeChallenge imported from real auth.js above.

// isAdmin/isReadonly — the real auth.js versions read from internal state (getUserGroups).
// These test versions take groups as a parameter to test the algorithm directly.
function isAdmin(groups) {
    const lower = groups.map(g => g.toLowerCase());
    return lower.includes('admin') || lower.includes('admins') || lower.includes('administrators');
}

function isReadonly(groups) {
    const lower = groups.map(g => g.toLowerCase());
    const hasReadonly = lower.includes('readonly') || lower.includes('read-only') ||
                        lower.includes('viewer') || lower.includes('viewers');
    const hasAdmin = lower.includes('admin') || lower.includes('admins') || lower.includes('administrators');
    return hasReadonly && !hasAdmin;
}

// UI_ONLY_hasRole — the real auth.js version takes (role) and reads groups internally.
// This test version takes (groups, role) to test the normalization algorithm directly
// with property-based inputs. The algorithm is the same; the interface differs.
function UI_ONLY_hasRole(groups, requiredRole) {
    const normalizedGroups = groups.map(g => g.toLowerCase());
    const normalizedRole = requiredRole.toLowerCase();
    return normalizedGroups.includes(normalizedRole) ||
           normalizedGroups.includes(normalizedRole + 's') ||
           normalizedGroups.includes(normalizedRole.replace(/s$/, ''));
}

// generateOAuthState is private — tested as algorithm
function generateOAuthState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// ARBITRARIES
// ============================================================================

/** Arbitrary for Unix timestamps (seconds) within reasonable range */
const expArb = fc.integer({
    min: Math.floor(Date.now() / 1000) - 86400,  // 1 day ago
    max: Math.floor(Date.now() / 1000) + 86400    // 1 day from now
});

/** Arbitrary for auth methods */
const authMethodArb = fc.constantFrom('password', 'passkey');

/** Arbitrary for Cognito group names (realistic) */
const cognitoGroupArb = fc.constantFrom(
    'admin', 'admins', 'administrators',
    'readonly', 'read-only', 'viewer', 'viewers',
    'user', 'users', 'editor', 'editors',
    'publisher', 'publishers', 'reviewer',
    'moderator',
    'developer', 'developers'
);

/** Arbitrary for user group arrays */
const userGroupsArb = fc.array(cognitoGroupArb, { minLength: 0, maxLength: 5 });

/** Arbitrary for role names used with UI_ONLY_hasRole */
const roleNameArb = fc.constantFrom(
    'admin', 'readonly', 'user', 'editor', 'publisher',
    'reviewer', 'moderator'
);

// Cookie domain arbitraries removed — getCookieDomain was removed from auth.js in v0.15.0

// ============================================================================
// PROPERTY: Token Expiry / shouldRefreshToken Relationship
// ============================================================================

describe('PROPERTY: Token Expiry Invariants', () => {
    it('if isTokenExpired is true AND refresh_token exists, shouldRefreshToken is also true', () => {
        fc.assert(
            fc.property(expArb, authMethodArb, (exp, authMethod) => {
                const tokens = {
                    id_token: createTestJwt({ sub: 'user1', exp }),
                    access_token: createTestJwt({ sub: 'user1', exp }),
                    refresh_token: 'refresh-token-abc',
                    auth_method: authMethod
                };

                if (isTokenExpired(tokens)) {
                    // Key invariant: expired tokens should always trigger refresh
                    expect(shouldRefreshToken(tokens)).toBe(true);
                }
                return true;
            }),
            { numRuns: 200 }
        );
    });

    // "standard mode" tests removed — only handler mode exists since v0.15.0.
    // shouldRefreshToken no longer checks for refresh_token (server holds it).

    it('shouldRefreshToken works without client-side refresh_token (handler mode)', () => {
        fc.assert(
            fc.property(authMethodArb, (authMethod) => {
                // Token near expiry, no client-side refresh_token
                const exp = Math.floor(Date.now() / 1000) + 60; // 1 minute
                const tokens = {
                    id_token: createTestJwt({ sub: 'user1', exp }),
                    access_token: createTestJwt({ sub: 'user1', exp }),
                    auth_method: authMethod
                };
                // Handler mode: server holds refresh_token, client doesn't need it
                expect(shouldRefreshToken(tokens)).toBe(true);
                return true;
            }),
            { numRuns: 50 }
        );
    });

    it('isTokenExpired is false for tokens far in the future', () => {
        fc.assert(
            fc.property(
                fc.integer({ min: 3600, max: 86400 }),
                (secondsFromNow) => {
                    const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
                    const tokens = {
                        id_token: createTestJwt({ sub: 'user1', exp }),
                        access_token: createTestJwt({ sub: 'user1', exp })
                    };
                    expect(isTokenExpired(tokens)).toBe(false);
                    return true;
                }
            ),
            { numRuns: 100 }
        );
    });

    it('isTokenExpired is true for tokens in the past', () => {
        fc.assert(
            fc.property(
                fc.integer({ min: 1, max: 86400 }),
                (secondsAgo) => {
                    const exp = Math.floor(Date.now() / 1000) - secondsAgo;
                    const tokens = {
                        id_token: createTestJwt({ sub: 'user1', exp }),
                        access_token: createTestJwt({ sub: 'user1', exp })
                    };
                    expect(isTokenExpired(tokens)).toBe(true);
                    return true;
                }
            ),
            { numRuns: 100 }
        );
    });
});

// ============================================================================
// PROPERTY: isAdmin / isReadonly Mutual Exclusion
// ============================================================================

describe('PROPERTY: isAdmin / isReadonly Mutual Exclusion', () => {
    it('isAdmin and isReadonly are never both true', () => {
        fc.assert(
            fc.property(userGroupsArb, (groups) => {
                const admin = isAdmin(groups);
                const readonly = isReadonly(groups);

                // Mutual exclusion: cannot be both admin and readonly
                expect(admin && readonly).toBe(false);
                return true;
            }),
            { numRuns: 500 }
        );
    });

    it('isReadonly is true only when readonly group present AND no admin group', () => {
        fc.assert(
            fc.property(userGroupsArb, (groups) => {
                const readonly = isReadonly(groups);
                const admin = isAdmin(groups);
                const lower = groups.map(g => g.toLowerCase());
                const hasReadonlyGroup = lower.includes('readonly') || lower.includes('read-only') ||
                                          lower.includes('viewer') || lower.includes('viewers');

                if (readonly) {
                    // If readonly is true, must have a readonly group and NOT admin
                    expect(hasReadonlyGroup).toBe(true);
                    expect(admin).toBe(false);
                }
                return true;
            }),
            { numRuns: 500 }
        );
    });

    it('admin group always overrides readonly', () => {
        fc.assert(
            fc.property(
                fc.constantFrom('admin', 'admins', 'administrators'),
                fc.constantFrom('readonly', 'read-only', 'viewer', 'viewers'),
                (adminGroup, readonlyGroup) => {
                    const groups = [adminGroup, readonlyGroup];
                    expect(isAdmin(groups)).toBe(true);
                    expect(isReadonly(groups)).toBe(false);
                    return true;
                }
            ),
            { numRuns: 20 }
        );
    });

    it('isAdmin is case-insensitive', () => {
        fc.assert(
            fc.property(
                fc.constantFrom('admin', 'admins', 'administrators'),
                (adminAlias) => {
                    // Various case combinations
                    expect(isAdmin([adminAlias.toUpperCase()])).toBe(true);
                    expect(isAdmin([adminAlias.charAt(0).toUpperCase() + adminAlias.slice(1)])).toBe(true);
                    expect(isAdmin([adminAlias.toLowerCase()])).toBe(true);
                    return true;
                }
            ),
            { numRuns: 10 }
        );
    });
});

// Cookie Domain Safety tests removed — getCookieDomain() and PUBLIC_SUFFIXES
// were removed from auth.js in v0.15.0 (handler-only mode, server handles cookies).

// ============================================================================
// PROPERTY: OAuth State Uniqueness
// ============================================================================

describe('PROPERTY: OAuth State Uniqueness', () => {
    it('generates 64-character hex strings', () => {
        fc.assert(
            fc.property(fc.constant(null), () => {
                const state = generateOAuthState();
                expect(state).toHaveLength(64);
                expect(state).toMatch(/^[0-9a-f]{64}$/);
                return true;
            }),
            { numRuns: 100 }
        );
    });

    it('no collisions in batch generation', () => {
        const states = new Set();
        const batchSize = 10000;

        for (let i = 0; i < batchSize; i++) {
            states.add(generateOAuthState());
        }

        // With 256-bit random values, collision probability is negligible
        expect(states.size).toBe(batchSize);
    });
});

// ============================================================================
// PROPERTY: UI_ONLY_hasRole Normalization
// ============================================================================

describe('PROPERTY: UI_ONLY_hasRole Normalization', () => {
    it('singular and plural forms produce same result', () => {
        fc.assert(
            fc.property(userGroupsArb, roleNameArb, (groups, role) => {
                // Singular form
                const singularResult = UI_ONLY_hasRole(groups, role);
                // Plural form (add 's')
                const pluralResult = UI_ONLY_hasRole(groups, role + 's');

                // Both should detect the same groups
                // Note: this property holds because the function checks both
                // role and role+'s' and role.replace(/s$/, '')
                if (singularResult) {
                    // If singular matches, plural should too (it strips trailing 's')
                    expect(pluralResult).toBe(true);
                }
                return true;
            }),
            { numRuns: 200 }
        );
    });

    it('is case-insensitive', () => {
        fc.assert(
            fc.property(userGroupsArb, roleNameArb, (groups, role) => {
                const lower = UI_ONLY_hasRole(groups, role.toLowerCase());
                const upper = UI_ONLY_hasRole(groups, role.toUpperCase());
                const mixed = UI_ONLY_hasRole(groups,
                    role.charAt(0).toUpperCase() + role.slice(1).toLowerCase());

                // All case variants should produce the same result
                expect(lower).toBe(upper);
                expect(lower).toBe(mixed);
                return true;
            }),
            { numRuns: 200 }
        );
    });

    it('empty groups array always returns false', () => {
        fc.assert(
            fc.property(roleNameArb, (role) => {
                expect(UI_ONLY_hasRole([], role)).toBe(false);
                return true;
            }),
            { numRuns: 50 }
        );
    });

    it('exact match always works', () => {
        fc.assert(
            fc.property(cognitoGroupArb, (group) => {
                // If the group is in the array, hasRole should find it
                expect(UI_ONLY_hasRole([group], group)).toBe(true);
                return true;
            }),
            { numRuns: 50 }
        );
    });
});

// ============================================================================
// PROPERTY: UNSAFE_decodeJwtPayload Roundtrip
// ============================================================================

describe('PROPERTY: JWT Decode Roundtrip', () => {
    it('decode(encode(claims)) equals original claims', () => {
        fc.assert(
            fc.property(
                fc.record({
                    sub: fc.string({ minLength: 1, maxLength: 50 }),
                    email: fc.emailAddress(),
                    exp: fc.integer({ min: 0, max: 9999999999 }),
                    iat: fc.integer({ min: 0, max: 9999999999 })
                }),
                (claims) => {
                    const jwt = createTestJwt(claims);
                    const decoded = UNSAFE_decodeJwtPayload(jwt);
                    expect(decoded).toEqual(claims);
                    return true;
                }
            ),
            { numRuns: 200 }
        );
    });

    it('handles special characters in claims', () => {
        fc.assert(
            fc.property(
                fc.record({
                    sub: fc.string({ minLength: 1, maxLength: 20 }),
                    name: fc.string({ minLength: 0, maxLength: 50 }),
                    exp: fc.integer({ min: 0, max: 9999999999 })
                }),
                (claims) => {
                    const jwt = createTestJwt(claims);
                    const decoded = UNSAFE_decodeJwtPayload(jwt);
                    expect(decoded.sub).toBe(claims.sub);
                    expect(decoded.exp).toBe(claims.exp);
                    return true;
                }
            ),
            { numRuns: 100 }
        );
    });

    it('rejects non-JWT strings', () => {
        fc.assert(
            fc.property(
                fc.string({ minLength: 0, maxLength: 50 }).filter(s => !s.includes('.')),
                (notAJwt) => {
                    expect(() => UNSAFE_decodeJwtPayload(notAJwt)).toThrow();
                    return true;
                }
            ),
            { numRuns: 50 }
        );
    });
});

// ============================================================================
// EDGE CASES: Explicit Regression Tests
// ============================================================================

describe('EDGE CASES: Auth Property Regressions', () => {
    it('shouldRefreshToken handles missing id_token gracefully', () => {
        expect(shouldRefreshToken(null)).toBe(false);
        expect(shouldRefreshToken({})).toBe(false);
        expect(shouldRefreshToken({ id_token: null })).toBe(false);
    });

    it('isTokenExpired handles malformed tokens', () => {
        expect(isTokenExpired({})).toBe(true);
        expect(isTokenExpired({ id_token: 'not.a.jwt' })).toBe(true);
        expect(isTokenExpired({ id_token: 'no-dots' })).toBe(true);
    });

    // getCookieDomain edge case test removed — function removed in v0.15.0

    it('UI_ONLY_hasRole with edge case inputs', () => {
        // Role ending in 's' that is not a plural
        expect(UI_ONLY_hasRole(['status'], 'status')).toBe(true);
        // Asking for 'statu' should match 'status' via normalizedRole + 's'
        expect(UI_ONLY_hasRole(['status'], 'statu')).toBe(true);

        // Double-s ending
        expect(UI_ONLY_hasRole(['access'], 'access')).toBe(true);
    });

    it('isAdmin handles all known aliases', () => {
        expect(isAdmin(['admin'])).toBe(true);
        expect(isAdmin(['admins'])).toBe(true);
        expect(isAdmin(['administrators'])).toBe(true);
        expect(isAdmin(['Admin'])).toBe(true);
        expect(isAdmin(['ADMIN'])).toBe(true);
        expect(isAdmin(['user'])).toBe(false);
        expect(isAdmin([])).toBe(false);
    });

    it('isReadonly handles all known aliases', () => {
        expect(isReadonly(['readonly'])).toBe(true);
        expect(isReadonly(['read-only'])).toBe(true);
        expect(isReadonly(['viewer'])).toBe(true);
        expect(isReadonly(['viewers'])).toBe(true);
        expect(isReadonly(['Readonly'])).toBe(true);
        expect(isReadonly(['VIEWER'])).toBe(true);
        expect(isReadonly(['user'])).toBe(false);
        expect(isReadonly([])).toBe(false);
    });
});

// ============================================================================
// SHARP-EDGES: Token Validation Missing Claims (S2)
// ============================================================================

// validateTokenClaims is private in auth.js — tested through isAuthenticated()
// in token-validation.test.js. This section tests the same invariants using
// a local mirror (the function takes a config parameter, unlike the real one).
function validateTokenClaims(tokens, testConfig) {
    if (!tokens || !tokens.id_token) return false;
    try {
        const claims = UNSAFE_decodeJwtPayload(tokens.id_token);
        if (claims.iss) {
            const expectedIssPrefix = 'https://cognito-idp.' + testConfig.cognitoRegion + '.amazonaws.com/';
            if (!claims.iss.startsWith(expectedIssPrefix)) return false;
        }
        const tokenClientId = claims.aud || claims.client_id;
        if (!tokenClientId) return false;
        if (tokenClientId !== testConfig.clientId) return false;
        if (!claims.exp || typeof claims.exp !== 'number') return false;
        const maxReasonableExp = Date.now() / 1000 + (30 * 24 * 60 * 60);
        if (claims.exp > maxReasonableExp) return false;
        return true;
    } catch {
        return false;
    }
}

describe('SHARP-EDGE: Token Validation Missing Claims (S2)', () => {
    const testConfig = {
        clientId: 'test-client-id',
        cognitoRegion: 'us-west-2'
    };

    it('token with only sub (no aud, exp) is rejected — S2 fixed', () => {
        // S2 fix: tokens missing aud/client_id or exp are now rejected.
        // Cognito tokens always include these claims; their absence indicates
        // a crafted or malformed token.
        const minimalToken = createTestJwt({ sub: 'user-123' });
        const result = validateTokenClaims({ id_token: minimalToken }, testConfig);
        expect(result).toBe(false);
    });

    it('token with aud but no exp is rejected', () => {
        const token = createTestJwt({ sub: 'user-123', aud: testConfig.clientId });
        expect(validateTokenClaims({ id_token: token }, testConfig)).toBe(false);
    });

    it('token with exp but no aud is rejected', () => {
        const token = createTestJwt({
            sub: 'user-123',
            exp: Math.floor(Date.now() / 1000) + 3600
        });
        expect(validateTokenClaims({ id_token: token }, testConfig)).toBe(false);
    });

    it('token with wrong issuer is always rejected', () => {
        fc.assert(fc.property(
            fc.string({ minLength: 1, maxLength: 50 }),
            (randomIss) => {
                fc.pre(!randomIss.startsWith('https://cognito-idp.us-west-2.amazonaws.com/'));
                const token = createTestJwt({
                    sub: 'user-123',
                    iss: randomIss,
                    aud: testConfig.clientId,
                    exp: Math.floor(Date.now() / 1000) + 3600
                });
                return validateTokenClaims({ id_token: token }, testConfig) === false;
            }
        ));
    });

    it('token with wrong client_id is always rejected', () => {
        fc.assert(fc.property(
            fc.string({ minLength: 1, maxLength: 50 }),
            (randomClientId) => {
                fc.pre(randomClientId !== testConfig.clientId);
                const token = createTestJwt({
                    sub: 'user-123',
                    iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_ABC123',
                    aud: randomClientId,
                    exp: Math.floor(Date.now() / 1000) + 3600
                });
                return validateTokenClaims({ id_token: token }, testConfig) === false;
            }
        ));
    });

    it('token with exp > 30 days from now is always rejected', () => {
        fc.assert(fc.property(
            fc.integer({ min: 31 * 24 * 60 * 60, max: 365 * 24 * 60 * 60 }),
            (secondsFuture) => {
                const token = createTestJwt({
                    sub: 'user-123',
                    iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_ABC123',
                    aud: testConfig.clientId,
                    exp: Math.floor(Date.now() / 1000) + secondsFuture
                });
                return validateTokenClaims({ id_token: token }, testConfig) === false;
            }
        ));
    });

    it('valid token with all claims passes', () => {
        const validToken = createTestJwt({
            sub: 'user-123',
            iss: 'https://cognito-idp.us-west-2.amazonaws.com/us-west-2_ABC123',
            aud: testConfig.clientId,
            exp: Math.floor(Date.now() / 1000) + 3600
        });
        expect(validateTokenClaims({ id_token: validToken }, testConfig)).toBe(true);
    });
});

// ============================================================================
// SHARP-EDGES: Login Rate Limiting Config Edge Cases (S3)
// ============================================================================

/**
 * Mirrors auth.js checkLoginRateLimit / getLoginAttemptInfo logic.
 */
function computeBackoffDelay(attemptCount, threshold, baseMs, maxMs) {
    if (attemptCount < threshold) return 0;
    const attemptsOverThreshold = attemptCount - threshold;
    const exponentialDelay = baseMs * Math.pow(2, attemptsOverThreshold);
    return Math.min(exponentialDelay, maxMs);
}

describe('SHARP-EDGE: Rate Limiting Config Boundaries (S3)', () => {
    it('backoff delay is always non-negative', () => {
        fc.assert(fc.property(
            fc.integer({ min: 0, max: 100 }),      // attemptCount
            fc.integer({ min: 0, max: 20 }),        // threshold
            fc.integer({ min: 1, max: 60000 }),     // baseMs
            fc.integer({ min: 1, max: 120000 }),    // maxMs
            (count, threshold, baseMs, maxMs) => {
                return computeBackoffDelay(count, threshold, baseMs, maxMs) >= 0;
            }
        ));
    });

    it('backoff delay never exceeds maxMs', () => {
        fc.assert(fc.property(
            fc.integer({ min: 0, max: 100 }),
            fc.integer({ min: 0, max: 20 }),
            fc.integer({ min: 1, max: 60000 }),
            fc.integer({ min: 1, max: 120000 }),
            (count, threshold, baseMs, maxMs) => {
                return computeBackoffDelay(count, threshold, baseMs, maxMs) <= maxMs;
            }
        ));
    });

    it('backoff delay is zero when under threshold', () => {
        fc.assert(fc.property(
            fc.integer({ min: 1, max: 20 }),  // threshold (>= 1)
            fc.integer({ min: 1, max: 60000 }),
            fc.integer({ min: 1, max: 120000 }),
            (threshold, baseMs, maxMs) => {
                // Under-threshold attempts should have zero delay
                for (let i = 0; i < threshold; i++) {
                    if (computeBackoffDelay(i, threshold, baseMs, maxMs) !== 0) return false;
                }
                return true;
            }
        ));
    });

    it('backoff delay is monotonically non-decreasing as attempts grow', () => {
        fc.assert(fc.property(
            fc.integer({ min: 1, max: 10 }),  // threshold
            fc.integer({ min: 1, max: 5000 }),  // baseMs
            fc.integer({ min: 1, max: 60000 }),  // maxMs
            (threshold, baseMs, maxMs) => {
                let prev = 0;
                for (let i = 0; i <= threshold + 20; i++) {
                    const delay = computeBackoffDelay(i, threshold, baseMs, maxMs);
                    if (delay < prev) return false;
                    prev = delay;
                }
                return true;
            }
        ));
    });

    it('threshold=0 throttles from first failure', () => {
        const delay = computeBackoffDelay(0, 0, 1000, 30000);
        expect(delay).toBe(1000); // 1000 * 2^0 = 1000
    });
});

// ============================================================================
// PROPERTY: PKCE (Proof Key for Code Exchange) Invariants
// ============================================================================

// generateCodeVerifier and generateCodeChallenge imported from real auth.js above.

/** Base64url alphabet regex — no +, /, or = characters */
const BASE64URL_RE = /^[A-Za-z0-9\-_]+$/;

describe('PROPERTY: PKCE Code Verifier Invariants', () => {
    it('verifier is always exactly 64 characters (48 bytes → base64url)', () => {
        fc.assert(
            fc.property(fc.constant(null), () => {
                const verifier = generateCodeVerifier();
                expect(verifier).toHaveLength(64);
                return true;
            }),
            { numRuns: 200 }
        );
    });

    it('verifier uses only base64url-safe characters (no +, /, =)', () => {
        fc.assert(
            fc.property(fc.constant(null), () => {
                const verifier = generateCodeVerifier();
                expect(verifier).toMatch(BASE64URL_RE);
                return true;
            }),
            { numRuns: 200 }
        );
    });

    it('verifier satisfies RFC 7636 length bounds (43-128 chars)', () => {
        fc.assert(
            fc.property(fc.constant(null), () => {
                const verifier = generateCodeVerifier();
                expect(verifier.length).toBeGreaterThanOrEqual(43);
                expect(verifier.length).toBeLessThanOrEqual(128);
                return true;
            }),
            { numRuns: 100 }
        );
    });

    it('no verifier collisions in batch generation (entropy)', () => {
        const verifiers = new Set();
        const batchSize = 1000;

        for (let i = 0; i < batchSize; i++) {
            verifiers.add(generateCodeVerifier());
        }

        // 48 bytes of randomness → collision probability is negligible
        expect(verifiers.size).toBe(batchSize);
    });
});

describe('PROPERTY: PKCE Code Challenge Invariants', () => {
    it('challenge is always exactly 43 characters (SHA-256 = 32 bytes → base64url)', async () => {
        // SHA-256 outputs 32 bytes; base64url(32 bytes) = 43 chars (no padding)
        for (let i = 0; i < 100; i++) {
            const verifier = generateCodeVerifier();
            const challenge = await generateCodeChallenge(verifier);
            expect(challenge).toHaveLength(43);
        }
    });

    it('challenge uses only base64url-safe characters', async () => {
        for (let i = 0; i < 100; i++) {
            const verifier = generateCodeVerifier();
            const challenge = await generateCodeChallenge(verifier);
            expect(challenge).toMatch(BASE64URL_RE);
        }
    });

    it('challenge is deterministic — same verifier always produces same challenge', async () => {
        // Use a fixed verifier (not random) to test determinism
        const fixedVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        const challenge1 = await generateCodeChallenge(fixedVerifier);
        const challenge2 = await generateCodeChallenge(fixedVerifier);
        expect(challenge1).toBe(challenge2);
    });

    it('challenge differs from verifier (SHA-256 is not identity)', async () => {
        for (let i = 0; i < 100; i++) {
            const verifier = generateCodeVerifier();
            const challenge = await generateCodeChallenge(verifier);
            // Different lengths alone prove this (64 vs 43), but also check content
            expect(challenge).not.toBe(verifier);
        }
    });

    it('different verifiers produce different challenges (collision resistance)', async () => {
        const challenges = new Set();
        const batchSize = 200;

        for (let i = 0; i < batchSize; i++) {
            const verifier = generateCodeVerifier();
            const challenge = await generateCodeChallenge(verifier);
            challenges.add(challenge);
        }

        expect(challenges.size).toBe(batchSize);
    });

    it('challenge is not reversible to verifier (pre-image resistance, structural)', async () => {
        // Structural test: challenge is shorter than verifier (43 < 64),
        // so information is provably lost — you can't reconstruct 48 bytes from 32.
        const verifier = generateCodeVerifier();
        const challenge = await generateCodeChallenge(verifier);
        expect(challenge.length).toBeLessThan(verifier.length);
    });
});
