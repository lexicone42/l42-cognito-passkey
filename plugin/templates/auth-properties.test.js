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
 * 3. Cookie domain safety with PUBLIC_SUFFIXES
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

// ============================================================================
// Extracted logic from auth.js (tested against the same algorithms)
// ============================================================================

/**
 * JWT encoding/decoding - mirrors auth.js UNSAFE_decodeJwtPayload
 */
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

/**
 * Token expiry logic - mirrors auth.js
 */
function isTokenExpired(tokens) {
    try {
        return Date.now() >= UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
    } catch {
        return true;
    }
}

const REFRESH_CONFIG = {
    password: { cookieMaxAge: 86400, refreshBefore: 300000 },
    passkey: { cookieMaxAge: 2592000, refreshBefore: 3600000 }
};

function shouldRefreshToken(tokens, { handlerMode = false } = {}) {
    if (!tokens || !tokens.id_token) return false;
    if (!handlerMode && !tokens.refresh_token) return false;
    try {
        const exp = UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
        const authMethod = tokens.auth_method || 'password';
        const refreshConfig = REFRESH_CONFIG[authMethod] || REFRESH_CONFIG.password;
        return Date.now() >= (exp - refreshConfig.refreshBefore);
    } catch {
        return false;
    }
}

/**
 * Cookie domain logic - mirrors auth.js getCookieDomain
 */
const PUBLIC_SUFFIXES = [
    'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'com.br', 'net.br', 'org.br',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp',
    'co.nz', 'org.nz', 'net.nz',
    'co.za', 'org.za', 'net.za',
    'co.in', 'org.in', 'net.in',
    'com.hk', 'org.hk', 'edu.hk',
    'com.sg', 'org.sg', 'edu.sg',
    'com.de',
    'com.cn', 'net.cn', 'org.cn',
    'com.tw', 'org.tw',
    'com.mx', 'org.mx',
    'com.ar', 'org.ar',
    'co.kr', 'or.kr'
];

function getCookieDomain(hostname) {
    if (hostname === 'localhost' || hostname === '127.0.0.1') return null;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return null;

    const parts = hostname.split('.');
    const lastTwo = parts.slice(-2).join('.');

    if (PUBLIC_SUFFIXES.includes(lastTwo)) {
        if (parts.length < 3) return null;
        return '.' + parts.slice(-3).join('.');
    }

    if (parts.length >= 2) {
        return '.' + parts.slice(-2).join('.');
    }

    return null;
}

/**
 * isAdmin / isReadonly logic - mirrors auth.js
 */
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

/**
 * UI_ONLY_hasRole logic - mirrors auth.js
 */
function UI_ONLY_hasRole(groups, requiredRole) {
    const normalizedGroups = groups.map(g => g.toLowerCase());
    const normalizedRole = requiredRole.toLowerCase();
    return normalizedGroups.includes(normalizedRole) ||
           normalizedGroups.includes(normalizedRole + 's') ||
           normalizedGroups.includes(normalizedRole.replace(/s$/, ''));
}

/**
 * OAuth state generation - mirrors auth.js
 */
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
    'player', 'dm', 'moderator',
    'developer', 'developers'
);

/** Arbitrary for user group arrays */
const userGroupsArb = fc.array(cognitoGroupArb, { minLength: 0, maxLength: 5 });

/** Arbitrary for role names used with UI_ONLY_hasRole */
const roleNameArb = fc.constantFrom(
    'admin', 'readonly', 'user', 'editor', 'publisher',
    'reviewer', 'player', 'dm', 'moderator'
);

/** Arbitrary for valid-looking hostnames */
const hostnamePartArb = fc.stringMatching(/^[a-z0-9]{1,10}$/);

const standardTldArb = fc.constantFrom('com', 'org', 'net', 'io', 'dev', 'app');

const ccTldSuffixArb = fc.constantFrom(...PUBLIC_SUFFIXES);

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

    it('shouldRefreshToken is false when no refresh_token in standard mode', () => {
        fc.assert(
            fc.property(expArb, authMethodArb, (exp, authMethod) => {
                const tokens = {
                    id_token: createTestJwt({ sub: 'user1', exp }),
                    access_token: createTestJwt({ sub: 'user1', exp }),
                    // No refresh_token
                    auth_method: authMethod
                };

                // Without refresh_token in non-handler mode, cannot refresh
                expect(shouldRefreshToken(tokens, { handlerMode: false })).toBe(false);
                return true;
            }),
            { numRuns: 100 }
        );
    });

    it('shouldRefreshToken is true in handler mode even without refresh_token (if near expiry)', () => {
        fc.assert(
            fc.property(authMethodArb, (authMethod) => {
                const refreshConfig = REFRESH_CONFIG[authMethod] || REFRESH_CONFIG.password;
                // Create token that expires just inside the refresh window
                const exp = Math.floor(Date.now() / 1000) + Math.floor(refreshConfig.refreshBefore / 2000);
                const tokens = {
                    id_token: createTestJwt({ sub: 'user1', exp }),
                    access_token: createTestJwt({ sub: 'user1', exp }),
                    // No refresh_token, but handler mode
                    auth_method: authMethod
                };

                expect(shouldRefreshToken(tokens, { handlerMode: true })).toBe(true);
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

// ============================================================================
// PROPERTY: Cookie Domain Safety
// ============================================================================

describe('PROPERTY: Cookie Domain Safety', () => {
    it('never returns a PUBLIC_SUFFIX as the cookie domain', () => {
        fc.assert(
            fc.property(
                hostnamePartArb,
                ccTldSuffixArb,
                (sub, suffix) => {
                    const hostname = `${sub}.${suffix}`;
                    const domain = getCookieDomain(hostname);

                    if (domain !== null) {
                        // The domain without leading dot should not be a public suffix
                        const domainWithoutDot = domain.replace(/^\./, '');
                        expect(PUBLIC_SUFFIXES).not.toContain(domainWithoutDot);
                    }
                    return true;
                }
            ),
            { numRuns: 200 }
        );
    });

    it('ccTLD domains get 3-part cookie domain', () => {
        fc.assert(
            fc.property(
                hostnamePartArb,
                hostnamePartArb,
                ccTldSuffixArb,
                (sub1, sub2, suffix) => {
                    const hostname = `${sub1}.${sub2}.${suffix}`;
                    const domain = getCookieDomain(hostname);

                    if (domain !== null) {
                        // Should be .sub2.suffix (3 parts)
                        const parts = domain.replace(/^\./, '').split('.');
                        expect(parts.length).toBe(suffix.split('.').length + 1);
                    }
                    return true;
                }
            ),
            { numRuns: 200 }
        );
    });

    it('standard TLD domains get 2-part cookie domain', () => {
        fc.assert(
            fc.property(
                hostnamePartArb,
                hostnamePartArb,
                standardTldArb,
                (sub, domain, tld) => {
                    const hostname = `${sub}.${domain}.${tld}`;
                    const cookieDomain = getCookieDomain(hostname);

                    if (cookieDomain !== null) {
                        // Should be .domain.tld (2 parts)
                        const parts = cookieDomain.replace(/^\./, '').split('.');
                        expect(parts.length).toBe(2);
                    }
                    return true;
                }
            ),
            { numRuns: 200 }
        );
    });

    it('cookie domain always starts with a dot', () => {
        fc.assert(
            fc.property(
                hostnamePartArb,
                hostnamePartArb,
                standardTldArb,
                (sub, domain, tld) => {
                    const hostname = `${sub}.${domain}.${tld}`;
                    const cookieDomain = getCookieDomain(hostname);

                    if (cookieDomain !== null) {
                        expect(cookieDomain.startsWith('.')).toBe(true);
                    }
                    return true;
                }
            ),
            { numRuns: 100 }
        );
    });

    it('localhost and 127.0.0.1 always return null', () => {
        expect(getCookieDomain('localhost')).toBeNull();
        expect(getCookieDomain('127.0.0.1')).toBeNull();
    });

    it('IP addresses return null', () => {
        fc.assert(
            fc.property(
                fc.integer({ min: 1, max: 255 }),
                fc.integer({ min: 0, max: 255 }),
                fc.integer({ min: 0, max: 255 }),
                fc.integer({ min: 0, max: 255 }),
                (a, b, c, d) => {
                    const ip = `${a}.${b}.${c}.${d}`;
                    expect(getCookieDomain(ip)).toBeNull();
                    return true;
                }
            ),
            { numRuns: 50 }
        );
    });

    it('bare public suffixes return null (cannot set domain cookie)', () => {
        for (const suffix of PUBLIC_SUFFIXES) {
            expect(getCookieDomain(suffix)).toBeNull();
        }
    });
});

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

    it('getCookieDomain handles edge case domains', () => {
        // Single-part hostname
        expect(getCookieDomain('localhost')).toBeNull();

        // Public suffix without subdomain
        expect(getCookieDomain('co.uk')).toBeNull();

        // Deeply nested subdomain
        const domain = getCookieDomain('a.b.c.d.example.com');
        expect(domain).toBe('.example.com');

        // ccTLD with proper subdomain
        const ukDomain = getCookieDomain('app.example.co.uk');
        expect(ukDomain).toBe('.example.co.uk');
    });

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
