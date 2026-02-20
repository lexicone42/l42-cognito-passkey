/**
 * L42 Cognito Passkey - Pre-Registration Credential Validation Tests
 *
 * Tests for the _validateCredential() gate that checks credentials
 * against server policies (AAGUID allowlist, device-bound) before
 * completing registration with Cognito.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fc from 'fast-check';

// ============================================================================
// Simulated internals (mirrored from auth.js for testing)
// ============================================================================

let config = {
    validateCredentialEndpoint: null,
    debug: false
};

function debugLog() {}

/**
 * _validateCredential implementation (mirrored from auth.js)
 */
async function _validateCredential(credentialResponse) {
    if (!config.validateCredentialEndpoint) {
        return;
    }

    const response = await fetch(config.validateCredentialEndpoint, {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'X-L42-CSRF': '1'
        },
        body: JSON.stringify({
            attestation_object: credentialResponse.response.attestationObject,
            client_data_json: credentialResponse.response.clientDataJSON
        })
    });

    if (!response.ok) {
        var body = {};
        try { body = await response.json(); } catch (_) { /* ignore parse errors */ }
        var reason = body.reason || 'Credential rejected by server';
        throw new Error('Credential validation failed: ' + reason);
    }
}

// ============================================================================
// Mock credential response (simulates buildCredentialResponse output)
// ============================================================================

function mockCredentialResponse(overrides = {}) {
    return {
        id: 'credential-id-123',
        rawId: 'base64-raw-id',
        type: 'public-key',
        response: {
            clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
            attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YQ',
            ...overrides.response
        },
        authenticatorMetadata: {
            userPresent: true,
            userVerified: true,
            backupEligible: false,
            backupState: false,
            attestedCredentialData: true,
            extensionData: false,
            signCount: 0,
            aaguid: 'cb69481e-8ff7-4039-93ec-0a2729a154a8',
            ...overrides.authenticatorMetadata
        },
        ...overrides
    };
}

// ============================================================================
// Tests
// ============================================================================

describe('_validateCredential', () => {
    beforeEach(() => {
        config.validateCredentialEndpoint = null;
        vi.restoreAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should skip validation when no endpoint is configured', async () => {
        config.validateCredentialEndpoint = null;
        const fetchSpy = vi.spyOn(globalThis, 'fetch');

        await _validateCredential(mockCredentialResponse());

        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should send correct body and headers when endpoint is configured', async () => {
        config.validateCredentialEndpoint = '/auth/validate-credential';

        const cred = mockCredentialResponse();
        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: true,
            json: async () => ({ allowed: true, device: {} })
        });

        await _validateCredential(cred);

        expect(fetch).toHaveBeenCalledWith('/auth/validate-credential', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'X-L42-CSRF': '1'
            },
            body: JSON.stringify({
                attestation_object: cred.response.attestationObject,
                client_data_json: cred.response.clientDataJSON
            })
        });
    });

    it('should succeed silently on 200', async () => {
        config.validateCredentialEndpoint = '/auth/validate-credential';

        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: true,
            json: async () => ({
                allowed: true,
                device: {
                    aaguid: 'cb69481e-8ff7-4039-93ec-0a2729a154a8',
                    backup_eligible: false,
                    backup_state: false,
                    user_verified: true
                }
            })
        });

        // Should not throw
        await expect(_validateCredential(mockCredentialResponse())).resolves.toBeUndefined();
    });

    it('should throw on 403 with server reason', async () => {
        config.validateCredentialEndpoint = '/auth/validate-credential';

        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: false,
            status: 403,
            json: async () => ({
                allowed: false,
                reason: 'AAGUID cb69481e-8ff7-4039-93ec-0a2729a154a8 not in allowlist (1 allowed)'
            })
        });

        await expect(_validateCredential(mockCredentialResponse()))
            .rejects.toThrow('AAGUID cb69481e-8ff7-4039-93ec-0a2729a154a8 not in allowlist');
    });

    it('should throw with default reason when server returns no reason', async () => {
        config.validateCredentialEndpoint = '/auth/validate-credential';

        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: false,
            status: 403,
            json: async () => ({})
        });

        await expect(_validateCredential(mockCredentialResponse()))
            .rejects.toThrow('Credential rejected by server');
    });

    it('should throw with default reason when response body is not JSON', async () => {
        config.validateCredentialEndpoint = '/auth/validate-credential';

        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: false,
            status: 500,
            json: async () => { throw new SyntaxError('Unexpected token'); }
        });

        await expect(_validateCredential(mockCredentialResponse()))
            .rejects.toThrow('Credential rejected by server');
    });

    it('should throw on device-bound rejection', async () => {
        config.validateCredentialEndpoint = '/auth/validate-credential';

        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: false,
            status: 403,
            json: async () => ({
                allowed: false,
                reason: 'Device-bound credential required, but this credential is backup-eligible (synced/syncable)'
            })
        });

        await expect(_validateCredential(mockCredentialResponse({
            authenticatorMetadata: { backupEligible: true, backupState: true }
        }))).rejects.toThrow('backup-eligible');
    });
});

// ============================================================================
// Integration: registerPasskey flow simulation
// ============================================================================

describe('registerPasskey validation gate', () => {
    let cognitoRequestMock;
    let navigatorCreateMock;

    beforeEach(() => {
        config.validateCredentialEndpoint = '/auth/validate-credential';
        vi.restoreAllMocks();

        cognitoRequestMock = vi.fn();
        navigatorCreateMock = vi.fn();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    /**
     * Simulates the registerPasskey flow:
     * 1. navigator.credentials.create() → credential
     * 2. buildCredentialResponse(credential) → credentialResponse
     * 3. _validateCredential(credentialResponse) → pass or throw
     * 4. CompleteWebAuthnRegistration → success
     */
    async function simulateRegisterPasskey() {
        const credential = await navigatorCreateMock();
        const credentialResponse = mockCredentialResponse();

        // Validation gate
        await _validateCredential(credentialResponse);

        // If we get here, validation passed → complete with Cognito
        await cognitoRequestMock('CompleteWebAuthnRegistration', {
            Credential: credentialResponse
        });
    }

    it('should call Cognito after validation succeeds', async () => {
        navigatorCreateMock.mockResolvedValue({});

        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: true,
            json: async () => ({ allowed: true })
        });

        await simulateRegisterPasskey();

        expect(fetch).toHaveBeenCalledTimes(1);
        expect(cognitoRequestMock).toHaveBeenCalledWith(
            'CompleteWebAuthnRegistration',
            expect.objectContaining({ Credential: expect.any(Object) })
        );
    });

    it('should abort registration when validation rejects', async () => {
        navigatorCreateMock.mockResolvedValue({});

        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: false,
            status: 403,
            json: async () => ({
                allowed: false,
                reason: 'AAGUID not in allowlist'
            })
        });

        await expect(simulateRegisterPasskey()).rejects.toThrow('AAGUID not in allowlist');

        // Cognito should NOT have been called
        expect(cognitoRequestMock).not.toHaveBeenCalled();
    });

    it('should skip validation and proceed when no endpoint configured', async () => {
        config.validateCredentialEndpoint = null;
        navigatorCreateMock.mockResolvedValue({});

        const fetchSpy = vi.spyOn(globalThis, 'fetch');

        await simulateRegisterPasskey();

        // No fetch for validation, but Cognito still called
        expect(fetchSpy).not.toHaveBeenCalled();
        expect(cognitoRequestMock).toHaveBeenCalledTimes(1);
    });
});

// ============================================================================
// Integration: upgradeToPasskey flow simulation
// ============================================================================

describe('upgradeToPasskey validation gate', () => {
    beforeEach(() => {
        config.validateCredentialEndpoint = '/auth/validate-credential';
        vi.restoreAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    /**
     * Simulates upgradeToPasskey: returns false on rejection (silent failure).
     */
    async function simulateUpgradeToPasskey() {
        const credentialResponse = mockCredentialResponse();

        try {
            await _validateCredential(credentialResponse);
            // If validation passed, complete registration
            return true;
        } catch (_e) {
            // Silent failure — don't disrupt user experience
            return false;
        }
    }

    it('should return true when validation passes', async () => {
        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: true,
            json: async () => ({ allowed: true })
        });

        const result = await simulateUpgradeToPasskey();
        expect(result).toBe(true);
    });

    it('should return false when validation rejects', async () => {
        vi.spyOn(globalThis, 'fetch').mockResolvedValue({
            ok: false,
            status: 403,
            json: async () => ({
                allowed: false,
                reason: 'Device-bound credential required'
            })
        });

        const result = await simulateUpgradeToPasskey();
        expect(result).toBe(false);
    });

    it('should return true when no endpoint configured (skip)', async () => {
        config.validateCredentialEndpoint = null;
        const fetchSpy = vi.spyOn(globalThis, 'fetch');

        const result = await simulateUpgradeToPasskey();
        expect(result).toBe(true);
        expect(fetchSpy).not.toHaveBeenCalled();
    });
});

// ============================================================================
// PROPERTY: Server-side credential validation invariants
// Replicates Rust credential.rs logic (AAGUID + device-bound checks)
// ============================================================================

/**
 * Mirrors rust/src/credential.rs check_aaguid_allowed — case-insensitive.
 * Empty allowlist permits all.
 */
function checkAaguidAllowed(aaguid, allowlist) {
    if (allowlist.length === 0) return { ok: true };
    const lower = aaguid.toLowerCase();
    const found = allowlist.some(a => a.toLowerCase() === lower);
    return found
        ? { ok: true }
        : { ok: false, reason: `AAGUID ${aaguid} not in allowlist (${allowlist.length} allowed)` };
}

/**
 * Mirrors rust/src/credential.rs check_device_bound.
 * When require=true, backup-eligible credentials are rejected.
 */
function checkDeviceBound(backupEligible, require) {
    if (require && backupEligible) {
        return { ok: false, reason: 'Device-bound credential required, but this credential is backup-eligible' };
    }
    return { ok: true };
}

/** Arbitrary for UUID-format AAGUIDs */
const aaguidArb = fc.stringMatching(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
);

describe('PROPERTY: AAGUID Allowlist Invariants', () => {
    it('empty allowlist always permits', () => {
        fc.assert(
            fc.property(aaguidArb, (aaguid) => {
                return checkAaguidAllowed(aaguid, []).ok === true;
            }),
            { numRuns: 200 }
        );
    });

    it('AAGUID in list is always permitted', () => {
        fc.assert(
            fc.property(
                aaguidArb,
                fc.array(aaguidArb, { minLength: 0, maxLength: 5 }),
                (aaguid, extras) => {
                    const allowlist = [aaguid, ...extras];
                    return checkAaguidAllowed(aaguid, allowlist).ok === true;
                }
            ),
            { numRuns: 200 }
        );
    });

    it('AAGUID matching is case-insensitive', () => {
        fc.assert(
            fc.property(aaguidArb, (aaguid) => {
                const allowlist = [aaguid.toLowerCase()];
                const resultUpper = checkAaguidAllowed(aaguid.toUpperCase(), allowlist);
                const resultLower = checkAaguidAllowed(aaguid.toLowerCase(), allowlist);
                const resultMixed = checkAaguidAllowed(
                    aaguid.charAt(0).toUpperCase() + aaguid.slice(1).toLowerCase(),
                    allowlist
                );
                return resultUpper.ok && resultLower.ok && resultMixed.ok;
            }),
            { numRuns: 100 }
        );
    });

    it('AAGUID not in non-empty list is always rejected', () => {
        fc.assert(
            fc.property(
                aaguidArb,
                fc.array(aaguidArb, { minLength: 1, maxLength: 5 }),
                (aaguid, allowlist) => {
                    // Pre-condition: aaguid is not in the allowlist
                    fc.pre(!allowlist.some(a => a.toLowerCase() === aaguid.toLowerCase()));
                    const result = checkAaguidAllowed(aaguid, allowlist);
                    return result.ok === false && result.reason.includes('not in allowlist');
                }
            ),
            { numRuns: 200 }
        );
    });

    it('rejection message includes AAGUID and allowlist size', () => {
        fc.assert(
            fc.property(
                aaguidArb,
                fc.array(aaguidArb, { minLength: 1, maxLength: 5 }),
                (aaguid, allowlist) => {
                    fc.pre(!allowlist.some(a => a.toLowerCase() === aaguid.toLowerCase()));
                    const result = checkAaguidAllowed(aaguid, allowlist);
                    return result.reason.includes(aaguid) &&
                           result.reason.includes(`${allowlist.length} allowed`);
                }
            ),
            { numRuns: 100 }
        );
    });
});

describe('PROPERTY: Device-Bound Policy Invariants', () => {
    it('when not required, always permits regardless of backup status', () => {
        fc.assert(
            fc.property(fc.boolean(), (backupEligible) => {
                return checkDeviceBound(backupEligible, false).ok === true;
            }),
            { numRuns: 50 }
        );
    });

    it('when required, device-bound (BE=false) always passes', () => {
        expect(checkDeviceBound(false, true).ok).toBe(true);
    });

    it('when required, backup-eligible (BE=true) always fails', () => {
        const result = checkDeviceBound(true, true);
        expect(result.ok).toBe(false);
        expect(result.reason).toContain('backup-eligible');
    });

    it('combined: device-bound + any allowlist policy is consistent', () => {
        fc.assert(
            fc.property(
                aaguidArb,
                fc.boolean(),  // backupEligible
                fc.boolean(),  // requireDeviceBound
                fc.array(aaguidArb, { minLength: 0, maxLength: 3 }),  // allowlist
                (aaguid, backupEligible, requireDeviceBound, allowlist) => {
                    const aaguidResult = checkAaguidAllowed(aaguid, allowlist);
                    const deviceResult = checkDeviceBound(backupEligible, requireDeviceBound);

                    // Both checks must pass for overall acceptance
                    const overallAllowed = aaguidResult.ok && deviceResult.ok;

                    // If either rejects, the overall result rejects
                    if (!aaguidResult.ok || !deviceResult.ok) {
                        return overallAllowed === false;
                    }
                    return overallAllowed === true;
                }
            ),
            { numRuns: 200 }
        );
    });
});
