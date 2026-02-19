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
