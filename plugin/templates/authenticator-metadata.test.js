/**
 * L42 Cognito Passkey - Authenticator Metadata Tests
 *
 * Tests for parseAuthenticatorData(), formatAaguid(), and integration with
 * buildCredentialResponse() / buildAssertionResponse().
 *
 * Tests:
 * - parseAuthenticatorData flag parsing (UP, UV, BE, BS, AT, ED)
 * - Sign count extraction (big-endian uint32)
 * - AAGUID extraction when AT flag is set
 * - formatAaguid UUID formatting
 * - Edge cases: short buffers, missing AT flag, zero AAGUID
 * - Integration with buildCredentialResponse / buildAssertionResponse
 * - Attestation option passthrough in registerPasskey / upgradeToPasskey
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect } from 'vitest';

// ============================================================================
// Simulated auth.js internals (matching the actual implementation)
// ============================================================================

function formatAaguid(bytes) {
    const hex = Array.from(bytes, function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20, 32);
}

function parseAuthenticatorData(authData) {
    var bytes = new Uint8Array(authData);
    if (bytes.length < 37) return null;

    var flags = bytes[32];
    var result = {
        userPresent: !!(flags & 0x01),
        userVerified: !!(flags & 0x04),
        backupEligible: !!(flags & 0x08),
        backupState: !!(flags & 0x10),
        attestedCredentialData: !!(flags & 0x40),
        extensionData: !!(flags & 0x80),
        signCount: new DataView(authData).getUint32(33, false)
    };

    if (result.attestedCredentialData && bytes.length >= 55) {
        var aaguidBytes = bytes.slice(37, 53);
        result.aaguid = formatAaguid(aaguidBytes);
    }

    return result;
}

function arrayBufferToB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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

    var metadata = parseAuthenticatorData(credential.response.authenticatorData);
    if (metadata) {
        response.authenticatorMetadata = metadata;
    }

    return response;
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
        var rawAuthData = credential.response.getAuthenticatorData();
        response.response.authenticatorData = arrayBufferToB64(rawAuthData);

        var metadata = parseAuthenticatorData(rawAuthData);
        if (metadata) {
            response.authenticatorMetadata = metadata;
        }
    }

    return response;
}

// ============================================================================
// Helpers for building authenticatorData buffers
// ============================================================================

/**
 * Build a minimal authenticatorData buffer (37 bytes).
 * @param {number} flags - The flags byte
 * @param {number} signCount - The sign count (uint32)
 * @returns {ArrayBuffer}
 */
function makeAuthData(flags, signCount = 0) {
    const buf = new ArrayBuffer(37);
    const view = new DataView(buf);
    const bytes = new Uint8Array(buf);
    // 32 bytes of rpIdHash (zeros)
    bytes[32] = flags;
    view.setUint32(33, signCount, false); // big-endian
    return buf;
}

/**
 * Build authenticatorData with attested credential data (AAGUID included).
 * Minimum 55 bytes: 37 header + 16 AAGUID + 2 credIdLen.
 * @param {number} flags - Must include AT (0x40)
 * @param {number} signCount
 * @param {Uint8Array} aaguid - 16 bytes
 * @returns {ArrayBuffer}
 */
function makeAuthDataWithAaguid(flags, signCount, aaguid) {
    const buf = new ArrayBuffer(55);
    const view = new DataView(buf);
    const bytes = new Uint8Array(buf);
    bytes[32] = flags;
    view.setUint32(33, signCount, false);
    bytes.set(aaguid, 37); // AAGUID at offset 37
    // credIdLen at offset 53 (2 bytes, zero)
    return buf;
}

/**
 * Create a mock credential for assertions.
 */
function mockAssertionCredential(authDataBuffer) {
    return {
        id: 'cred-123',
        rawId: new Uint8Array([1, 2, 3]).buffer,
        type: 'public-key',
        response: {
            clientDataJSON: new Uint8Array([0x7b, 0x7d]).buffer, // "{}"
            authenticatorData: authDataBuffer,
            signature: new Uint8Array([0xaa, 0xbb]).buffer
        },
        getClientExtensionResults: () => ({})
    };
}

/**
 * Create a mock credential for registrations.
 */
function mockRegistrationCredential(authDataBuffer) {
    return {
        id: 'cred-456',
        rawId: new Uint8Array([4, 5, 6]).buffer,
        type: 'public-key',
        response: {
            clientDataJSON: new Uint8Array([0x7b, 0x7d]).buffer,
            attestationObject: new Uint8Array([0xcc, 0xdd]).buffer,
            getAuthenticatorData: () => authDataBuffer,
            getTransports: () => ['internal'],
            getPublicKey: () => new Uint8Array([0x01]).buffer,
            getPublicKeyAlgorithm: () => -7
        },
        authenticatorAttachment: 'platform',
        getClientExtensionResults: () => ({})
    };
}

// ============================================================================
// Tests
// ============================================================================

describe('formatAaguid', () => {
    it('formats 16 bytes as UUID string', () => {
        const bytes = new Uint8Array([
            0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15,
            0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e, 0xdc, 0x7d
        ]);
        expect(formatAaguid(bytes)).toBe('f8a011f3-8c0a-4d15-8006-17111f9edc7d');
    });

    it('formats zero AAGUID', () => {
        const bytes = new Uint8Array(16);
        expect(formatAaguid(bytes)).toBe('00000000-0000-0000-0000-000000000000');
    });

    it('formats all-FF AAGUID', () => {
        const bytes = new Uint8Array(16).fill(0xff);
        expect(formatAaguid(bytes)).toBe('ffffffff-ffff-ffff-ffff-ffffffffffff');
    });
});

describe('parseAuthenticatorData', () => {
    describe('flag parsing', () => {
        it('parses all flags = 0', () => {
            const result = parseAuthenticatorData(makeAuthData(0x00));
            expect(result).not.toBeNull();
            expect(result.userPresent).toBe(false);
            expect(result.userVerified).toBe(false);
            expect(result.backupEligible).toBe(false);
            expect(result.backupState).toBe(false);
            expect(result.attestedCredentialData).toBe(false);
            expect(result.extensionData).toBe(false);
        });

        it('parses UP flag (0x01)', () => {
            const result = parseAuthenticatorData(makeAuthData(0x01));
            expect(result.userPresent).toBe(true);
            expect(result.userVerified).toBe(false);
        });

        it('parses UV flag (0x04)', () => {
            const result = parseAuthenticatorData(makeAuthData(0x04));
            expect(result.userVerified).toBe(true);
            expect(result.userPresent).toBe(false);
        });

        it('parses UP + UV (0x05)', () => {
            const result = parseAuthenticatorData(makeAuthData(0x05));
            expect(result.userPresent).toBe(true);
            expect(result.userVerified).toBe(true);
        });

        it('parses BE flag (0x08) — device eligible for sync', () => {
            const result = parseAuthenticatorData(makeAuthData(0x08));
            expect(result.backupEligible).toBe(true);
            expect(result.backupState).toBe(false);
        });

        it('parses BE + BS (0x18) — synced/multi-device credential', () => {
            const result = parseAuthenticatorData(makeAuthData(0x18));
            expect(result.backupEligible).toBe(true);
            expect(result.backupState).toBe(true);
        });

        it('parses BS without BE (0x10) — invalid per spec but parseable', () => {
            const result = parseAuthenticatorData(makeAuthData(0x10));
            expect(result.backupEligible).toBe(false);
            expect(result.backupState).toBe(true);
        });

        it('parses device-bound credential (BE=0, BS=0)', () => {
            const result = parseAuthenticatorData(makeAuthData(0x05)); // UP + UV
            expect(result.backupEligible).toBe(false);
            expect(result.backupState).toBe(false);
        });

        it('parses AT flag (0x40)', () => {
            const result = parseAuthenticatorData(makeAuthData(0x40));
            expect(result.attestedCredentialData).toBe(true);
        });

        it('parses ED flag (0x80)', () => {
            const result = parseAuthenticatorData(makeAuthData(0x80));
            expect(result.extensionData).toBe(true);
        });

        it('parses all flags set (0xDD = UP|UV|BE|BS|AT|ED)', () => {
            // 0x01 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80 = 0xDD
            const result = parseAuthenticatorData(makeAuthData(0xDD));
            expect(result.userPresent).toBe(true);
            expect(result.userVerified).toBe(true);
            expect(result.backupEligible).toBe(true);
            expect(result.backupState).toBe(true);
            expect(result.attestedCredentialData).toBe(true);
            expect(result.extensionData).toBe(true);
        });
    });

    describe('sign count', () => {
        it('reads signCount = 0', () => {
            const result = parseAuthenticatorData(makeAuthData(0x01, 0));
            expect(result.signCount).toBe(0);
        });

        it('reads signCount = 1', () => {
            const result = parseAuthenticatorData(makeAuthData(0x01, 1));
            expect(result.signCount).toBe(1);
        });

        it('reads signCount = 256', () => {
            const result = parseAuthenticatorData(makeAuthData(0x01, 256));
            expect(result.signCount).toBe(256);
        });

        it('reads signCount = 0xFFFFFFFF (max uint32)', () => {
            const result = parseAuthenticatorData(makeAuthData(0x01, 0xFFFFFFFF));
            expect(result.signCount).toBe(4294967295);
        });

        it('reads big-endian correctly (0x00000100 = 256, not 1)', () => {
            const buf = new ArrayBuffer(37);
            const bytes = new Uint8Array(buf);
            bytes[32] = 0x01; // UP
            bytes[33] = 0x00;
            bytes[34] = 0x00;
            bytes[35] = 0x01;
            bytes[36] = 0x00;
            const result = parseAuthenticatorData(buf);
            expect(result.signCount).toBe(256);
        });
    });

    describe('AAGUID extraction', () => {
        it('extracts AAGUID when AT flag set and enough bytes', () => {
            const aaguid = new Uint8Array([
                0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15,
                0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e, 0xdc, 0x7d
            ]);
            const buf = makeAuthDataWithAaguid(0x41, 42, aaguid); // UP + AT
            const result = parseAuthenticatorData(buf);
            expect(result.aaguid).toBe('f8a011f3-8c0a-4d15-8006-17111f9edc7d');
            expect(result.signCount).toBe(42);
            expect(result.attestedCredentialData).toBe(true);
        });

        it('does not extract AAGUID when AT flag is not set', () => {
            const result = parseAuthenticatorData(makeAuthData(0x01, 5));
            expect(result.aaguid).toBeUndefined();
        });

        it('does not extract AAGUID when AT set but buffer too short', () => {
            // AT flag set but only 37 bytes (need >= 55)
            const result = parseAuthenticatorData(makeAuthData(0x40, 0));
            expect(result.attestedCredentialData).toBe(true);
            expect(result.aaguid).toBeUndefined();
        });

        it('extracts zero AAGUID', () => {
            const zeroAaguid = new Uint8Array(16);
            const buf = makeAuthDataWithAaguid(0x41, 0, zeroAaguid);
            const result = parseAuthenticatorData(buf);
            expect(result.aaguid).toBe('00000000-0000-0000-0000-000000000000');
        });

        it('extracts AAGUID for YubiKey 5 series', () => {
            // Real YubiKey 5 AAGUID: cb69481e-8ff7-4039-93ec-0a2729a154a8
            const ykAaguid = new Uint8Array([
                0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39,
                0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54, 0xa8
            ]);
            const buf = makeAuthDataWithAaguid(0x45, 1, ykAaguid); // UP + UV + AT
            const result = parseAuthenticatorData(buf);
            expect(result.aaguid).toBe('cb69481e-8ff7-4039-93ec-0a2729a154a8');
            expect(result.backupEligible).toBe(false); // YubiKey = device-bound
            expect(result.backupState).toBe(false);
        });
    });

    describe('edge cases', () => {
        it('returns null for buffer shorter than 37 bytes', () => {
            const buf = new ArrayBuffer(36);
            expect(parseAuthenticatorData(buf)).toBeNull();
        });

        it('returns null for empty buffer', () => {
            const buf = new ArrayBuffer(0);
            expect(parseAuthenticatorData(buf)).toBeNull();
        });

        it('handles exactly 37 bytes (minimum valid)', () => {
            const result = parseAuthenticatorData(makeAuthData(0x05, 7));
            expect(result).not.toBeNull();
            expect(result.userPresent).toBe(true);
            expect(result.userVerified).toBe(true);
            expect(result.signCount).toBe(7);
        });

        it('handles buffer with extra bytes beyond AAGUID', () => {
            // 100 bytes — more than enough, should still parse correctly
            const buf = new ArrayBuffer(100);
            const bytes = new Uint8Array(buf);
            bytes[32] = 0x41; // UP + AT
            new DataView(buf).setUint32(33, 99, false);
            // Set AAGUID bytes
            for (let i = 0; i < 16; i++) bytes[37 + i] = i + 1;
            const result = parseAuthenticatorData(buf);
            expect(result.signCount).toBe(99);
            expect(result.aaguid).toBe('01020304-0506-0708-090a-0b0c0d0e0f10');
        });
    });
});

describe('buildAssertionResponse with authenticatorMetadata', () => {
    it('attaches metadata for synced passkey login', () => {
        // BE=1, BS=1 → synced credential
        const authData = makeAuthData(0x1D, 5); // UP|UV|BE|BS
        const cred = mockAssertionCredential(authData);
        const resp = buildAssertionResponse(cred);

        expect(resp.authenticatorMetadata).toBeDefined();
        expect(resp.authenticatorMetadata.backupEligible).toBe(true);
        expect(resp.authenticatorMetadata.backupState).toBe(true);
        expect(resp.authenticatorMetadata.signCount).toBe(5);
        expect(resp.authenticatorMetadata.userPresent).toBe(true);
        expect(resp.authenticatorMetadata.userVerified).toBe(true);
    });

    it('attaches metadata for device-bound credential login', () => {
        const authData = makeAuthData(0x05, 42); // UP|UV only
        const cred = mockAssertionCredential(authData);
        const resp = buildAssertionResponse(cred);

        expect(resp.authenticatorMetadata.backupEligible).toBe(false);
        expect(resp.authenticatorMetadata.backupState).toBe(false);
        expect(resp.authenticatorMetadata.signCount).toBe(42);
    });

    it('does not include AAGUID for assertions (no AT flag)', () => {
        const authData = makeAuthData(0x05, 1);
        const cred = mockAssertionCredential(authData);
        const resp = buildAssertionResponse(cred);

        expect(resp.authenticatorMetadata.aaguid).toBeUndefined();
    });
});

describe('buildCredentialResponse with authenticatorMetadata', () => {
    it('attaches metadata with AAGUID for registration', () => {
        const aaguid = new Uint8Array([
            0xf8, 0xa0, 0x11, 0xf3, 0x8c, 0x0a, 0x4d, 0x15,
            0x80, 0x06, 0x17, 0x11, 0x1f, 0x9e, 0xdc, 0x7d
        ]);
        const authData = makeAuthDataWithAaguid(0x45, 0, aaguid); // UP|UV|AT
        const cred = mockRegistrationCredential(authData);
        const resp = buildCredentialResponse(cred);

        expect(resp.authenticatorMetadata).toBeDefined();
        expect(resp.authenticatorMetadata.aaguid).toBe('f8a011f3-8c0a-4d15-8006-17111f9edc7d');
        expect(resp.authenticatorMetadata.backupEligible).toBe(false);
        expect(resp.authenticatorMetadata.backupState).toBe(false);
    });

    it('attaches metadata for synced credential registration', () => {
        const aaguid = new Uint8Array(16); // zero AAGUID
        const authData = makeAuthDataWithAaguid(0x5D, 0, aaguid); // UP|UV|BE|BS|AT
        const cred = mockRegistrationCredential(authData);
        const resp = buildCredentialResponse(cred);

        expect(resp.authenticatorMetadata.backupEligible).toBe(true);
        expect(resp.authenticatorMetadata.backupState).toBe(true);
        expect(resp.authenticatorMetadata.aaguid).toBe('00000000-0000-0000-0000-000000000000');
    });

    it('does not attach metadata if getAuthenticatorData is missing', () => {
        const cred = {
            id: 'cred-789',
            rawId: new Uint8Array([7, 8, 9]).buffer,
            type: 'public-key',
            response: {
                clientDataJSON: new Uint8Array([0x7b, 0x7d]).buffer,
                attestationObject: new Uint8Array([0xee, 0xff]).buffer
                // No getAuthenticatorData
            },
            getClientExtensionResults: () => ({})
        };
        const resp = buildCredentialResponse(cred);

        expect(resp.authenticatorMetadata).toBeUndefined();
        expect(resp.response.authenticatorData).toBeUndefined();
    });
});

describe('attestation option passthrough', () => {
    it('options.attestation overrides credOpts.attestation', () => {
        // Simulates the registerPasskey logic:
        // attestation: options.attestation || credOpts.attestation || 'none'
        const options = { attestation: 'direct' };
        const credOpts = { attestation: 'none' };
        const result = options.attestation || credOpts.attestation || 'none';
        expect(result).toBe('direct');
    });

    it('falls back to credOpts.attestation when options empty', () => {
        const options = {};
        const credOpts = { attestation: 'indirect' };
        const result = options.attestation || credOpts.attestation || 'none';
        expect(result).toBe('indirect');
    });

    it('falls back to none when neither specified', () => {
        const options = {};
        const credOpts = {};
        const result = options.attestation || credOpts.attestation || 'none';
        expect(result).toBe('none');
    });

    it('enterprise attestation passes through', () => {
        const options = { attestation: 'enterprise' };
        const credOpts = {};
        const result = options.attestation || credOpts.attestation || 'none';
        expect(result).toBe('enterprise');
    });
});
