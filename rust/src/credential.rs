//! WebAuthn credential parsing and policy enforcement.
//!
//! Parses CBOR attestation objects to extract AAGUID and backup flags,
//! then checks them against configurable policies (allowlist, device-bound).

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ciborium::Value as CborValue;
use subtle::ConstantTimeEq;

use crate::types::DeviceInfo;

/// Parse a base64-encoded attestationObject and extract device info.
///
/// The attestationObject is CBOR-encoded per W3C WebAuthn §6.5.4:
/// ```text
/// { "fmt": text, "attStmt": map, "authData": bytes }
/// ```
pub fn parse_attestation_object(b64: &str) -> Result<DeviceInfo, String> {
    // Try both standard and URL-safe base64
    let bytes = STANDARD
        .decode(b64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(b64))
        .map_err(|e| format!("Invalid base64: {e}"))?;

    let cbor: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| format!("Invalid CBOR: {e}"))?;

    let map = cbor.as_map().ok_or("attestationObject is not a CBOR map")?;

    // Find authData field
    let auth_data_bytes = map
        .iter()
        .find_map(|(k, v)| {
            let key = k.as_text()?;
            if key == "authData" {
                v.as_bytes()
            } else {
                None
            }
        })
        .ok_or("Missing authData in attestationObject")?;

    parse_auth_data(auth_data_bytes)
}

/// Parse raw authenticatorData bytes into DeviceInfo.
///
/// Layout (W3C WebAuthn §6.1):
/// ```text
/// rpIdHash[32] | flags[1] | signCount[4] | [attestedCredentialData] | [extensions]
/// ```
///
/// Flags byte:
/// - bit 0 (0x01): UP (User Present)
/// - bit 2 (0x04): UV (User Verified)
/// - bit 3 (0x08): BE (Backup Eligible)
/// - bit 4 (0x10): BS (Backup State)
/// - bit 6 (0x40): AT (Attested Credential Data included)
/// - bit 7 (0x80): ED (Extension Data included)
pub fn parse_auth_data(bytes: &[u8]) -> Result<DeviceInfo, String> {
    // Minimum: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37 bytes
    if bytes.len() < 37 {
        return Err(format!(
            "authData too short: {} bytes (minimum 37)",
            bytes.len()
        ));
    }

    let flags = bytes[32];
    let user_verified = flags & 0x04 != 0;
    let backup_eligible = flags & 0x08 != 0;
    let backup_state = flags & 0x10 != 0;
    let has_attested_cred = flags & 0x40 != 0;

    let aaguid = if has_attested_cred {
        // AAGUID starts at byte 37, length 16
        if bytes.len() < 55 {
            return Err(format!(
                "authData has AT flag but too short for AAGUID: {} bytes",
                bytes.len()
            ));
        }
        format_aaguid(&bytes[37..53])
    } else {
        "00000000-0000-0000-0000-000000000000".to_string()
    };

    Ok(DeviceInfo {
        aaguid,
        backup_eligible,
        backup_state,
        user_verified,
    })
}

/// Format 16 bytes as a UUID string (8-4-4-4-12).
pub fn format_aaguid(bytes: &[u8]) -> String {
    assert!(bytes.len() >= 16, "AAGUID must be at least 16 bytes");
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Check if the AAGUID is in the allowlist. Empty allowlist permits all.
///
/// Uses constant-time comparison to prevent timing side-channels that could
/// leak which AAGUIDs are in the allowlist.
pub fn check_aaguid_allowed(aaguid: &str, allowlist: &[String]) -> Result<(), String> {
    if allowlist.is_empty() {
        return Ok(());
    }
    let lower = aaguid.to_lowercase();
    let lower_bytes = lower.as_bytes();

    // Always iterate all entries — no short-circuit.
    let mut found = 0u8;
    for allowed in allowlist {
        let allowed_bytes = allowed.as_bytes();
        if lower_bytes.len() == allowed_bytes.len() {
            // ct_eq returns Choice; bitwise-OR accumulates matches
            found |= lower_bytes.ct_eq(allowed_bytes).unwrap_u8();
        }
    }

    if found != 0 {
        Ok(())
    } else {
        Err(format!(
            "AAGUID {aaguid} not in allowlist ({} allowed)",
            allowlist.len()
        ))
    }
}

/// Parse base64-encoded clientDataJSON and validate the origin.
///
/// clientDataJSON (W3C WebAuthn §5.8.1) is a JSON object with:
/// ```json
/// { "type": "webauthn.create", "challenge": "...", "origin": "https://example.com" }
/// ```
///
/// The `expected_origins` list contains allowed origins (e.g., FRONTEND_URL,
/// or all CDN origins in multi-origin mode). An empty list skips origin validation.
pub fn validate_client_data_origin(b64: &str, expected_origins: &[&str]) -> Result<String, String> {
    let bytes = STANDARD
        .decode(b64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(b64))
        .map_err(|e| format!("Invalid clientDataJSON base64: {e}"))?;

    let json_str =
        std::str::from_utf8(&bytes).map_err(|e| format!("clientDataJSON not UTF-8: {e}"))?;

    let parsed: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("clientDataJSON not valid JSON: {e}"))?;

    let origin = parsed
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or("clientDataJSON missing 'origin' field")?;

    if !expected_origins.is_empty() && !expected_origins.contains(&origin) {
        return Err(format!(
            "clientDataJSON origin mismatch: got '{}', expected one of {:?}",
            origin, expected_origins
        ));
    }

    Ok(origin.to_string())
}

/// Check if the credential satisfies the device-bound requirement.
/// When `require` is true, credentials with BE=true (backup eligible / syncable) are rejected.
pub fn check_device_bound(device: &DeviceInfo, require: bool) -> Result<(), String> {
    if require && device.backup_eligible {
        Err("Device-bound credential required, but this credential is backup-eligible (synced/syncable)".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    /// Build minimal authenticator data with given flags and optional AAGUID.
    fn build_auth_data(flags: u8, aaguid: Option<[u8; 16]>) -> Vec<u8> {
        let mut data = vec![0u8; 32]; // rpIdHash
        data.push(flags);
        data.extend_from_slice(&[0, 0, 0, 0]); // signCount = 0
        if let Some(aaguid_bytes) = aaguid {
            data.extend_from_slice(&aaguid_bytes);
            // credIdLen (2 bytes) + empty credId
            data.extend_from_slice(&[0, 0]);
        }
        data
    }

    /// Build a minimal CBOR attestation object from auth data.
    fn build_attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let cbor = CborValue::Map(vec![
            (
                CborValue::Text("fmt".into()),
                CborValue::Text("none".into()),
            ),
            (CborValue::Text("attStmt".into()), CborValue::Map(vec![])),
            (
                CborValue::Text("authData".into()),
                CborValue::Bytes(auth_data.to_vec()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor, &mut buf).unwrap();
        buf
    }

    // YubiKey 5 series AAGUID
    const YUBIKEY_5_AAGUID: [u8; 16] = [
        0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54,
        0xa8,
    ];

    #[test]
    fn test_format_aaguid() {
        let formatted = format_aaguid(&YUBIKEY_5_AAGUID);
        assert_eq!(formatted, "cb69481e-8ff7-4039-93ec-0a2729a154a8");
    }

    #[test]
    fn test_format_aaguid_zeros() {
        let zeros = [0u8; 16];
        assert_eq!(
            format_aaguid(&zeros),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn test_parse_auth_data_with_at_flag() {
        // UP + UV + AT flags
        let auth_data = build_auth_data(0x01 | 0x04 | 0x40, Some(YUBIKEY_5_AAGUID));
        let device = parse_auth_data(&auth_data).unwrap();
        assert_eq!(device.aaguid, "cb69481e-8ff7-4039-93ec-0a2729a154a8");
        assert!(device.user_verified);
        assert!(!device.backup_eligible);
        assert!(!device.backup_state);
    }

    #[test]
    fn test_parse_auth_data_backup_flags() {
        // UP + BE + BS + AT
        let auth_data = build_auth_data(0x01 | 0x08 | 0x10 | 0x40, Some(YUBIKEY_5_AAGUID));
        let device = parse_auth_data(&auth_data).unwrap();
        assert!(device.backup_eligible);
        assert!(device.backup_state);
        assert!(!device.user_verified);
    }

    #[test]
    fn test_parse_auth_data_no_at_flag() {
        // UP + UV only — no attested credential data
        let auth_data = build_auth_data(0x01 | 0x04, None);
        let device = parse_auth_data(&auth_data).unwrap();
        assert_eq!(device.aaguid, "00000000-0000-0000-0000-000000000000");
        assert!(device.user_verified);
    }

    #[test]
    fn test_parse_auth_data_too_short() {
        let result = parse_auth_data(&[0u8; 10]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_parse_auth_data_at_flag_but_truncated() {
        // AT flag set but data too short for AAGUID
        let mut data = vec![0u8; 37];
        data[32] = 0x40; // AT flag
        let result = parse_auth_data(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short for AAGUID"));
    }

    #[test]
    fn test_parse_attestation_object() {
        let auth_data = build_auth_data(0x01 | 0x04 | 0x40, Some(YUBIKEY_5_AAGUID));
        let cbor = build_attestation_object(&auth_data);
        let b64 = STANDARD.encode(&cbor);

        let device = parse_attestation_object(&b64).unwrap();
        assert_eq!(device.aaguid, "cb69481e-8ff7-4039-93ec-0a2729a154a8");
        assert!(device.user_verified);
    }

    #[test]
    fn test_parse_attestation_object_url_safe_base64() {
        let auth_data = build_auth_data(0x01 | 0x04 | 0x40, Some(YUBIKEY_5_AAGUID));
        let cbor = build_attestation_object(&auth_data);
        let b64 = URL_SAFE_NO_PAD.encode(&cbor);

        let device = parse_attestation_object(&b64).unwrap();
        assert_eq!(device.aaguid, "cb69481e-8ff7-4039-93ec-0a2729a154a8");
    }

    #[test]
    fn test_parse_attestation_object_invalid_base64() {
        let result = parse_attestation_object("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_aaguid_allowed_empty_list() {
        assert!(check_aaguid_allowed("anything", &[]).is_ok());
    }

    #[test]
    fn test_check_aaguid_allowed_in_list() {
        let list = vec!["cb69481e-8ff7-4039-93ec-0a2729a154a8".to_string()];
        assert!(check_aaguid_allowed("cb69481e-8ff7-4039-93ec-0a2729a154a8", &list).is_ok());
    }

    #[test]
    fn test_check_aaguid_allowed_case_insensitive() {
        let list = vec!["cb69481e-8ff7-4039-93ec-0a2729a154a8".to_string()];
        assert!(check_aaguid_allowed("CB69481E-8FF7-4039-93EC-0A2729A154A8", &list).is_ok());
    }

    #[test]
    fn test_check_aaguid_not_in_list() {
        let list = vec!["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string()];
        let result = check_aaguid_allowed("cb69481e-8ff7-4039-93ec-0a2729a154a8", &list);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowlist"));
    }

    #[test]
    fn test_check_device_bound_not_required() {
        let device = DeviceInfo {
            aaguid: "test".into(),
            backup_eligible: true,
            backup_state: true,
            user_verified: true,
        };
        assert!(check_device_bound(&device, false).is_ok());
    }

    #[test]
    fn test_check_device_bound_required_and_device_bound() {
        let device = DeviceInfo {
            aaguid: "test".into(),
            backup_eligible: false,
            backup_state: false,
            user_verified: true,
        };
        assert!(check_device_bound(&device, true).is_ok());
    }

    #[test]
    fn test_check_device_bound_required_but_syncable() {
        let device = DeviceInfo {
            aaguid: "test".into(),
            backup_eligible: true,
            backup_state: false,
            user_verified: true,
        };
        let result = check_device_bound(&device, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("backup-eligible"));
    }

    /// Helper: create base64-encoded clientDataJSON
    fn encode_client_data(json: &str) -> String {
        STANDARD.encode(json.as_bytes())
    }

    #[test]
    fn test_validate_origin_matching() {
        let b64 = encode_client_data(
            r#"{"type":"webauthn.create","challenge":"abc","origin":"https://example.com"}"#,
        );
        let result = validate_client_data_origin(&b64, &["https://example.com"]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com");
    }

    #[test]
    fn test_validate_origin_mismatch() {
        let b64 = encode_client_data(
            r#"{"type":"webauthn.create","challenge":"abc","origin":"https://evil.com"}"#,
        );
        let result = validate_client_data_origin(&b64, &["https://example.com"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("origin mismatch"));
    }

    #[test]
    fn test_validate_origin_empty_allowlist_skips() {
        let b64 = encode_client_data(
            r#"{"type":"webauthn.create","challenge":"abc","origin":"https://anything.com"}"#,
        );
        let result = validate_client_data_origin(&b64, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://anything.com");
    }

    #[test]
    fn test_validate_origin_multiple_allowed() {
        let b64 = encode_client_data(
            r#"{"type":"webauthn.create","challenge":"abc","origin":"https://app2.example.com"}"#,
        );
        let result = validate_client_data_origin(
            &b64,
            &["https://app1.example.com", "https://app2.example.com"],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_origin_missing_field() {
        let b64 = encode_client_data(r#"{"type":"webauthn.create","challenge":"abc"}"#);
        let result = validate_client_data_origin(&b64, &["https://example.com"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'origin'"));
    }

    #[test]
    fn test_validate_origin_invalid_base64() {
        let result = validate_client_data_origin("not-valid!!!", &["https://example.com"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("base64"));
    }

    #[test]
    fn test_validate_origin_invalid_json() {
        let b64 = STANDARD.encode(b"not json at all");
        let result = validate_client_data_origin(&b64, &["https://example.com"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not valid JSON"));
    }

    #[test]
    fn test_validate_origin_url_safe_base64() {
        let json = r#"{"type":"webauthn.create","challenge":"abc","origin":"https://example.com"}"#;
        let b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let result = validate_client_data_origin(&b64, &["https://example.com"]);
        assert!(result.is_ok());
    }
}
