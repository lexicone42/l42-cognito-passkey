//! HMAC-SHA256 session cookie signing and verification.
//!
//! Cookie format: `base64url(session_id).base64url(hmac_signature)`
//!
//! Unlike the Python backend's `itsdangerous` format, this is a clean
//! scheme with no cross-language format dependency. The HMAC covers
//! only the session ID — the session data lives server-side.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Sign a session ID, returning the cookie value.
///
/// Format: `base64url(session_id).base64url(hmac(secret, session_id))`
pub fn sign_session_id(secret: &[u8], session_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key length is always valid");
    mac.update(session_id.as_bytes());
    let signature = mac.finalize().into_bytes();

    let id_encoded = URL_SAFE_NO_PAD.encode(session_id.as_bytes());
    let sig_encoded = URL_SAFE_NO_PAD.encode(signature);

    format!("{}.{}", id_encoded, sig_encoded)
}

/// Verify a signed cookie value and extract the session ID.
///
/// Returns `None` if the signature is invalid or the format is wrong.
pub fn verify_cookie(secret: &[u8], cookie_value: &str) -> Option<String> {
    let (id_part, sig_part) = cookie_value.split_once('.')?;

    let id_bytes = URL_SAFE_NO_PAD.decode(id_part).ok()?;
    let session_id = String::from_utf8(id_bytes).ok()?;

    let expected_sig = URL_SAFE_NO_PAD.decode(sig_part).ok()?;

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key length is always valid");
    mac.update(session_id.as_bytes());

    mac.verify_slice(&expected_sig).ok()?;

    Some(session_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let secret = b"test-secret-key";
        let session_id = "abc123-session-id";

        let cookie = sign_session_id(secret, session_id);
        let recovered = verify_cookie(secret, &cookie);

        assert_eq!(recovered, Some(session_id.to_string()));
    }

    #[test]
    fn test_wrong_secret_fails() {
        let cookie = sign_session_id(b"secret-a", "session-1");
        let result = verify_cookie(b"secret-b", &cookie);
        assert_eq!(result, None);
    }

    #[test]
    fn test_tampered_id_fails() {
        let secret = b"my-secret";
        let cookie = sign_session_id(secret, "real-session");

        // Tamper with the ID part
        let tampered = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(b"fake-session"),
            cookie.split_once('.').unwrap().1
        );
        assert_eq!(verify_cookie(secret, &tampered), None);
    }

    #[test]
    fn test_tampered_signature_fails() {
        let secret = b"my-secret";
        let cookie = sign_session_id(secret, "my-session");

        // Tamper with the signature
        let (id_part, _) = cookie.split_once('.').unwrap();
        let tampered = format!("{}.{}", id_part, URL_SAFE_NO_PAD.encode(b"bad-sig"));
        assert_eq!(verify_cookie(secret, &tampered), None);
    }

    #[test]
    fn test_empty_session_id() {
        let secret = b"secret";
        let cookie = sign_session_id(secret, "");
        let result = verify_cookie(secret, &cookie);
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn test_malformed_cookie_no_dot() {
        assert_eq!(verify_cookie(b"secret", "nodothere"), None);
    }

    #[test]
    fn test_malformed_cookie_bad_base64() {
        assert_eq!(verify_cookie(b"secret", "!!!.!!!"), None);
    }

    #[test]
    fn test_cookie_format_has_dot_separator() {
        let cookie = sign_session_id(b"s", "id");
        assert!(cookie.contains('.'));
        assert_eq!(cookie.matches('.').count(), 1);
    }

    #[test]
    fn test_special_characters_in_session_id() {
        let secret = b"secret";
        for id in &[
            "session/slashes",
            "session+plus",
            "spaces here",
            "long-id-aaaa",
            "\u{1F600}",
        ] {
            let cookie = sign_session_id(secret, id);
            assert_eq!(verify_cookie(secret, &cookie), Some(id.to_string()));
        }
    }

    #[test]
    fn test_deterministic_signing() {
        let secret = b"fixed-secret";
        let id = "fixed-id";
        let cookie1 = sign_session_id(secret, id);
        let cookie2 = sign_session_id(secret, id);
        assert_eq!(cookie1, cookie2);
    }
}
