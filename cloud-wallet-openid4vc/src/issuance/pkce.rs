//! PKCE (Proof Key for Code Exchange) utilities for OID4VC flows.
//!
//! Implements [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) code verifier
//! and S256 code challenge generation.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generates a PKCE `code_verifier`.
///
/// Produces 32 cryptographically random bytes encoded as base64url without padding.
/// The result is 43 characters long, satisfying [RFC 7636 §4.1] (43–128 chars).
pub fn generate_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Derives the PKCE S256 `code_challenge` from a `code_verifier`.
///
/// Computes `BASE64URL(SHA-256(ASCII(code_verifier)))` per [RFC 7636 §4.2].
pub fn derive_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7636 §B.2 example values.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn rfc7636_s256_example() {
        assert_eq!(derive_challenge(RFC_VERIFIER), RFC_CHALLENGE);
    }

    #[test]
    fn verifier_length_is_43() {
        // 32 bytes → 43 base64url chars (no padding).
        let v = generate_verifier();
        assert_eq!(v.len(), 43);
    }

    #[test]
    fn verifier_charset_is_base64url() {
        let v = generate_verifier();
        assert!(
            v.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "verifier contains invalid chars: {v}"
        );
    }

    #[test]
    fn challenge_has_no_padding() {
        let challenge = derive_challenge(&generate_verifier());
        assert!(
            !challenge.contains('='),
            "challenge must not contain padding: {challenge}"
        );
    }

    #[test]
    fn challenge_is_deterministic() {
        let verifier = generate_verifier();
        assert_eq!(derive_challenge(&verifier), derive_challenge(&verifier));
    }

    #[test]
    fn challenge_charset_is_base64url() {
        let challenge = derive_challenge(&generate_verifier());
        assert!(
            challenge
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "challenge contains invalid chars: {challenge}"
        );
    }
}
