//! ISO/IEC 18013-5:2021 Annex D official test vectors (real spec data).
//!
//! Complements the synthetic rcgen tests in `verifier.rs`: those cover chain
//! anchoring and every rejection path; these prove parse/digests/Sig_Structure/
//! binding against ISO's own authoritative bytes.
//!
//! The credential is EXPIRED (validUntil 2021-10-01) — never call
//! temporal validity checks on it. Full `verify_issuer_signature` with trust-store
//! anchoring is NOT testable here: ISO does not publish the IACA root.

use super::*;

const ISSUER_SIGNED_B64URL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test_data/mdoc/issuer_signed.b64url"
));

const SIG_STRUCTURE_HEX: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/test_data/mdoc/sig_structure.hex"
));

// ISO 18013-5:2021 Annex D §D.4.1.2 device key public coordinates (P-256).
const DEVICE_KEY_X_HEX: &str = "96313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a";
const DEVICE_KEY_Y_HEX: &str = "1fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d6";

fn hx(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("Annex D hex must be valid"))
        .collect()
}

#[test]
fn annex_d_issuer_signed_parses() {
    let mdoc =
        ParsedMdoc::parse(ISSUER_SIGNED_B64URL.trim()).expect("Annex D IssuerSigned must parse");

    assert_eq!(mdoc.doc_type, "org.iso.18013.5.1.mDL");
    assert_eq!(mdoc.digest_algorithm, DigestAlgorithm::Sha256);
    assert!(
        mdoc.value_digests.contains_key("org.iso.18013.5.1"),
        "must have org.iso.18013.5.1 namespace"
    );
    assert!(
        mdoc.value_digests.contains_key("org.iso.18013.5.1.US"),
        "must have org.iso.18013.5.1.US namespace"
    );
}

#[test]
fn annex_d_digests_match() {
    let mdoc =
        ParsedMdoc::parse(ISSUER_SIGNED_B64URL.trim()).expect("Annex D IssuerSigned must parse");

    verify_digests(&mdoc).expect("Annex D digests must verify against the MSO");
}

#[test]
fn annex_d_sig_structure_matches() {
    let mdoc =
        ParsedMdoc::parse(ISSUER_SIGNED_B64URL.trim()).expect("Annex D IssuerSigned must parse");
    let expected = hx(SIG_STRUCTURE_HEX);

    let actual = mdoc.cose_sign1.tbs_data(b"");

    assert_eq!(
        actual, expected,
        "tbs_data must equal the spec Sig_Structure byte-for-byte"
    );
}

#[test]
fn annex_d_device_key_binding_matches() {
    let mdoc =
        ParsedMdoc::parse(ISSUER_SIGNED_B64URL.trim()).expect("Annex D IssuerSigned must parse");
    let jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(hx(DEVICE_KEY_X_HEX)),
            y: B64::new(hx(DEVICE_KEY_Y_HEX)),
            d: None,
        }),
        prm: Parameters::default(),
    };

    verify_device_key_binding(&mdoc, &jwk)
        .expect("Annex D device key must match its own coordinates");
}

#[test]
fn annex_d_device_key_binding_rejects_flipped_coordinate() {
    let mdoc =
        ParsedMdoc::parse(ISSUER_SIGNED_B64URL.trim()).expect("Annex D IssuerSigned must parse");
    let mut x = hx(DEVICE_KEY_X_HEX);
    x[0] ^= 0xff;
    let jwk = Jwk {
        key: Key::Ec(Ec {
            crv: Curve::P256,
            x: B64::new(x),
            y: B64::new(hx(DEVICE_KEY_Y_HEX)),
            d: None,
        }),
        prm: Parameters::default(),
    };

    let err =
        verify_device_key_binding(&mdoc, &jwk).expect_err("flipped x coordinate must be rejected");

    assert!(
        matches!(err, MdocError::DeviceKeyMismatch),
        "expected DeviceKeyMismatch, got: {err:?}"
    );
}
