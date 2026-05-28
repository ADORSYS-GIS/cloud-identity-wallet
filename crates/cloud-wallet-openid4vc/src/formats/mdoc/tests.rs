use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::Value;
use cloud_wallet_crypto::digest::HashAlg;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::DigestAlgorithm;
use super::error::MdocError;
use super::parser::ParsedMdoc;
use super::verifier::verify_digests;

// CBOR construction helpers

/// Serialises a `ciborium::Value` to CBOR bytes; panics on encoding error
/// (should never occur for well-formed `Value` trees in tests).
fn cbor(val: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(val, &mut buf).expect("CBOR encoding must succeed in tests");
    buf
}

/// Builds a minimal but structurally complete `IssuerSigned` CBOR value and
/// returns it as an unpadded base64url string.
///
/// `valid_from_str` and `valid_until_str` are RFC 3339 strings placed verbatim
/// into `validityInfo`.  Using extreme values (`"2000-01-01T00:00:00Z"` for the
/// past, `"9998-01-01T00:00:00Z"` for the future) keeps tests deterministic.
fn build_issuer_signed(valid_from_str: &str, valid_until_str: &str) -> String {
    let default_digests = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![(
            Value::Integer(0u64.into()),
            Value::Bytes(vec![0u8; 32]),
        )]),
    )]);
    build_issuer_signed_full(
        valid_from_str,
        valid_until_str,
        "SHA-256",
        default_digests,
        "1.0",
        Some(vec![0u8; 16]),
    )
}

/// Full fixture builder used by parameterised tests.
///
/// - `digest_algorithm` is placed verbatim in the MSO `digestAlgorithm` field.
/// - `value_digests` is the complete `ciborium::Value` placed in `valueDigests`.
fn build_issuer_signed_full(
    valid_from_str: &str,
    valid_until_str: &str,
    digest_algorithm: &str,
    value_digests: Value,
    mso_version: &str,
    item_random: Option<Vec<u8>>,
) -> String {
    // IssuerSignedItem
    let item = {
        let mut fields = vec![(Value::Text("digestID".into()), Value::Integer(0u64.into()))];
        if let Some(random_bytes) = item_random {
            fields.push((Value::Text("random".into()), Value::Bytes(random_bytes)));
        }
        fields.push((
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ));
        fields.push((
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ));
        Value::Map(fields)
    };
    let item_bytes = cbor(&item);
    // #6.24(bstr) IssuerSignedItemBytes
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(item_bytes)));

    // MobileSecurityObject
    // Dummy EC P-256 device key (COSE_Key structure)
    let device_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])), // x
        (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])), // y
    ]);

    let mso = Value::Map(vec![
        (
            Value::Text("version".into()),
            Value::Text(mso_version.into()),
        ),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text(digest_algorithm.into()),
        ),
        (Value::Text("valueDigests".into()), value_digests),
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(Value::Text("deviceKey".into()), device_key)]),
        ),
        (
            Value::Text("docType".into()),
            Value::Text("org.iso.18013.5.1.mDL".into()),
        ),
        (
            Value::Text("validityInfo".into()),
            Value::Map(vec![
                (
                    Value::Text("signed".into()),
                    Value::Tag(0, Box::new(Value::Text("1999-01-01T00:00:00Z".into()))),
                ),
                (
                    Value::Text("validFrom".into()),
                    Value::Tag(0, Box::new(Value::Text(valid_from_str.into()))),
                ),
                (
                    Value::Text("validUntil".into()),
                    Value::Tag(0, Box::new(Value::Text(valid_until_str.into()))),
                ),
            ]),
        ),
    ]);

    let mso_bytes = cbor(&mso);

    // COSE_Sign1 ([protected_bstr, {}, payload_bstr, sig_bstr])
    // coset v0.3.x expects the untagged array when deserialising via from_slice.
    // Protected header: {1: -7} (alg: ES256) encoded as a bstr.
    // CBOR of {1: -7}: a1 01 26
    //   a1 = map(1), 01 = uint(1), 26 = nint(-7) [0x20 + (7-1) = 0x26]
    let protected_header_bytes = vec![0xa1u8, 0x01, 0x26];

    // ISO 18013-5 §9.1.2: COSE payload must be MobileSecurityObjectBytes
    // = #6.24(bstr .cbor MobileSecurityObject), not bare MSO bytes.
    let mso_payload = cbor(&Value::Tag(24, Box::new(Value::Bytes(mso_bytes))));

    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_header_bytes), // protected header bstr
        Value::Map(vec![]),                   // unprotected header {}
        Value::Bytes(mso_payload), // MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
        Value::Bytes(vec![0u8; 64]), // dummy 64-byte signature
    ]);

    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (
            Value::Text("issuerAuth".into()),
            Value::Tag(18, Box::new(cose_sign1)),
        ),
    ]);

    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

#[test]
fn parses_valid_mdoc() {
    // Arrange: validity window that always brackets "now"
    let raw = build_issuer_signed("2020-01-01T00:00:00Z", "9998-01-01T00:00:00Z");

    // Act
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse without error");

    // Assert: top-level fields
    assert_eq!(mdoc.doc_type, "org.iso.18013.5.1.mDL");

    // Assert: digest_algorithm is the enum variant, not a raw string
    assert_eq!(mdoc.digest_algorithm, DigestAlgorithm::Sha256);

    // Assert: namespace contains the single item we inserted
    let items = mdoc
        .name_spaces
        .get("org.iso.18013.5.1")
        .expect("namespace must be present");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].digest_id, 0);
    assert_eq!(items[0].element_identifier, "family_name");
    assert!(!items[0].raw_tag24_bytes.is_empty());

    // Assert: valueDigests contains the namespace
    assert!(mdoc.value_digests.contains_key("org.iso.18013.5.1"));
    assert!(mdoc.value_digests["org.iso.18013.5.1"].contains_key(&0));

    // Assert: device_key is non-empty CBOR bytes
    assert!(!mdoc.device_key.is_empty());

    // Assert: raw bytes are present
    assert!(!mdoc.raw_issuer_signed_bytes.is_empty());
}

#[test]
fn rejects_expired_mdoc() {
    // Arrange: validity window entirely in 2000; inject a "now" of 2000-01-03 — after expiry.
    let raw = build_issuer_signed("2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z");
    let now = OffsetDateTime::parse("2000-01-03T00:00:00Z", &Rfc3339)
        .expect("fixed timestamp must parse");

    // Act
    let mdoc = ParsedMdoc::parse(&raw).expect("parse must succeed regardless of validity window");
    let err = mdoc
        .check_temporal_validity(now)
        .expect_err("expired mdoc should be rejected");

    assert!(
        matches!(err, MdocError::ExpiredCredential { .. }),
        "expected ExpiredCredential, got: {err:?}"
    );
}

#[test]
fn rejects_not_yet_valid_mdoc() {
    // Arrange: validity window starts 9997; inject a "now" of 2026 — before valid_from.
    let raw = build_issuer_signed("9997-01-01T00:00:00Z", "9998-01-01T00:00:00Z");
    let now = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339)
        .expect("fixed timestamp must parse");

    // Act
    let mdoc = ParsedMdoc::parse(&raw).expect("parse must succeed regardless of validity window");
    let err = mdoc
        .check_temporal_validity(now)
        .expect_err("not-yet-valid mdoc should be rejected");

    assert!(
        matches!(err, MdocError::NotYetValid { .. }),
        "expected NotYetValid, got: {err:?}"
    );
}

#[test]
fn parse_and_validate_accepts_valid_mdoc() {
    // Arrange: validity window that brackets the injected "now".
    let raw = build_issuer_signed("2020-01-01T00:00:00Z", "9998-01-01T00:00:00Z");
    let now = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339)
        .expect("fixed timestamp must parse");

    // Act + Assert: must succeed and return a fully parsed mdoc.
    let mdoc =
        ParsedMdoc::parse_and_validate(&raw, now).expect("valid mdoc should pass validation");
    assert_eq!(mdoc.doc_type, "org.iso.18013.5.1.mDL");
}

#[test]
fn parse_and_validate_rejects_expired() {
    // Arrange: validity window in the past; inject a "now" after expiry.
    let raw = build_issuer_signed("2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z");
    let now = OffsetDateTime::parse("2000-01-03T00:00:00Z", &Rfc3339)
        .expect("fixed timestamp must parse");

    // Act
    let err = ParsedMdoc::parse_and_validate(&raw, now)
        .expect_err("expired mdoc should be rejected by parse_and_validate");

    assert!(
        matches!(err, MdocError::ExpiredCredential { .. }),
        "expected ExpiredCredential, got: {err:?}"
    );
}

#[test]
fn rejects_invalid_base64() {
    // Arrange: contains characters illegal in base64url
    let raw = "not!!valid!!base64url";

    let err = ParsedMdoc::parse(raw).expect_err("invalid base64 should be rejected");

    assert!(
        matches!(err, MdocError::InvalidBase64 { .. }),
        "expected InvalidBase64, got: {err:?}"
    );
}

#[test]
fn rejects_malformed_cbor() {
    // Arrange: valid base64url but the decoded bytes are empty — guaranteed CborDecode (EOF)
    let raw = Base64UrlUnpadded::encode_string(b"");

    let err = ParsedMdoc::parse(&raw).expect_err("malformed CBOR should be rejected");

    assert!(
        matches!(err, MdocError::CborDecode { .. }),
        "expected CborDecode, got: {err:?}"
    );
}

#[test]
fn rejects_duplicate_map_key() {
    // Arrange: top-level IssuerSigned map with "nameSpaces" appearing twice.
    // The COSE_Sign1 is a placeholder — parsing must fail before it is decoded
    // because the duplicate check runs on the first take_entry call.
    let issuer_signed = Value::Map(vec![
        (Value::Text("nameSpaces".into()), Value::Map(vec![])),
        (Value::Text("nameSpaces".into()), Value::Map(vec![])),
        (Value::Text("issuerAuth".into()), Value::Array(vec![])),
    ]);
    let raw = Base64UrlUnpadded::encode_string(&cbor(&issuer_signed));

    let err = ParsedMdoc::parse(&raw).expect_err("duplicate map key should be rejected");

    assert!(
        matches!(err, MdocError::DuplicateMapKey { key: "nameSpaces" }),
        "expected DuplicateMapKey {{ key: \"nameSpaces\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_unsupported_digest_algorithm() {
    // Arrange: mDoc with "SHA-1" in the MSO digestAlgorithm field.
    // ISO 18013-5 §9.1.2.5 permits only SHA-256, SHA-384, and SHA-512.
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-1",
        Value::Map(vec![(
            Value::Text("org.iso.18013.5.1".into()),
            Value::Map(vec![(
                Value::Integer(0u64.into()),
                Value::Bytes(vec![0u8; 20]),
            )]),
        )]),
        "1.0",
        Some(vec![0u8; 16]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("unsupported digest algorithm should be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::UnsupportedDigestAlgorithm { ref algorithm } if algorithm == "SHA-1"),
        "expected UnsupportedDigestAlgorithm(\"SHA-1\"), got: {err:?}"
    );
}

#[test]
fn accepts_sha512_digest_algorithm() {
    // SHA-512 is permitted per ISO 18013-5 §9.1.2.5; must not be rejected.
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-512",
        Value::Map(vec![(
            Value::Text("org.iso.18013.5.1".into()),
            Value::Map(vec![(
                Value::Integer(0u64.into()),
                Value::Bytes(vec![0u8; 64]),
            )]),
        )]),
        "1.0",
        Some(vec![0u8; 16]),
    );

    let mdoc = ParsedMdoc::parse(&raw).expect("SHA-512 should be accepted");
    assert_eq!(mdoc.digest_algorithm, DigestAlgorithm::Sha512);
}

#[test]
fn rejects_unsupported_mso_version() {
    // Arrange: MSO with major version "2"; §8.1 requires rejecting unknown major versions.
    let default_digests = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![(
            Value::Integer(0u64.into()),
            Value::Bytes(vec![0u8; 32]),
        )]),
    )]);
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        default_digests,
        "2.0",
        Some(vec![0u8; 16]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("version 2.0 should be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::UnsupportedMsoVersion { ref version } if version == "2.0"),
        "expected UnsupportedMsoVersion(\"2.0\"), got: {err:?}"
    );
}

#[test]
fn rejects_duplicate_digest_id() {
    // Arrange: valueDigests map where digestID 0 appears twice for the same namespace.
    // RFC 8949 §5.6 and OWASP A03 require rejecting duplicate map keys in
    // security-sensitive structures; silent overwrite would allow digest substitution.
    let duplicate_digests = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![
            (Value::Integer(0u64.into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer(0u64.into()), Value::Bytes(vec![1u8; 32])), // duplicate
        ]),
    )]);
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        duplicate_digests,
        "1.0",
        Some(vec![0u8; 16]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("duplicate digestID should be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::DuplicateMapKey { key: "digestID" }),
        "expected DuplicateMapKey {{ key: \"digestID\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_duplicate_namespace_in_value_digests() {
    // Arrange: valueDigests map with the same namespace key appearing twice.
    // The second entry would silently overwrite the first, hiding the first set
    // of digests from subsequent verification.
    let duplicate_ns = Value::Map(vec![
        (
            Value::Text("org.iso.18013.5.1".into()),
            Value::Map(vec![(
                Value::Integer(0u64.into()),
                Value::Bytes(vec![0u8; 32]),
            )]),
        ),
        (
            Value::Text("org.iso.18013.5.1".into()), // duplicate namespace key
            Value::Map(vec![(
                Value::Integer(1u64.into()),
                Value::Bytes(vec![1u8; 32]),
            )]),
        ),
    ]);
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        duplicate_ns,
        "1.0",
        Some(vec![0u8; 16]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("duplicate namespace key should be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::DuplicateMapKey { key: "namespace" }),
        "expected DuplicateMapKey {{ key: \"namespace\" }}, got: {err:?}"
    );
}

// ── digest-verification helpers ──────────────────────────────────────────────

/// Builds the `#6.24(bstr .cbor IssuerSignedItem)` encoding for one item
/// and returns `(raw_tag24_bytes, real_sha256_digest)`.
///
/// This mirrors exactly what `parse_issuer_signed_item` stores in
/// `IssuerSignedItem::raw_tag24_bytes` so that the digest computed here will
/// match what `verify_digests` recomputes.
fn item_tag24_and_digest(
    digest_id: u64,
    element_identifier: &str,
    element_value: &str,
    alg: HashAlg,
) -> (Vec<u8>, Vec<u8>) {
    let item = Value::Map(vec![
        (
            Value::Text("digestID".into()),
            Value::Integer(digest_id.into()),
        ),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text(element_identifier.into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text(element_value.into()),
        ),
    ]);

    let inner_bytes = cbor(&item);
    let tag24 = Value::Tag(24, Box::new(Value::Bytes(inner_bytes)));
    let raw_tag24_bytes = cbor(&tag24);

    let digest = alg.hash(&raw_tag24_bytes);
    (raw_tag24_bytes, digest.as_ref().to_vec())
}

/// Builds a complete `IssuerSigned` base64url string whose `valueDigests` entries
/// are the real hashes (using `alg`) of the corresponding `#6.24` item encodings.
///
/// The single item has `digestID = 0`, `elementIdentifier = "family_name"`,
/// `elementValue = "Doe"`.
fn build_issuer_signed_with_correct_digests_for(alg: HashAlg, alg_str: &str) -> String {
    let (item_tag24_bytes, digest_bytes) = item_tag24_and_digest(0, "family_name", "Doe", alg);

    // Reconstruct the #6.24 value for embedding in nameSpaces.
    let item_tag24_val: Value =
        ciborium::de::from_reader(item_tag24_bytes.as_slice()).expect("round-trip must succeed");

    let device_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])),
        (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])),
    ]);

    let mso = Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text(alg_str.into()),
        ),
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Map(vec![(
                    Value::Integer(0u64.into()),
                    Value::Bytes(digest_bytes),
                )]),
            )]),
        ),
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(Value::Text("deviceKey".into()), device_key)]),
        ),
        (
            Value::Text("docType".into()),
            Value::Text("org.iso.18013.5.1.mDL".into()),
        ),
        (
            Value::Text("validityInfo".into()),
            Value::Map(vec![
                (
                    Value::Text("signed".into()),
                    Value::Tag(0, Box::new(Value::Text("1999-01-01T00:00:00Z".into()))),
                ),
                (
                    Value::Text("validFrom".into()),
                    Value::Tag(0, Box::new(Value::Text("2020-01-01T00:00:00Z".into()))),
                ),
                (
                    Value::Text("validUntil".into()),
                    Value::Tag(0, Box::new(Value::Text("9998-01-01T00:00:00Z".into()))),
                ),
            ]),
        ),
    ]);

    let mso_bytes = cbor(&mso);
    let protected_header_bytes = vec![0xa1u8, 0x01, 0x26];
    let mso_payload = cbor(&Value::Tag(24, Box::new(Value::Bytes(mso_bytes))));

    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_header_bytes),
        Value::Map(vec![]),
        Value::Bytes(mso_payload),
        Value::Bytes(vec![0u8; 64]),
    ]);

    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24_val]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);

    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

/// Builds a complete `IssuerSigned` base64url string whose `valueDigests` entries
/// are the real SHA-256 hashes of the corresponding `#6.24` item encodings.
///
/// The single item has `digestID = 0`, `elementIdentifier = "family_name"`,
/// `elementValue = "Doe"`.
fn build_issuer_signed_with_correct_digests() -> String {
    build_issuer_signed_with_correct_digests_for(HashAlg::Sha256, "SHA-256")
}

// ── verify_digests tests ──────────────────────────────────────────────────────

#[test]
fn verify_digests_passes_for_all_valid() {
    // Arrange: mdoc whose valueDigests contain the real SHA-256 of each item
    let raw = build_issuer_signed_with_correct_digests();
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse");

    // Act
    let result = verify_digests(&mdoc);

    // Assert
    assert!(result.is_ok(), "all valid digests should pass: {result:?}");
}

#[test]
fn verify_digests_passes_sha384() {
    // Arrange: mdoc whose valueDigests contain the real SHA-384 of each item
    let raw = build_issuer_signed_with_correct_digests_for(HashAlg::Sha384, "SHA-384");
    let mdoc = ParsedMdoc::parse(&raw).expect("valid SHA-384 mdoc should parse");
    assert_eq!(mdoc.digest_algorithm, DigestAlgorithm::Sha384);

    // Act
    let result = verify_digests(&mdoc);

    // Assert
    assert!(result.is_ok(), "SHA-384 digests should pass: {result:?}");
}

#[test]
fn verify_digests_passes_sha512() {
    // Arrange: mdoc whose valueDigests contain the real SHA-512 of each item
    let raw = build_issuer_signed_with_correct_digests_for(HashAlg::Sha512, "SHA-512");
    let mdoc = ParsedMdoc::parse(&raw).expect("valid SHA-512 mdoc should parse");
    assert_eq!(mdoc.digest_algorithm, DigestAlgorithm::Sha512);

    // Act
    let result = verify_digests(&mdoc);

    // Assert
    assert!(result.is_ok(), "SHA-512 digests should pass: {result:?}");
}

#[test]
fn verify_digests_rejects_tampered_item() {
    // Arrange: parse a valid mdoc, then corrupt the raw bytes of the first item
    let raw = build_issuer_signed_with_correct_digests();
    let mut mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse");

    let items = mdoc
        .name_spaces
        .get_mut("org.iso.18013.5.1")
        .expect("namespace must be present");
    // Flip the last byte of raw_tag24_bytes — the digest will no longer match.
    let last = items[0]
        .raw_tag24_bytes
        .last_mut()
        .expect("bytes non-empty");
    *last ^= 0xFF;

    // Act
    let err = verify_digests(&mdoc).expect_err("tampered item must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::DigestMismatch { ref namespace, digest_id: 0 } if namespace == "org.iso.18013.5.1"),
        "expected DigestMismatch {{ namespace: org.iso.18013.5.1, digest_id: 0 }}, got: {err:?}"
    );
}

#[test]
fn rejects_wrong_digest_length() {
    // Arrange: SHA-256 MSO but digest bytes are 64 bytes (SHA-512 size).
    // ISO 18013-5 §9.1.2.5: digest length must match the declared algorithm.
    let bad_len_digests = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![(
            Value::Integer(0u64.into()),
            Value::Bytes(vec![0u8; 64]), // wrong: SHA-256 requires 32 bytes
        )]),
    )]);
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        bad_len_digests,
        "1.0",
        Some(vec![0u8; 16]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("wrong digest length should be rejected");

    // Assert
    assert!(
        matches!(
            err,
            MdocError::InvalidDigestLength {
                expected: 32,
                actual: 64,
                ..
            }
        ),
        "expected InvalidDigestLength {{ expected: 32, actual: 64 }}, got: {err:?}"
    );
}

#[test]
fn rejects_validity_info_valid_from_before_signed() {
    // Arrange: validFrom (1998) is before the hardcoded signed timestamp (1999).
    // ISO 18013-5 §9.1.2.4 requires validFrom >= signed.
    let raw = build_issuer_signed("1998-01-01T00:00:00Z", "9998-01-01T00:00:00Z");

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("validFrom before signed must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidValidityInfo),
        "expected InvalidValidityInfo, got: {err:?}"
    );
}

#[test]
fn rejects_validity_info_valid_until_equal_to_valid_from() {
    // Arrange: validUntil equals validFrom; ISO 18013-5 §9.1.2.4 requires validUntil > validFrom.
    let raw = build_issuer_signed("2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z");

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("validUntil equal to validFrom must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidValidityInfo),
        "expected InvalidValidityInfo, got: {err:?}"
    );
}

#[test]
fn rejects_random_field_too_short() {
    // Arrange: IssuerSignedItem with a 15-byte random; minimum is 16 (ISO 18013-5 §9.1.2.5).
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        Value::Map(vec![(
            Value::Text("org.iso.18013.5.1".into()),
            Value::Map(vec![(
                Value::Integer(0u64.into()),
                Value::Bytes(vec![0u8; 32]),
            )]),
        )]),
        "1.0",
        Some(vec![0u8; 15]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("15-byte random field must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidRandomLength { actual: 15 }),
        "expected InvalidRandomLength {{ actual: 15 }}, got: {err:?}"
    );
}

#[test]
fn rejects_random_field_absent() {
    // Arrange: IssuerSignedItem with no `random` field; ISO 18013-5 §9.1.2.5 requires it.
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        Value::Map(vec![(
            Value::Text("org.iso.18013.5.1".into()),
            Value::Map(vec![(
                Value::Integer(0u64.into()),
                Value::Bytes(vec![0u8; 32]),
            )]),
        )]),
        "1.0",
        None,
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("absent random field must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::MissingField { field: "random" }),
        "expected MissingField {{ field: \"random\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_digest_id_out_of_range() {
    // Arrange: valueDigests map with digestID = 2^31 = 2_147_483_648.
    // ISO 18013-5 §9.1.2.4 requires digestID < 2^31; values at or above must be rejected.
    let out_of_range_digests = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![(
            Value::Integer(2_147_483_648u64.into()),
            Value::Bytes(vec![0u8; 32]),
        )]),
    )]);
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        out_of_range_digests,
        "1.0",
        Some(vec![0u8; 16]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("digestID >= 2^31 must be rejected");

    // Assert
    assert!(
        matches!(
            err,
            MdocError::DigestIdOutOfRange {
                digest_id: 2_147_483_648
            }
        ),
        "expected DigestIdOutOfRange {{ digest_id: 2_147_483_648 }}, got: {err:?}"
    );
}

/// Builds a base64url-encoded `IssuerSigned` with a caller-controlled
/// `nameSpaces` value.
///
/// The MSO (`version`, `digestAlgorithm`, `validityInfo`, `valueDigests`,
/// `deviceKeyInfo`, `docType`) and the `COSE_Sign1` (`issuerAuth`) are
/// constructed with minimal but structurally valid values, so that parsing
/// reaches `parse_name_spaces` before encountering the injected error.
fn build_issuer_signed_with_ns(name_spaces_val: Value) -> String {
    let device_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])), // x
        (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])), // y
    ]);

    let mso = Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text("SHA-256".into()),
        ),
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Map(vec![(
                    Value::Integer(0u64.into()),
                    Value::Bytes(vec![0u8; 32]),
                )]),
            )]),
        ),
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(Value::Text("deviceKey".into()), device_key)]),
        ),
        (
            Value::Text("docType".into()),
            Value::Text("org.iso.18013.5.1.mDL".into()),
        ),
        (
            Value::Text("validityInfo".into()),
            Value::Map(vec![
                (
                    Value::Text("signed".into()),
                    Value::Tag(0, Box::new(Value::Text("1999-01-01T00:00:00Z".into()))),
                ),
                (
                    Value::Text("validFrom".into()),
                    Value::Tag(0, Box::new(Value::Text("2020-01-01T00:00:00Z".into()))),
                ),
                (
                    Value::Text("validUntil".into()),
                    Value::Tag(0, Box::new(Value::Text("9998-01-01T00:00:00Z".into()))),
                ),
            ]),
        ),
    ]);

    let mso_bytes = cbor(&mso);
    // ISO 18013-5 §9.1.2: COSE payload = MobileSecurityObjectBytes = #6.24(bstr)
    let mso_payload = cbor(&Value::Tag(24, Box::new(Value::Bytes(mso_bytes))));
    // {1: -7} = alg: ES256
    let protected_header_bytes = vec![0xa1u8, 0x01, 0x26];
    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_header_bytes),
        Value::Map(vec![]),
        Value::Bytes(mso_payload),
        Value::Bytes(vec![0u8; 64]),
    ]);

    let issuer_signed = Value::Map(vec![
        (Value::Text("nameSpaces".into()), name_spaces_val),
        (
            Value::Text("issuerAuth".into()),
            Value::Tag(18, Box::new(cose_sign1)),
        ),
    ]);

    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

#[test]
fn rejects_untagged_issuer_auth() {
    // Arrange: issuerAuth is a plain CBOR array — not wrapped in CBOR tag 18.
    // RFC 9052 §4.2 and ISO 18013-5 §9.1.2 require issuerAuth = #6.18(COSE_Sign1).
    // The tag check fires before any MSO decoding, so nameSpaces does not need
    // to be structurally valid.
    let issuer_signed = Value::Map(vec![
        (Value::Text("nameSpaces".into()), Value::Map(vec![])),
        // Raw COSE_Sign1 array — intentionally omits the required tag 18 wrapper.
        (Value::Text("issuerAuth".into()), Value::Array(vec![])),
    ]);
    let raw = Base64UrlUnpadded::encode_string(&cbor(&issuer_signed));

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("untagged issuerAuth must be rejected");

    // Assert
    assert!(
        matches!(
            err,
            MdocError::UnexpectedCborType {
                field: "issuerAuth"
            }
        ),
        "expected UnexpectedCborType {{ field: \"issuerAuth\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_empty_value_digests() {
    // Arrange: MSO `valueDigests` is an empty map.
    // ISO 18013-5 CDDL: ValueDigests = { + NameSpace => DigestIDs }
    // The `+` operator requires at least one entry; an empty map is invalid.
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        Value::Map(vec![]), // empty valueDigests
        "1.0",
        Some(vec![0u8; 16]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("empty valueDigests must be rejected");

    // Assert
    assert!(
        matches!(
            err,
            MdocError::UnexpectedCborType {
                field: "valueDigests"
            }
        ),
        "expected UnexpectedCborType {{ field: \"valueDigests\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_empty_digest_ids_per_namespace() {
    // Arrange: `valueDigests` has a namespace entry, but the inner DigestIDs map is empty.
    // ISO 18013-5 CDDL: DigestIDs = { + DigestID => Digest }
    // The `+` operator requires at least one digest per namespace; an empty map is invalid.
    let empty_digest_ids = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![]), // empty DigestIDs for this namespace
    )]);
    let raw = build_issuer_signed_full(
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
        "SHA-256",
        empty_digest_ids,
        "1.0",
        Some(vec![0u8; 16]),
    );

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("empty DigestIDs must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::UnexpectedCborType { field: "DigestIDs" }),
        "expected UnexpectedCborType {{ field: \"DigestIDs\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_empty_name_spaces() {
    // Arrange: `nameSpaces` map has no namespace entries at all.
    // ISO 18013-5 CDDL: IssuerNameSpaces = { + NameSpace => [ + IssuerSignedItemBytes ] }
    // The `+` operator requires at least one namespace.
    let raw = build_issuer_signed_with_ns(Value::Map(vec![]));

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("empty nameSpaces must be rejected");

    // Assert
    assert!(
        matches!(
            err,
            MdocError::UnexpectedCborType {
                field: "nameSpaces"
            }
        ),
        "expected UnexpectedCborType {{ field: \"nameSpaces\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_empty_namespace_item_array() {
    // Arrange: `nameSpaces` has a namespace key but its item array is empty.
    // ISO 18013-5 CDDL: [ + IssuerSignedItemBytes ] — at least one item is required
    // per namespace; an empty array must be rejected to prevent a namespace with no
    // verifiable elements from being silently accepted.
    let empty_ns = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Array(vec![]), // namespace present but no items
    )]);
    let raw = build_issuer_signed_with_ns(empty_ns);

    // Act
    let err = ParsedMdoc::parse(&raw).expect_err("empty namespace item array must be rejected");

    // Assert
    assert!(
        matches!(
            err,
            MdocError::UnexpectedCborType {
                field: "IssuerNameSpaces"
            }
        ),
        "expected UnexpectedCborType {{ field: \"IssuerNameSpaces\" }}, got: {err:?}"
    );
}

#[test]
fn verify_digests_rejects_missing_digest() {
    // Arrange: parse a valid mdoc, then remove the digest entry for the item
    let raw = build_issuer_signed_with_correct_digests();
    let mut mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse");

    // Remove the only entry in the namespace digest map so the lookup fails.
    mdoc.value_digests
        .get_mut("org.iso.18013.5.1")
        .expect("namespace must be present")
        .remove(&0);

    // Act
    let err = verify_digests(&mdoc).expect_err("missing digest must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::MissingDigest { ref namespace, digest_id: 0 } if namespace == "org.iso.18013.5.1"),
        "expected MissingDigest {{ namespace: org.iso.18013.5.1, digest_id: 0 }}, got: {err:?}"
    );
}
