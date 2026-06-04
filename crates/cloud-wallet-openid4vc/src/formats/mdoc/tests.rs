use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::Value;
use cloud_wallet_crypto::digest::HashAlg;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::DigestAlgorithm;
use super::error::MdocError;
use super::parser::ParsedMdoc;
use super::verifier::{StaticTrustStore, verify_digests, verify_issuer_signature};

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
        (
            Value::Text("issuerAuth".into()),
            Value::Tag(18, Box::new(cose_sign1)),
        ),
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

/// Builds an `IssuerSigned` with two items in one namespace, both with correct SHA-256
/// digests.
///
/// Items: `digestID = 0` → `family_name = "Doe"`, `digestID = 1` → `given_name = "John"`.
/// Both `raw_tag24_bytes` and `valueDigests` entries are consistent so that
/// `verify_digests` passes without tampering.
fn build_two_item_mdoc() -> String {
    let alg = HashAlg::Sha256;
    let (bytes0, digest0) = item_tag24_and_digest(0, "family_name", "Doe", alg);
    let (bytes1, digest1) = item_tag24_and_digest(1, "given_name", "John", alg);

    let val0: Value =
        ciborium::de::from_reader(bytes0.as_slice()).expect("round-trip must succeed");
    let val1: Value =
        ciborium::de::from_reader(bytes1.as_slice()).expect("round-trip must succeed");

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
            Value::Text("SHA-256".into()),
        ),
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Map(vec![
                    (Value::Integer(0u64.into()), Value::Bytes(digest0)),
                    (Value::Integer(1u64.into()), Value::Bytes(digest1)),
                ]),
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
    let mso_payload = cbor(&Value::Tag(24, Box::new(Value::Bytes(mso_bytes))));
    let protected_header_bytes = vec![0xa1u8, 0x01, 0x26];
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
                Value::Array(vec![val0, val1]),
            )]),
        ),
        (
            Value::Text("issuerAuth".into()),
            Value::Tag(18, Box::new(cose_sign1)),
        ),
    ]);
    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

/// Builds an `IssuerSigned` with one item in each of two namespaces, both with correct
/// SHA-256 digests.
///
/// Namespaces:
/// - `"org.iso.18013.5.1"` → `digestID = 0`, `family_name = "Doe"`
/// - `"org.iso.18013.5.1.US"` → `digestID = 0`, `domestic_driving_privileges = "A"`
fn build_two_namespace_mdoc() -> String {
    let alg = HashAlg::Sha256;
    let (bytes_ns1, digest_ns1) = item_tag24_and_digest(0, "family_name", "Doe", alg);
    let (bytes_ns2, digest_ns2) = item_tag24_and_digest(0, "domestic_driving_privileges", "A", alg);

    let val_ns1: Value =
        ciborium::de::from_reader(bytes_ns1.as_slice()).expect("round-trip must succeed");
    let val_ns2: Value =
        ciborium::de::from_reader(bytes_ns2.as_slice()).expect("round-trip must succeed");

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
            Value::Text("SHA-256".into()),
        ),
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![
                (
                    Value::Text("org.iso.18013.5.1".into()),
                    Value::Map(vec![(
                        Value::Integer(0u64.into()),
                        Value::Bytes(digest_ns1),
                    )]),
                ),
                (
                    Value::Text("org.iso.18013.5.1.US".into()),
                    Value::Map(vec![(
                        Value::Integer(0u64.into()),
                        Value::Bytes(digest_ns2),
                    )]),
                ),
            ]),
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
    let mso_payload = cbor(&Value::Tag(24, Box::new(Value::Bytes(mso_bytes))));
    let protected_header_bytes = vec![0xa1u8, 0x01, 0x26];
    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_header_bytes),
        Value::Map(vec![]),
        Value::Bytes(mso_payload),
        Value::Bytes(vec![0u8; 64]),
    ]);
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![
                (
                    Value::Text("org.iso.18013.5.1".into()),
                    Value::Array(vec![val_ns1]),
                ),
                (
                    Value::Text("org.iso.18013.5.1.US".into()),
                    Value::Array(vec![val_ns2]),
                ),
            ]),
        ),
        (
            Value::Text("issuerAuth".into()),
            Value::Tag(18, Box::new(cose_sign1)),
        ),
    ]);
    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
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

#[test]
fn verify_digests_rejects_second_of_two_items_in_same_namespace() {
    // Arrange: mdoc with two items in one namespace; confirm it passes clean first.
    let raw = build_two_item_mdoc();
    let mut mdoc = ParsedMdoc::parse(&raw).expect("two-item mdoc should parse");
    assert!(
        verify_digests(&mdoc).is_ok(),
        "all digests should pass before tampering"
    );

    // Corrupt the second item (digestID 1) — exercises the inner item loop.
    let items = mdoc
        .name_spaces
        .get_mut("org.iso.18013.5.1")
        .expect("namespace must be present");
    let item1 = items
        .iter_mut()
        .find(|i| i.digest_id == 1)
        .expect("digestID 1 must be present");
    *item1.raw_tag24_bytes.last_mut().expect("bytes non-empty") ^= 0xFF;

    // Act
    let err = verify_digests(&mdoc).expect_err("tampered second item must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::DigestMismatch { ref namespace, digest_id: 1 }
            if namespace == "org.iso.18013.5.1"),
        "expected DigestMismatch {{ namespace: org.iso.18013.5.1, digest_id: 1 }}, got: {err:?}"
    );
}

#[test]
fn verify_digests_rejects_item_in_second_namespace() {
    // Arrange: mdoc with items across two namespaces; confirm it passes clean first.
    let raw = build_two_namespace_mdoc();
    let mut mdoc = ParsedMdoc::parse(&raw).expect("two-namespace mdoc should parse");
    assert!(
        verify_digests(&mdoc).is_ok(),
        "all digests should pass before tampering"
    );

    // Corrupt the item in the second namespace — confirms both namespaces are checked.
    let items = mdoc
        .name_spaces
        .get_mut("org.iso.18013.5.1.US")
        .expect("second namespace must be present");
    *items[0]
        .raw_tag24_bytes
        .last_mut()
        .expect("bytes non-empty") ^= 0xFF;

    // Act
    let err =
        verify_digests(&mdoc).expect_err("tampered item in second namespace must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::DigestMismatch { ref namespace, digest_id: 0 }
            if namespace == "org.iso.18013.5.1.US"),
        "expected DigestMismatch {{ namespace: org.iso.18013.5.1.US, digest_id: 0 }}, got: {err:?}"
    );
}

#[test]
fn verify_digests_rejects_namespace_absent_from_value_digests() {
    // Arrange: valid mdoc; remove the entire namespace key from value_digests.
    // This covers the `value_digests.get(namespace) → None` branch in verify_digests,
    // which is distinct from removing only the digestID entry (covered by
    // `verify_digests_rejects_missing_digest`).
    let raw = build_issuer_signed_with_correct_digests();
    let mut mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse");
    mdoc.value_digests.remove("org.iso.18013.5.1");

    // Act
    let err =
        verify_digests(&mdoc).expect_err("namespace absent from value_digests must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::MissingDigest { ref namespace, digest_id: 0 }
            if namespace == "org.iso.18013.5.1"),
        "expected MissingDigest {{ namespace: org.iso.18013.5.1, digest_id: 0 }}, got: {err:?}"
    );
}

/// ISO 18013-5 Document Signer Certificate EKU OID (arc 1.0.18013.5.1.2).
/// Encoded as relative OID component integers for rcgen `ExtendedKeyUsagePurpose::Other`.
const DSC_EKU_OID: &[u64] = &[1, 0, 18013, 5, 1, 2];

/// Builds an IACA root CA cert and a DSC cert signed by that IACA, returning
/// `(iaca_der, dsc_der, dsc_signing_key)` where `dsc_signing_key` is backed by
/// `aws-lc-rs` so that signatures produced by it can be verified by
/// `cloud_wallet_crypto::ecdsa::VerifyingKey`.
///
/// The `include_dsc_eku` flag controls whether the DSC carries the mandatory
/// ISO 18013-5 EKU OID; set it to `false` to exercise the missing-EKU path.
fn build_chain(include_dsc_eku: bool) -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    build_chain_params(include_dsc_eku, None, None, None, None, None)
}

/// Parameterised version of [`build_chain`] for tests that need specific DSC validity
/// dates, per-country-code attributes, or stateOrProvinceName attributes.
///
/// - `dsc_validity`: `(not_before, not_after)` for the DSC; defaults to a 396-day window
///   (`2023-12-01` to `2024-12-31`) that covers the `minimal_mso_cbor()` `signed` timestamp.
/// - `iaca_country`: `CountryName` for the IACA subject DN (e.g. `"DE"`).
/// - `dsc_country`: `CountryName` for the DSC subject DN (e.g. `"FR"`).
/// - `iaca_state`: `stateOrProvinceName` for the IACA subject DN (e.g. `"California"`).
/// - `dsc_state`: `stateOrProvinceName` for the DSC subject DN (e.g. `"NewYork"`).
fn build_chain_params(
    include_dsc_eku: bool,
    dsc_validity: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
    iaca_country: Option<&str>,
    dsc_country: Option<&str>,
    iaca_state: Option<&str>,
    dsc_state: Option<&str>,
) -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyUsagePurpose,
    };
    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    if let Some(c) = iaca_country {
        iaca_params.distinguished_name.push(DnType::CountryName, c);
    }
    if let Some(s) = iaca_state {
        iaca_params
            .distinguished_name
            .push(DnType::StateOrProvinceName, s);
    }
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
            .expect("aws-lc-rs DSC key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading aws-lc-rs key into rcgen must succeed");

    // Default DSC validity: 396-day window that covers the minimal_mso_cbor() signed date.
    let (not_before, not_after) = dsc_validity.unwrap_or_else(|| {
        (
            OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse"),
            OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse"),
        )
    });

    let mut dsc_params = CertificateParams::new(vec!["DSC".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    if include_dsc_eku {
        dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    }
    if let Some(c) = dsc_country {
        dsc_params.distinguished_name.push(DnType::CountryName, c);
    }
    if let Some(s) = dsc_state {
        dsc_params
            .distinguished_name
            .push(DnType::StateOrProvinceName, s);
    }
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC signing by IACA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

/// Constructs the COSE Sig_Structure (RFC 9052 §4.4) and signs it with
/// `signing_key`, then assembles a raw `IssuerSigned` CBOR payload suitable
/// for `ParsedMdoc::parse`.
///
/// The unprotected header carries `x5chain` (label 33) as an array of two
/// DER-encoded certs: `[dsc_der, iaca_der]`.
///
/// If `tamper` is `true` the COSE signature bytes are altered after signing so
/// that signature verification fails while the payload structure remains valid.
fn build_issuer_signed_with_issuer_auth(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
    tamper: bool,
) -> String {
    // {1: -7} (ES256), CBOR-encoded: a1 01 26
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];

    // RFC 9052 §4.4 Sig_Structure: ["Signature1", protected_bstr, external_aad, payload]
    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]), // external AAD = b""
        Value::Bytes(mso_bytes.clone()),
    ]));

    let sig_bytes = signing_key
        .sign_sha256(&tbs)
        .expect("COSE signing must succeed");

    // Flip one byte so signature verification fails while CBOR structure stays intact.
    let final_sig: Vec<u8> = if tamper {
        let mut corrupted = sig_bytes.to_vec();
        corrupted[0] ^= 0xff;
        corrupted
    } else {
        sig_bytes.to_vec()
    };

    // Label 33 must be an integer key so coset parses it as Label::Int(33).
    let unprotected_map = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(final_sig),
        ])),
    );

    // Parser requires at least one namespace entry.
    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);

    let raw = cbor(&issuer_signed);
    Base64UrlUnpadded::encode_string(&raw)
}

/// Returns the MSO payload bytes as they appear inside the COSE_Sign1 `payload` field:
/// `Tag(24, bstr(mso_cbor))` per ISO 18013-5 §9.1.2 MobileSecurityObjectBytes.
fn minimal_mso_cbor() -> Vec<u8> {
    let validity_info = Value::Map(vec![
        (
            Value::Text("signed".into()),
            Value::Tag(0, Box::new(Value::Text("2024-01-01T00:00:00Z".into()))),
        ),
        (
            Value::Text("validFrom".into()),
            Value::Tag(0, Box::new(Value::Text("2024-01-01T00:00:00Z".into()))),
        ),
        (
            Value::Text("validUntil".into()),
            Value::Tag(0, Box::new(Value::Text("9998-01-01T00:00:00Z".into()))),
        ),
    ]);

    let mso = Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text("SHA-256".into()),
        ),
        // valueDigests must have at least one namespace with at least one digest (32 bytes for SHA-256).
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Map(vec![(
                    Value::Integer(0.into()),
                    Value::Bytes(vec![0u8; 32]),
                )]),
            )]),
        ),
        // deviceKeyInfo must contain a deviceKey entry.
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(
                Value::Text("deviceKey".into()),
                // Minimal COSE_Key: {1: 2, -1: 1} (kty=EC2, crv=P-256)
                Value::Map(vec![
                    (Value::Integer(1.into()), Value::Integer(2.into())),
                    (
                        Value::Integer(ciborium::value::Integer::from(-1i64)),
                        Value::Integer(1.into()),
                    ),
                ]),
            )]),
        ),
        (
            Value::Text("docType".into()),
            Value::Text("org.iso.18013.5.1.mDL".into()),
        ),
        (Value::Text("validityInfo".into()), validity_info),
    ]);

    cbor(&Value::Tag(24, Box::new(Value::Bytes(cbor(&mso)))))
}

#[test]
fn verify_issuer_signature_accepts_valid_chain() {
    // Arrange
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der.clone(), &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let result = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store);

    // Assert
    assert!(
        result.is_ok(),
        "valid COSE_Sign1 with trusted chain must be accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

#[test]
fn verify_issuer_signature_rejects_tampered_payload() {
    // Arrange: sign normally, then corrupt the payload bytes so the signature
    // covers different content than what the verifier sees.
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(
        mso_bytes,
        dsc_der,
        &signing_key,
        true, // tamper = true
    );
    let mdoc =
        ParsedMdoc::parse(&raw).expect("tampered mdoc must still parse (parser is not a verifier)");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("tampered payload must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidIssuerSignature),
        "expected InvalidIssuerSignature, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_untrusted_root() {
    // Arrange: produce a valid chain but supply a *different* CA as trust anchor.
    let (_, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");

    let (unrelated_iaca_der, _, _) = build_chain(true);
    let trust_store = StaticTrustStore::new(vec![unrelated_iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("chain not anchored to trusted root must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_missing_eku() {
    // Arrange: DSC is validly signed by IACA but lacks the ISO 18013-5 EKU OID.
    let (iaca_der, dsc_der, signing_key) = build_chain(false); // no EKU
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("DSC without ISO 18013-5 EKU must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::MissingDocSignerEku),
        "expected MissingDocSignerEku, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_missing_x5chain() {
    // Arrange: build an IssuerSigned where the unprotected header has NO x5chain entry.
    let (iaca_der, _dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();

    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(mso_bytes.clone()),
    ]));
    let sig_bytes = signing_key.sign_sha256(&tbs).expect("signing must succeed");

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            Value::Map(vec![]), // empty unprotected header
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );
    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);
    let raw = Base64UrlUnpadded::encode_string(&cbor(&issuer_signed));
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc without x5chain must still parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("missing x5chain must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::MissingX5Chain),
        "expected MissingX5Chain, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_doctype_mismatch() {
    // Arrange: MSO has docType "org.iso.18013.5.1.mDL" but outer_doc_type differs.
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act: pass a different outer_doc_type.
    let err = verify_issuer_signature(&mdoc, "com.example.other.doctype", &trust_store)
        .expect_err("docType mismatch must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::DocTypeMismatch { .. }),
        "expected DocTypeMismatch, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_signed_outside_dsc_validity() {
    // Arrange: DSC valid 2025-01-01..2025-12-31 (365 days < 457-day max), but the MSO
    // signed timestamp is "2024-01-01T00:00:00Z" — before the DSC notBefore.
    let (iaca_der, dsc_der, signing_key) = build_chain_params(
        true,
        Some((
            OffsetDateTime::parse("2025-01-01T00:00:00Z", &Rfc3339).expect("date must parse"),
            OffsetDateTime::parse("2025-12-31T23:59:59Z", &Rfc3339).expect("date must parse"),
        )),
        None,
        None,
        None,
        None,
    );
    let mso_bytes = minimal_mso_cbor(); // signed = "2024-01-01T00:00:00Z"
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("MSO signed before DSC notBefore must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::SignedOutsideDscValidity { .. }),
        "expected SignedOutsideDscValidity, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_country_mismatch() {
    // Arrange: IACA subject C=DE, DSC subject C=FR — country mismatch (ISO 18013-5 §9.3.3).
    let (iaca_der, dsc_der, signing_key) =
        build_chain_params(true, None, Some("DE"), Some("FR"), None, None);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("DSC/IACA country mismatch must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::CountryMismatch { .. }),
        "expected CountryMismatch, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_dsc_validity_too_long() {
    // Arrange: DSC notBefore=2024-01-01, notAfter=2025-04-04 → 459 days > 457-day maximum.
    // MSO signed="2024-01-01T00:00:00Z" = DSC notBefore (would be within-window if allowed).
    let (iaca_der, dsc_der, signing_key) = build_chain_params(
        true,
        Some((
            OffsetDateTime::parse("2024-01-01T00:00:00Z", &Rfc3339).expect("date must parse"),
            OffsetDateTime::parse("2025-04-04T00:00:00Z", &Rfc3339).expect("date must parse"),
        )),
        None,
        None,
        None,
        None,
    );
    let mso_bytes = minimal_mso_cbor(); // signed = "2024-01-01T00:00:00Z"
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("DSC with 459-day validity must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain (457-day limit exceeded), got: {err:?}"
    );
}

/// Builds an IACA root and DSC cert chain backed by P-521 keys (ES512 / -36).
///
/// Returns `(iaca_der, dsc_der, dsc_signing_key)` where the signing key uses
/// `cloud_wallet_crypto::ecdsa::Curve::P521`.
fn build_chain_p521() -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyUsagePurpose,
    };

    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root P521".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P521)
            .expect("aws-lc-rs P-521 key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P521_SHA512,
    )
    .expect("loading P-521 key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params = CertificateParams::new(vec!["DSC P521".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    dsc_params
        .distinguished_name
        .push(DnType::CommonName, "DSC P521");
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC P-521 signing by IACA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

/// Like [`build_issuer_signed_with_issuer_auth`] but uses the ES512 algorithm (-36).
///
/// Protected header encodes `{1: -36}` and the payload is signed with SHA-512.
fn build_issuer_signed_with_issuer_auth_es512(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    // {1: -36} (ES512), CBOR-encoded: a1 01 38 23
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x38, 0x23];

    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(mso_bytes.clone()),
    ]));

    let sig_bytes = signing_key
        .sign_sha512(&tbs)
        .expect("ES512 COSE signing must succeed");

    let unprotected_map = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );

    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);

    let raw = cbor(&issuer_signed);
    Base64UrlUnpadded::encode_string(&raw)
}

#[test]
fn verify_issuer_signature_accepts_valid_es512() {
    // Arrange: P-521 key pair, real ES512 signature, proper chain and EKU.
    let (iaca_der, dsc_der, signing_key) = build_chain_p521();
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth_es512(mso_bytes, dsc_der.clone(), &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid ES512 issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let result = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store);

    // Assert
    assert!(
        result.is_ok(),
        "valid ES512 COSE_Sign1 with trusted chain must be accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

#[test]
fn verify_issuer_signature_rejects_state_mismatch() {
    // Arrange: IACA subject ST=California, DSC subject ST=NewYork — state mismatch (ISO 18013-5 §9.3.3).
    let (iaca_der, dsc_der, signing_key) =
        build_chain_params(true, None, None, None, Some("California"), Some("NewYork"));
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("DSC/IACA state mismatch must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::StateMismatch { .. }),
        "expected StateMismatch, got: {err:?}"
    );
}

/// Builds a chain where the DSC has a Key Usage extension but the `digitalSignature`
/// bit is NOT set (only `ContentCommitment`), exercising the key-usage rejection path.
fn build_chain_dsc_wrong_key_usage() -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyUsagePurpose,
    };

    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
            .expect("aws-lc-rs DSC key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params =
        CertificateParams::new(vec!["DSC Wrong KU".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    // Key Usage extension IS present, but digitalSignature bit is NOT set.
    dsc_params.key_usages = vec![KeyUsagePurpose::ContentCommitment];
    dsc_params
        .distinguished_name
        .push(DnType::CommonName, "DSC Wrong KU");
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC signing must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

#[test]
fn verify_issuer_signature_rejects_missing_key_usage() {
    // Arrange: DSC carries a Key Usage extension but only ContentCommitment is set —
    // the digitalSignature bit required by ISO 18013-5 Annex B Table B.3 is absent.
    let (iaca_der, dsc_der, signing_key) = build_chain_dsc_wrong_key_usage();
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("DSC without digitalSignature key usage must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::MissingDigitalSignatureKeyUsage),
        "expected MissingDigitalSignatureKeyUsage, got: {err:?}"
    );
}

// ── New helpers and tests added to improve coverage ─────────────────────────

/// Builds an `IssuerSigned` where the x5chain unprotected header value is a
/// single `bstr` rather than `[bstr]`.  Per RFC 9360 §2 both forms are valid.
fn build_issuer_signed_single_bstr_x5chain(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    // {1: -7} (ES256)
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];

    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(mso_bytes.clone()),
    ]));
    let sig_bytes = signing_key
        .sign_sha256(&tbs)
        .expect("COSE signing must succeed");

    // Single bstr — no wrapping array.
    let unprotected_map = Value::Map(vec![(Value::Integer(33.into()), Value::Bytes(dsc_der))]);

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );

    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);
    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

/// Builds an `IssuerSigned` with a multi-cert x5chain `[dsc, …]` (leaf-first).
///
/// The protected header is fixed to ES256; the signature covers `mso_bytes`
/// using `signing_key`.
fn build_issuer_signed_with_chain_x5chain(
    mso_bytes: Vec<u8>,
    cert_chain: Vec<Vec<u8>>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];

    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(mso_bytes.clone()),
    ]));
    let sig_bytes = signing_key
        .sign_sha256(&tbs)
        .expect("COSE signing must succeed");

    let chain_vals: Vec<Value> = cert_chain.into_iter().map(Value::Bytes).collect();
    let unprotected_map = Value::Map(vec![(Value::Integer(33.into()), Value::Array(chain_vals))]);

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );

    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);
    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

/// Builds an `IssuerSigned` with an arbitrary raw protected-header CBOR blob and
/// a dummy (zero-filled) COSE signature.  Intended for tests that verify errors
/// that fire before signature verification (e.g. unsupported algorithm).
fn build_issuer_signed_with_custom_alg(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    protected_header_bytes: Vec<u8>,
) -> String {
    // Dummy 64-byte signature — error fires in dispatch_verify before verification.
    let dummy_sig = vec![0u8; 64];

    let unprotected_map = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(dummy_sig),
        ])),
    );

    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);
    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

/// Builds a three-tier certificate chain: IACA root → Intermediate CA → DSC.
///
/// Returns `(iaca_der, intermediate_der, dsc_der, dsc_signing_key)`.
fn build_three_cert_chain() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    cloud_wallet_crypto::ecdsa::KeyPair,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
    };

    // IACA root (self-signed CA)
    let iaca_key = rcgen::KeyPair::generate().expect("IACA key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["Three-tier IACA Root".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("IACA self-sign must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    // Intermediate CA (signed by IACA root)
    let int_key = rcgen::KeyPair::generate().expect("Intermediate CA key generation must succeed");
    let mut int_params =
        CertificateParams::new(vec!["Three-tier Intermediate CA".to_string()]).expect("int params");
    int_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let int_cert = int_params
        .signed_by(&int_key, &iaca_issuer)
        .expect("Intermediate CA signing must succeed");
    let int_der: Vec<u8> = int_cert.der().to_vec();
    let int_issuer = Issuer::new(int_params, int_key);

    // DSC (signed by Intermediate CA)
    let dsc_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
            .expect("aws-lc-rs DSC key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading aws-lc-rs key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params =
        CertificateParams::new(vec!["Three-tier DSC".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &int_issuer)
        .expect("DSC signing by Intermediate CA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, int_der, dsc_der, dsc_aws_key)
}

// ── BLOCKING-2: signed timestamp after DSC notAfter ──────────────────────────

#[test]
fn verify_issuer_signature_rejects_signed_after_dsc_expiry() {
    // Arrange: DSC validity window 2023-01-01..2023-06-30 (170 days, well under the
    // 457-day limit).  The minimal_mso_cbor() fixture has signed = "2024-01-01",
    // which is after notAfter (2023-06-30), so check_signed_within_dsc_validity
    // must reject the credential.
    let (iaca_der, dsc_der, signing_key) = build_chain_params(
        true,
        Some((
            OffsetDateTime::parse("2023-01-01T00:00:00Z", &Rfc3339).expect("fixed date must parse"),
            OffsetDateTime::parse("2023-06-30T23:59:59Z", &Rfc3339).expect("fixed date must parse"),
        )),
        None,
        None,
        None,
        None,
    );
    let mso_bytes = minimal_mso_cbor(); // signed = "2024-01-01" — after notAfter
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("MSO signed after DSC notAfter must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::SignedOutsideDscValidity { .. }),
        "expected SignedOutsideDscValidity, got: {err:?}"
    );
}

// ── NB-10: single-bstr x5chain ───────────────────────────────────────────────

#[test]
fn verify_issuer_signature_accepts_single_bstr_x5chain() {
    // RFC 9360 §2 permits x5chain to be either a single bstr or an array of
    // bstr.  Both forms must be accepted.
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_single_bstr_x5chain(mso_bytes, dsc_der, &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let result = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store);

    // Assert
    assert!(
        result.is_ok(),
        "credential with single-bstr x5chain must be accepted: {result:?}"
    );
}

// ── NB-11: multi-cert chain (IACA → IntCA → DSC) ─────────────────────────────

#[test]
fn verify_issuer_signature_accepts_intermediate_ca_chain() {
    // x5chain = [dsc_der, int_der] (leaf first; IACA root not included per
    // ISO 18013-5 Annex B §B.1).  validate_cert_chain must walk the full path.
    let (iaca_der, int_der, dsc_der, signing_key) = build_three_cert_chain();
    let mso_bytes = minimal_mso_cbor();
    let raw =
        build_issuer_signed_with_chain_x5chain(mso_bytes, vec![dsc_der, int_der], &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let result = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store);

    // Assert
    assert!(
        result.is_ok(),
        "three-cert chain with valid intermediate must be accepted: {result:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_tampered_intermediate() {
    // Replace the real intermediate with a fresh IACA root (different key).
    // chain[0].verify_signature(chain[1].public_key()) will fail because the
    // DSC was signed by the real intermediate, not by the replacement.
    let (iaca_der, _int_der, dsc_der, signing_key) = build_three_cert_chain();

    // A fresh IACA cert has a different key — use it as the "wrong intermediate".
    let (wrong_cert_der, _, _) = build_chain(true);

    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_chain_x5chain(
        mso_bytes,
        vec![dsc_der, wrong_cert_der],
        &signing_key,
    );
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc must still parse structurally");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("chain with wrong intermediate must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain, got: {err:?}"
    );
}

// ── NB-12: empty trust store ──────────────────────────────────────────────────

#[test]
fn verify_issuer_signature_rejects_empty_trust_store() {
    // An empty trust store cannot anchor any chain.
    let (_iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_with_issuer_auth(mso_bytes, dsc_der, &signing_key, false);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![]); // empty

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("empty trust store must reject all chains");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain, got: {err:?}"
    );
}

// ── NB-13: Brainpool P-256/P-384/P-512 algorithm identifiers ─────────────────
//
// Algorithm IDs -38, -47, -48 (Brainpool) must be recognised by read_cose_alg
// and reach dispatch_verify, which returns UnsupportedAlgorithm immediately.
// The credential structure must otherwise be valid (chain, EKU, etc.) so the
// error comes from dispatch_verify, not from an earlier check.
//
// CBOR protected header encoding:
//   {1: -38} = a1 01 38 25   (Brainpool P-256r1)
//   {1: -47} = a1 01 38 2e   (Brainpool P-384r1)
//   {1: -48} = a1 01 38 2f   (Brainpool P-512r1)

#[test]
fn verify_issuer_signature_rejects_brainpool_p256_algorithm() {
    let (iaca_der, dsc_der, _) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    // {1: -38} CBOR = a1 01 38 25
    let raw = build_issuer_signed_with_custom_alg(mso_bytes, dsc_der, vec![0xa1, 0x01, 0x38, 0x25]);
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc with Brainpool P-256 alg must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("Brainpool P-256 must be rejected as unsupported");

    // Assert
    assert!(
        matches!(err, MdocError::UnsupportedAlgorithm { alg: -38 }),
        "expected UnsupportedAlgorithm {{ alg: -38 }}, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_brainpool_p384_algorithm() {
    let (iaca_der, dsc_der, _) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    // {1: -47} CBOR = a1 01 38 2e
    let raw = build_issuer_signed_with_custom_alg(mso_bytes, dsc_der, vec![0xa1, 0x01, 0x38, 0x2e]);
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc with Brainpool P-384 alg must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("Brainpool P-384 must be rejected as unsupported");

    // Assert
    assert!(
        matches!(err, MdocError::UnsupportedAlgorithm { alg: -47 }),
        "expected UnsupportedAlgorithm {{ alg: -47 }}, got: {err:?}"
    );
}

#[test]
fn verify_issuer_signature_rejects_brainpool_p512_algorithm() {
    let (iaca_der, dsc_der, _) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    // {1: -48} CBOR = a1 01 38 2f
    let raw = build_issuer_signed_with_custom_alg(mso_bytes, dsc_der, vec![0xa1, 0x01, 0x38, 0x2f]);
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc with Brainpool P-512 alg must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("Brainpool P-512 must be rejected as unsupported");

    // Assert
    assert!(
        matches!(err, MdocError::UnsupportedAlgorithm { alg: -48 }),
        "expected UnsupportedAlgorithm {{ alg: -48 }}, got: {err:?}"
    );
}

// ── NB-4: IACA root present in x5chain ────────────────────────────────────────

#[test]
fn verify_issuer_signature_rejects_iaca_root_in_x5chain() {
    // ISO 18013-5 Annex B §B.1: the IACA root must NOT appear in x5chain.
    // Placing it as the second entry causes validate_cert_chain to find the
    // trusted root inside the chain and reject the credential.
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();
    // chain = [dsc_der, iaca_der] — IACA root is present as the second entry.
    let raw = build_issuer_signed_with_chain_x5chain(
        mso_bytes,
        vec![dsc_der, iaca_der.clone()],
        &signing_key,
    );
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc with IACA root in chain must still parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("IACA root present in x5chain must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::InvalidCertificateChain { .. }),
        "expected InvalidCertificateChain, got: {err:?}"
    );
}

// ── NB-5: Ed448 public key rejected ──────────────────────────────────────────

/// Constructs a minimal X.509 certificate with an Ed448 public key (OID `1.3.101.113`)
/// in the SubjectPublicKeyInfo, signed by the provided P-256 IACA key.
///
/// `rcgen 0.13` does not support Ed448 key generation, so the certificate is built from
/// raw DER.  The public key payload is all-zeros (57 bytes) — sufficient for the Ed448
/// OID check in `verify_issuer_signature`, which fires before any key-payload check.
fn build_ed448_dsc_manual(
    iaca_cert_der: &[u8],
    iaca_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> Vec<u8> {
    use x509_parser::prelude::{FromDer as _, X509Certificate};

    // Extract the IACA subject DER bytes — these become the DSC issuer field.
    let (_, iaca_x509) =
        X509Certificate::from_der(iaca_cert_der).expect("IACA cert must be parseable");
    let issuer_raw = iaca_x509.tbs_certificate.subject.as_raw().to_vec();

    // ── Minimal DER helpers ──────────────────────────────────────────────────
    fn len_bytes(n: usize) -> Vec<u8> {
        if n < 128 {
            vec![n as u8]
        } else if n < 256 {
            vec![0x81, n as u8]
        } else {
            vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
        }
    }
    fn tlv(tag: u8, body: Vec<u8>) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(len_bytes(body.len()));
        v.extend(body);
        v
    }
    fn seq(body: Vec<u8>) -> Vec<u8> {
        tlv(0x30, body)
    }
    fn set(body: Vec<u8>) -> Vec<u8> {
        tlv(0x31, body)
    }
    fn ctx_explicit(n: u8, body: Vec<u8>) -> Vec<u8> {
        tlv(0xa0 | n, body)
    }
    fn oid(components: &[u64]) -> Vec<u8> {
        fn base128(mut n: u64) -> Vec<u8> {
            if n == 0 {
                return vec![0];
            }
            let mut b = Vec::new();
            while n > 0 {
                b.push((n & 0x7f) as u8);
                n >>= 7;
            }
            b.reverse();
            for i in 0..b.len() - 1 {
                b[i] |= 0x80;
            }
            b
        }
        let mut bytes = base128(components[0] * 40 + components[1]);
        for &c in &components[2..] {
            bytes.extend(base128(c));
        }
        tlv(0x06, bytes)
    }
    fn integer_pos(b: Vec<u8>) -> Vec<u8> {
        let mut content = b;
        if content.first().is_some_and(|&x| x & 0x80 != 0) {
            content.insert(0, 0);
        }
        tlv(0x02, content)
    }
    fn bit_str(data: Vec<u8>) -> Vec<u8> {
        let mut c = vec![0x00]; // 0 unused bits
        c.extend(data);
        tlv(0x03, c)
    }
    fn octet_str(b: Vec<u8>) -> Vec<u8> {
        tlv(0x04, b)
    }
    fn bool_true() -> Vec<u8> {
        vec![0x01, 0x01, 0xff]
    }
    fn utc_time(s: &'static str) -> Vec<u8> {
        tlv(0x17, s.as_bytes().to_vec())
    }

    // ── Build TBSCertificate ─────────────────────────────────────────────────
    let version = ctx_explicit(0, integer_pos(vec![0x02])); // [0] INTEGER 2 → v3
    let serial = integer_pos(vec![0x01]); // serialNumber = 1
    let sig_alg_id = seq(oid(&[1, 2, 840, 10045, 4, 3, 2])); // ecdsa-with-SHA256
    let validity = seq({
        let mut b = utc_time("231201000000Z");
        b.extend(utc_time("241231235959Z"));
        b
    });
    let subject = seq(set(seq({
        let mut b = oid(&[2, 5, 4, 3]); // id-at-commonName
        b.extend(tlv(0x0c, b"Ed448DSC".to_vec())); // UTF8String
        b
    })));
    let spki = seq({
        let mut b = seq(oid(&[1, 3, 101, 113])); // id-Ed448, no params
        b.extend(bit_str(vec![0u8; 57])); // fake 57-byte public key
        b
    });
    // extendedKeyUsage (2.5.29.37), critical — ISO 18013-5 EKU
    let eku_ext = seq({
        let mut b = oid(&[2, 5, 29, 37]);
        b.extend(bool_true());
        // ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
        b.extend(octet_str(seq(oid(&[1, 0, 18013, 5, 1, 2]))));
        b
    });
    // keyUsage (2.5.29.15), critical, digitalSignature bit set
    let ku_ext = seq({
        let mut b = oid(&[2, 5, 29, 15]);
        b.extend(bool_true());
        b.extend(octet_str(tlv(0x03, vec![0x07, 0x80]))); // BIT STRING: 7 unused, bit 0
        b
    });
    let extensions = ctx_explicit(
        3,
        seq({
            let mut b = eku_ext;
            b.extend(ku_ext);
            b
        }),
    );
    let tbs = seq({
        let mut b = version;
        b.extend(serial);
        b.extend(sig_alg_id.clone());
        b.extend(issuer_raw);
        b.extend(validity);
        b.extend(subject);
        b.extend(spki);
        b.extend(extensions);
        b
    });

    // Sign TBSCertificate with the IACA's P-256 key (ASN.1 DER encoding for X.509).
    let mut sig_buf = [0u8; 80]; // P-256 ASN.1 ECDSA signature is at most ~72 bytes
    let sig = iaca_key
        .sign_sha256_asn1(&tbs, &mut sig_buf)
        .expect("ECDSA-P256 signing of TBSCertificate must succeed");

    // Assemble full Certificate = SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING }
    seq({
        let mut b = tbs;
        b.extend(sig_alg_id);
        b.extend(bit_str(sig.to_vec()));
        b
    })
}

/// Builds a P-256 IACA root and a minimal Ed448 DSC signed by that root.
///
/// `rcgen 0.13` does not support Ed448 key generation; the DSC is assembled from raw
/// DER via [`build_ed448_dsc_manual`].  The DSC's SPKI holds OID `1.3.101.113`
/// (id-Ed448) with a fake public key — sufficient to exercise the OID rejection check.
fn build_ed448_dsc_chain() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa};

    // Use cloud_wallet_crypto key so we can sign the TBSCertificate for the DSC.
    let iaca_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
            .expect("P-256 IACA key generation must succeed");

    let iaca_pkcs8 = iaca_aws_key.to_pkcs8_der();
    let iaca_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            iaca_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .expect("loading P-256 key into rcgen must succeed");

    let mut iaca_params =
        CertificateParams::new(vec!["Ed448 Test IACA".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_rcgen_key)
        .expect("IACA self-sign must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();

    let dsc_der = build_ed448_dsc_manual(&iaca_der, &iaca_aws_key);

    (iaca_der, dsc_der)
}

#[test]
fn verify_issuer_signature_rejects_ed448_algorithm() {
    // Ed448 (OID 1.3.101.113) is not supported even when the COSE alg field is
    // EdDSA (-8). The check fires after chain validation but before the crypto
    // backend, so a dummy signature is sufficient to reach the rejection.
    let (iaca_der, dsc_der) = build_ed448_dsc_chain();
    let mso_bytes = minimal_mso_cbor();
    // {1: -8} (EdDSA) protected header: a1 01 27
    let raw = build_issuer_signed_with_custom_alg(mso_bytes, dsc_der, vec![0xa1, 0x01, 0x27]);
    let mdoc = ParsedMdoc::parse(&raw).expect("mdoc with Ed448 DSC must still parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let err = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store)
        .expect_err("Ed448 DSC must be rejected");

    // Assert
    assert!(
        matches!(err, MdocError::UnsupportedAlgorithm { alg: -8 }),
        "expected UnsupportedAlgorithm {{ alg: -8 }}, got: {err:?}"
    );
}

// ── NB-6: ES384 and Ed25519 happy-path tests ──────────────────────────────────

/// Builds an IACA root (P-256) and a DSC backed by a P-384 key (ES384 / -35).
///
/// Returns `(iaca_der, dsc_der, dsc_signing_key)`.
fn build_chain_p384() -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
    };

    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root P384".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key =
        cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P384)
            .expect("aws-lc-rs P-384 key generation must succeed");

    let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8,
        )),
        &rcgen::PKCS_ECDSA_P384_SHA384,
    )
    .expect("loading P-384 key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params = CertificateParams::new(vec!["DSC P384".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC P-384 signing by IACA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

/// Like [`build_issuer_signed_with_issuer_auth`] but uses the ES384 algorithm (-35).
///
/// Protected header encodes `{1: -35}` and the payload is signed with SHA-384.
fn build_issuer_signed_es384(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ecdsa::KeyPair,
) -> String {
    // {1: -35} (ES384), CBOR-encoded: a1 01 38 22
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x38, 0x22];

    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(mso_bytes.clone()),
    ]));

    let sig_bytes = signing_key
        .sign_sha384(&tbs)
        .expect("ES384 COSE signing must succeed");

    let unprotected_map = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );

    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);

    let raw = cbor(&issuer_signed);
    Base64UrlUnpadded::encode_string(&raw)
}

#[test]
fn verify_issuer_signature_accepts_valid_es384() {
    // Arrange: P-384 key pair, real ES384 signature, proper chain and EKU.
    let (iaca_der, dsc_der, signing_key) = build_chain_p384();
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_es384(mso_bytes, dsc_der.clone(), &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid ES384 issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let result = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store);

    // Assert
    assert!(
        result.is_ok(),
        "valid ES384 COSE_Sign1 with trusted chain must be accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

/// Builds an IACA root (P-256) and a DSC backed by an Ed25519 key.
///
/// Returns `(iaca_der, dsc_der, dsc_signing_key)`.
fn build_chain_ed25519() -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ed25519::KeyPair) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose,
    };

    let iaca_key = rcgen::KeyPair::generate().expect("rcgen key generation must succeed");
    let mut iaca_params =
        CertificateParams::new(vec!["IACA Root Ed25519".to_string()]).expect("iaca params");
    iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let iaca_cert = iaca_params
        .self_signed(&iaca_key)
        .expect("self-signed IACA cert must succeed");
    let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
    let iaca_issuer = Issuer::new(iaca_params, iaca_key);

    let dsc_aws_key = cloud_wallet_crypto::ed25519::KeyPair::generate()
        .expect("aws-lc-rs Ed25519 key generation must succeed");

    let mut pkcs8_buf = [0u8; 128];
    let dsc_pkcs8 = dsc_aws_key
        .to_pkcs8_der(&mut pkcs8_buf)
        .expect("Ed25519 PKCS#8 export must succeed");
    let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
        &rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
            dsc_pkcs8.to_vec(),
        )),
        &rcgen::PKCS_ED25519,
    )
    .expect("loading Ed25519 key into rcgen must succeed");

    let not_before =
        OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339).expect("fixed date must parse");
    let not_after =
        OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339).expect("fixed date must parse");

    let mut dsc_params =
        CertificateParams::new(vec!["DSC Ed25519".to_string()]).expect("dsc params");
    dsc_params.is_ca = IsCa::NoCa;
    dsc_params.not_before = not_before;
    dsc_params.not_after = not_after;
    dsc_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
    dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let dsc_cert = dsc_params
        .signed_by(&dsc_rcgen_key, &iaca_issuer)
        .expect("DSC Ed25519 signing by IACA must succeed");
    let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

    (iaca_der, dsc_der, dsc_aws_key)
}

/// Like [`build_issuer_signed_with_issuer_auth`] but uses the EdDSA algorithm (-8)
/// with an Ed25519 signing key.
///
/// Protected header encodes `{1: -8}` and the TBS is signed directly by `signing_key`.
fn build_issuer_signed_ed25519(
    mso_bytes: Vec<u8>,
    dsc_der: Vec<u8>,
    signing_key: &cloud_wallet_crypto::ed25519::KeyPair,
) -> String {
    // {1: -8} (EdDSA), CBOR-encoded: a1 01 27
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x27];

    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(mso_bytes.clone()),
    ]));

    let sig_bytes = signing_key.sign(&tbs);

    let unprotected_map = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);

    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );

    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1),
    ]);

    let raw = cbor(&issuer_signed);
    Base64UrlUnpadded::encode_string(&raw)
}

#[test]
fn verify_issuer_signature_accepts_valid_ed25519() {
    // Arrange: Ed25519 key pair, real EdDSA signature, proper chain and EKU.
    let (iaca_der, dsc_der, signing_key) = build_chain_ed25519();
    let mso_bytes = minimal_mso_cbor();
    let raw = build_issuer_signed_ed25519(mso_bytes, dsc_der.clone(), &signing_key);
    let mdoc = ParsedMdoc::parse(&raw).expect("valid Ed25519 issuer-signed mdoc must parse");
    let trust_store = StaticTrustStore::new(vec![iaca_der]);

    // Act
    let result = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store);

    // Assert
    assert!(
        result.is_ok(),
        "valid EdDSA/Ed25519 COSE_Sign1 with trusted chain must be accepted, got: {result:?}"
    );
    let info = result.unwrap();
    assert_eq!(
        info.cert_chain[0], dsc_der,
        "cert_chain[0] must be the DSC leaf certificate"
    );
}

#[test]
fn tbs_data_preserves_original_protected_header_bytes() {
    // Arrange
    let (iaca_der, dsc_der, signing_key) = build_chain(true);
    let mso_bytes = minimal_mso_cbor();

    // {1: -7} (ES256), CBOR-encoded: a1 01 26 — these are the exact bytes the parser
    // will store as CoseSign1::protected::original_data.
    let protected_header_bytes: Vec<u8> = vec![0xa1, 0x01, 0x26];

    // RFC 9052 §4.4 Sig_Structure: ["Signature1", protected_bstr, external_aad, payload]
    let expected_tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header_bytes.clone()),
        Value::Bytes(vec![]), // external AAD = b""
        Value::Bytes(mso_bytes.clone()),
    ]));

    let sig_bytes = signing_key
        .sign_sha256(&expected_tbs)
        .expect("signing must succeed in tests");

    let unprotected_map = Value::Map(vec![(
        Value::Integer(33.into()),
        Value::Array(vec![Value::Bytes(dsc_der)]),
    )]);
    let cose_sign1_val = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header_bytes),
            unprotected_map,
            Value::Bytes(mso_bytes),
            Value::Bytes(sig_bytes.to_vec()),
        ])),
    );
    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Integer(0u64.into())),
        (Value::Text("random".into()), Value::Bytes(vec![0u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Doe".into()),
        ),
    ]);
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let issuer_signed = Value::Map(vec![
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Array(vec![item_tag24]),
            )]),
        ),
        (Value::Text("issuerAuth".into()), cose_sign1_val),
    ]);
    let raw = Base64UrlUnpadded::encode_string(&cbor(&issuer_signed));
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc must parse");

    // Act: ask coset for the Sig_Structure it will use for verification.
    let actual_tbs = mdoc.cose_sign1.tbs_data(b"");

    // Assert: byte-exact match confirms no re-encoding occurred between parse and verify.
    assert_eq!(
        actual_tbs, expected_tbs,
        "tbs_data() must return the same byte sequence as the manually-constructed Sig_Structure"
    );

    // End-to-end confirmation: the signature was created over `expected_tbs`; if
    // tbs_data() had re-encoded the header, verification would fail with InvalidIssuerSignature.
    let trust_store = StaticTrustStore::new(vec![iaca_der]);
    let result = verify_issuer_signature(&mdoc, "org.iso.18013.5.1.mDL", &trust_store);
    assert!(
        result.is_ok(),
        "signature over original protected-header bytes must verify: {result:?}"
    );
}
