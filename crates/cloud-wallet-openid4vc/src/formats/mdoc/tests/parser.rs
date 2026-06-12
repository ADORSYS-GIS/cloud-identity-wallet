use super::*;
/// Builds a complete `IssuerSigned` base64url string whose `valueDigests` entries
/// are the real hashes (using `alg`) of the corresponding `#6.24` item encodings.
///
/// The single item has `digestID = 0`, `elementIdentifier = "family_name"`,
/// `elementValue = "Doe"`.
fn build_issuer_signed_with_correct_digests_for(alg: HashAlg, alg_str: &str) -> String {
    let (item_tag24_bytes, digest_bytes) = item_tag24_and_digest(0, "family_name", "Doe", alg);
    let item_tag24_val: Value =
        ciborium::de::from_reader(item_tag24_bytes.as_slice()).expect("round-trip must succeed");
    let value_digests = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![(
            Value::Integer(0u64.into()),
            Value::Bytes(digest_bytes),
        )]),
    )]);
    let mso_bytes = build_mso(
        "1.0",
        alg_str,
        value_digests,
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
    );
    let issuer_auth = dummy_cose1(mso_bytes, vec![0xa1u8, 0x01, 0x26]);
    let name_spaces = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Array(vec![item_tag24_val]),
    )]);
    issuer_signed_b64(name_spaces, issuer_auth)
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
    let value_digests = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![
            (Value::Integer(0u64.into()), Value::Bytes(digest0)),
            (Value::Integer(1u64.into()), Value::Bytes(digest1)),
        ]),
    )]);
    let mso_bytes = build_mso(
        "1.0",
        "SHA-256",
        value_digests,
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
    );
    let issuer_auth = dummy_cose1(mso_bytes, vec![0xa1u8, 0x01, 0x26]);
    let name_spaces = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Array(vec![val0, val1]),
    )]);
    issuer_signed_b64(name_spaces, issuer_auth)
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
    let value_digests = Value::Map(vec![
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
    ]);
    let mso_bytes = build_mso(
        "1.0",
        "SHA-256",
        value_digests,
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
    );
    let issuer_auth = dummy_cose1(mso_bytes, vec![0xa1u8, 0x01, 0x26]);
    let name_spaces = Value::Map(vec![
        (
            Value::Text("org.iso.18013.5.1".into()),
            Value::Array(vec![val_ns1]),
        ),
        (
            Value::Text("org.iso.18013.5.1.US".into()),
            Value::Array(vec![val_ns2]),
        ),
    ]);
    issuer_signed_b64(name_spaces, issuer_auth)
}

/// Builds a base64url-encoded `IssuerSigned` with a caller-controlled
/// `nameSpaces` value.
///
/// The MSO (`version`, `digestAlgorithm`, `validityInfo`, `valueDigests`,
/// `deviceKeyInfo`, `docType`) and the `COSE_Sign1` (`issuerAuth`) are
/// constructed with minimal but structurally valid values, so that parsing
/// reaches `parse_name_spaces` before encountering the injected error.
fn build_issuer_signed_with_ns(name_spaces_val: Value) -> String {
    let value_digests = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Map(vec![(
            Value::Integer(0u64.into()),
            Value::Bytes(vec![0u8; 32]),
        )]),
    )]);
    let mso_bytes = build_mso(
        "1.0",
        "SHA-256",
        value_digests,
        "2020-01-01T00:00:00Z",
        "9998-01-01T00:00:00Z",
    );
    let issuer_auth = dummy_cose1(mso_bytes, vec![0xa1u8, 0x01, 0x26]);
    issuer_signed_b64(name_spaces_val, issuer_auth)
}

// ── Parser tests ─────────────────────────────────────────────────────────────

#[test]
fn parses_valid_mdoc() {
    let raw = build_issuer_signed("2020-01-01T00:00:00Z", "9998-01-01T00:00:00Z");

    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse without error");

    assert_eq!(mdoc.doc_type, "org.iso.18013.5.1.mDL");

    assert_eq!(mdoc.digest_algorithm, DigestAlgorithm::Sha256);

    let items = mdoc
        .name_spaces
        .get("org.iso.18013.5.1")
        .expect("namespace must be present");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].digest_id, 0);
    assert_eq!(items[0].element_identifier, "family_name");
    assert!(!items[0].raw_tag24_bytes.is_empty());

    assert!(mdoc.value_digests.contains_key("org.iso.18013.5.1"));
    assert!(mdoc.value_digests["org.iso.18013.5.1"].contains_key(&0));

    assert!(!mdoc.device_key.is_empty());

    assert!(!mdoc.raw_issuer_signed_bytes.is_empty());
}

#[test]
fn rejects_expired_mdoc() {
    let raw = build_issuer_signed("2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z");
    let now = OffsetDateTime::parse("2000-01-03T00:00:00Z", &Rfc3339)
        .expect("fixed timestamp must parse");

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
    let raw = build_issuer_signed("9997-01-01T00:00:00Z", "9998-01-01T00:00:00Z");
    let now = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339)
        .expect("fixed timestamp must parse");

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
    let raw = build_issuer_signed("2020-01-01T00:00:00Z", "9998-01-01T00:00:00Z");
    let now = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339)
        .expect("fixed timestamp must parse");

    let mdoc =
        ParsedMdoc::parse_and_validate(&raw, now).expect("valid mdoc should pass validation");
    assert_eq!(mdoc.doc_type, "org.iso.18013.5.1.mDL");
}

#[test]
fn parse_and_validate_rejects_expired() {
    let raw = build_issuer_signed("2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z");
    let now = OffsetDateTime::parse("2000-01-03T00:00:00Z", &Rfc3339)
        .expect("fixed timestamp must parse");

    let err = ParsedMdoc::parse_and_validate(&raw, now)
        .expect_err("expired mdoc should be rejected by parse_and_validate");

    assert!(
        matches!(err, MdocError::ExpiredCredential { .. }),
        "expected ExpiredCredential, got: {err:?}"
    );
}

#[test]
fn rejects_invalid_base64() {
    let raw = "not!!valid!!base64url";

    let err = ParsedMdoc::parse(raw).expect_err("invalid base64 should be rejected");

    assert!(
        matches!(err, MdocError::InvalidBase64 { .. }),
        "expected InvalidBase64, got: {err:?}"
    );
}

#[test]
fn rejects_malformed_cbor() {
    let raw = Base64UrlUnpadded::encode_string(b"");

    let err = ParsedMdoc::parse(&raw).expect_err("malformed CBOR should be rejected");

    assert!(
        matches!(err, MdocError::CborDecode { .. }),
        "expected CborDecode, got: {err:?}"
    );
}

#[test]
fn rejects_duplicate_map_key() {
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

    let err = ParsedMdoc::parse(&raw).expect_err("unsupported digest algorithm should be rejected");

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

    let err = ParsedMdoc::parse(&raw).expect_err("version 2.0 should be rejected");

    assert!(
        matches!(err, MdocError::UnsupportedMsoVersion { ref version } if version == "2.0"),
        "expected UnsupportedMsoVersion(\"2.0\"), got: {err:?}"
    );
}

#[test]
fn rejects_duplicate_digest_id() {
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

    let err = ParsedMdoc::parse(&raw).expect_err("duplicate digestID should be rejected");

    assert!(
        matches!(err, MdocError::DuplicateMapKey { key: "digestID" }),
        "expected DuplicateMapKey {{ key: \"digestID\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_duplicate_namespace_in_value_digests() {
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

    let err = ParsedMdoc::parse(&raw).expect_err("duplicate namespace key should be rejected");

    assert!(
        matches!(err, MdocError::DuplicateMapKey { key: "namespace" }),
        "expected DuplicateMapKey {{ key: \"namespace\" }}, got: {err:?}"
    );
}

#[test]
fn verify_digests_passes_for_all_valid() {
    let raw = build_issuer_signed_with_correct_digests();
    let mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse");

    let result = verify_digests(&mdoc);

    assert!(result.is_ok(), "all valid digests should pass: {result:?}");
}

#[test]
fn verify_digests_passes_sha384() {
    let raw = build_issuer_signed_with_correct_digests_for(HashAlg::Sha384, "SHA-384");
    let mdoc = ParsedMdoc::parse(&raw).expect("valid SHA-384 mdoc should parse");
    assert_eq!(mdoc.digest_algorithm, DigestAlgorithm::Sha384);

    let result = verify_digests(&mdoc);

    assert!(result.is_ok(), "SHA-384 digests should pass: {result:?}");
}

#[test]
fn verify_digests_passes_sha512() {
    let raw = build_issuer_signed_with_correct_digests_for(HashAlg::Sha512, "SHA-512");
    let mdoc = ParsedMdoc::parse(&raw).expect("valid SHA-512 mdoc should parse");
    assert_eq!(mdoc.digest_algorithm, DigestAlgorithm::Sha512);

    let result = verify_digests(&mdoc);

    assert!(result.is_ok(), "SHA-512 digests should pass: {result:?}");
}

#[test]
fn verify_digests_rejects_tampered_item() {
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

    let err = verify_digests(&mdoc).expect_err("tampered item must be rejected");

    assert!(
        matches!(err, MdocError::DigestMismatch { ref namespace, digest_id: 0 } if namespace == "org.iso.18013.5.1"),
        "expected DigestMismatch {{ namespace: org.iso.18013.5.1, digest_id: 0 }}, got: {err:?}"
    );
}

#[test]
fn rejects_wrong_digest_length() {
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

    let err = ParsedMdoc::parse(&raw).expect_err("wrong digest length should be rejected");

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
    // ISO 18013-5 §9.1.2.4 requires validFrom >= signed.
    let raw = build_issuer_signed("1998-01-01T00:00:00Z", "9998-01-01T00:00:00Z");

    let err = ParsedMdoc::parse(&raw).expect_err("validFrom before signed must be rejected");

    assert!(
        matches!(err, MdocError::InvalidValidityInfo),
        "expected InvalidValidityInfo, got: {err:?}"
    );
}

#[test]
fn rejects_validity_info_valid_until_equal_to_valid_from() {
    let raw = build_issuer_signed("2020-01-01T00:00:00Z", "2020-01-01T00:00:00Z");

    let err = ParsedMdoc::parse(&raw).expect_err("validUntil equal to validFrom must be rejected");

    assert!(
        matches!(err, MdocError::InvalidValidityInfo),
        "expected InvalidValidityInfo, got: {err:?}"
    );
}

#[test]
fn rejects_random_field_too_short() {
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

    let err = ParsedMdoc::parse(&raw).expect_err("15-byte random field must be rejected");

    assert!(
        matches!(err, MdocError::InvalidRandomLength { actual: 15 }),
        "expected InvalidRandomLength {{ actual: 15 }}, got: {err:?}"
    );
}

#[test]
fn rejects_random_field_absent() {
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

    let err = ParsedMdoc::parse(&raw).expect_err("absent random field must be rejected");

    assert!(
        matches!(err, MdocError::MissingField { field: "random" }),
        "expected MissingField {{ field: \"random\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_digest_id_out_of_range() {
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

    let err = ParsedMdoc::parse(&raw).expect_err("digestID >= 2^31 must be rejected");

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

#[test]
fn rejects_non_array_issuer_auth() {
    let issuer_signed = Value::Map(vec![
        (Value::Text("nameSpaces".into()), Value::Map(vec![])),
        (
            Value::Text("issuerAuth".into()),
            Value::Text("not-a-cose-sign1".into()),
        ),
    ]);
    let raw = Base64UrlUnpadded::encode_string(&cbor(&issuer_signed));

    let err = ParsedMdoc::parse(&raw).expect_err("non-array issuerAuth must be rejected");

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

    let err = ParsedMdoc::parse(&raw).expect_err("empty valueDigests must be rejected");

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

    let err = ParsedMdoc::parse(&raw).expect_err("empty DigestIDs must be rejected");

    assert!(
        matches!(err, MdocError::UnexpectedCborType { field: "DigestIDs" }),
        "expected UnexpectedCborType {{ field: \"DigestIDs\" }}, got: {err:?}"
    );
}

#[test]
fn rejects_empty_name_spaces() {
    // ISO 18013-5 CDDL: IssuerNameSpaces = { + NameSpace => [ + IssuerSignedItemBytes ] }
    // The `+` operator requires at least one namespace.
    let raw = build_issuer_signed_with_ns(Value::Map(vec![]));

    let err = ParsedMdoc::parse(&raw).expect_err("empty nameSpaces must be rejected");

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
    // ISO 18013-5 CDDL: [ + IssuerSignedItemBytes ] — at least one item is required
    // per namespace; an empty array must be rejected to prevent a namespace with no
    // verifiable elements from being silently accepted.
    let empty_ns = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Array(vec![]), // namespace present but no items
    )]);
    let raw = build_issuer_signed_with_ns(empty_ns);

    let err = ParsedMdoc::parse(&raw).expect_err("empty namespace item array must be rejected");

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
    let raw = build_issuer_signed_with_correct_digests();
    let mut mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse");

    // Remove the only entry in the namespace digest map so the lookup fails.
    mdoc.value_digests
        .get_mut("org.iso.18013.5.1")
        .expect("namespace must be present")
        .remove(&0);

    let err = verify_digests(&mdoc).expect_err("missing digest must be rejected");

    assert!(
        matches!(err, MdocError::MissingDigest { ref namespace, digest_id: 0 } if namespace == "org.iso.18013.5.1"),
        "expected MissingDigest {{ namespace: org.iso.18013.5.1, digest_id: 0 }}, got: {err:?}"
    );
}

#[test]
fn verify_digests_rejects_second_of_two_items_in_same_namespace() {
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

    let err = verify_digests(&mdoc).expect_err("tampered second item must be rejected");

    assert!(
        matches!(err, MdocError::DigestMismatch { ref namespace, digest_id: 1 }
            if namespace == "org.iso.18013.5.1"),
        "expected DigestMismatch {{ namespace: org.iso.18013.5.1, digest_id: 1 }}, got: {err:?}"
    );
}

#[test]
fn verify_digests_rejects_item_in_second_namespace() {
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

    let err =
        verify_digests(&mdoc).expect_err("tampered item in second namespace must be rejected");

    assert!(
        matches!(err, MdocError::DigestMismatch { ref namespace, digest_id: 0 }
            if namespace == "org.iso.18013.5.1.US"),
        "expected DigestMismatch {{ namespace: org.iso.18013.5.1.US, digest_id: 0 }}, got: {err:?}"
    );
}

#[test]
fn verify_digests_rejects_namespace_absent_from_value_digests() {
    // This covers the `value_digests.get(namespace) → None` branch in verify_digests,
    // which is distinct from removing only the digestID entry (covered by
    // `verify_digests_rejects_missing_digest`).
    let raw = build_issuer_signed_with_correct_digests();
    let mut mdoc = ParsedMdoc::parse(&raw).expect("valid mdoc should parse");
    mdoc.value_digests.remove("org.iso.18013.5.1");

    let err =
        verify_digests(&mdoc).expect_err("namespace absent from value_digests must be rejected");

    assert!(
        matches!(err, MdocError::MissingDigest { ref namespace, digest_id: 0 }
            if namespace == "org.iso.18013.5.1"),
        "expected MissingDigest {{ namespace: org.iso.18013.5.1, digest_id: 0 }}, got: {err:?}"
    );
}
