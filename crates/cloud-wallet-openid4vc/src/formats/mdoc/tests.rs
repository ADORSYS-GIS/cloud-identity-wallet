use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::Value;

use super::error::MdocError;
use super::parser::parse_issuer_signed;

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
    // IssuerSignedItem
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

    let cose_sign1 = Value::Array(vec![
        Value::Bytes(protected_header_bytes), // protected header bstr
        Value::Map(vec![]),                   // unprotected header {}
        Value::Bytes(mso_bytes),              // payload bstr
        Value::Bytes(vec![0u8; 64]),          // dummy 64-byte signature
    ]);

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

#[test]
fn parses_valid_mdoc() {
    // Arrange: validity window that always brackets "now"
    let raw = build_issuer_signed("2020-01-01T00:00:00Z", "9998-01-01T00:00:00Z");

    // Act
    let mdoc = parse_issuer_signed(&raw).expect("valid mdoc should parse without error");

    // Assert: top-level fields
    assert_eq!(mdoc.doc_type, "org.iso.18013.5.1.mDL");

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
    // Arrange: both timestamps in the distant past  always expired
    let raw = build_issuer_signed("2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z");

    let err = parse_issuer_signed(&raw).expect_err("expired mdoc should be rejected");

    assert!(
        matches!(err, MdocError::ExpiredCredential { .. }),
        "expected ExpiredCredential, got: {err:?}"
    );
}

#[test]
fn rejects_not_yet_valid_mdoc() {
    // Arrange: validity window far in the future — never valid yet
    let raw = build_issuer_signed("9997-01-01T00:00:00Z", "9998-01-01T00:00:00Z");

    let err = parse_issuer_signed(&raw).expect_err("not-yet-valid mdoc should be rejected");

    assert!(
        matches!(err, MdocError::NotYetValid { .. }),
        "expected NotYetValid, got: {err:?}"
    );
}

#[test]
fn rejects_invalid_base64() {
    // Arrange: contains characters illegal in base64url
    let raw = "not!!valid!!base64url";

    let err = parse_issuer_signed(raw).expect_err("invalid base64 should be rejected");

    assert!(
        matches!(err, MdocError::InvalidBase64 { .. }),
        "expected InvalidBase64, got: {err:?}"
    );
}

#[test]
fn rejects_malformed_cbor() {
    // Arrange: valid base64url but the decoded bytes are empty — guaranteed CborDecode (EOF)
    let raw = Base64UrlUnpadded::encode_string(b"");

    let err = parse_issuer_signed(&raw).expect_err("malformed CBOR should be rejected");

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

    let err = parse_issuer_signed(&raw).expect_err("duplicate map key should be rejected");

    assert!(
        matches!(err, MdocError::DuplicateMapKey("nameSpaces")),
        "expected DuplicateMapKey(\"nameSpaces\"), got: {err:?}"
    );
}
