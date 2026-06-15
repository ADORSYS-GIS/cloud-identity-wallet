mod annex_d;
mod parser;
mod verifier;

pub use base64ct::{Base64UrlUnpadded, Encoding};
pub use ciborium::Value;
pub use cloud_wallet_crypto::digest::HashAlg;
pub use cloud_wallet_crypto::jwk::{B64, Curve, Ec, Jwk, Key, Okp, OkpCurve, Parameters};
pub use time::OffsetDateTime;
pub use time::format_description::well_known::Rfc3339;

pub use super::DigestAlgorithm;
pub use super::error::MdocError;
pub use super::parser::ParsedMdoc;
pub use super::verifier::StaticTrustStore;
pub(crate) use super::verifier::{
    verify_device_key_binding, verify_digests, verify_issuer_signature,
};

// CBOR construction helpers

/// Serialises a `ciborium::Value` to CBOR bytes; panics on encoding error
/// (should never occur for well-formed `Value` trees in tests).
pub fn cbor(val: &Value) -> Vec<u8> {
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
pub fn build_issuer_signed(valid_from_str: &str, valid_until_str: &str) -> String {
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
pub fn build_issuer_signed_full(
    valid_from_str: &str,
    valid_until_str: &str,
    digest_algorithm: &str,
    value_digests: Value,
    mso_version: &str,
    item_random: Option<Vec<u8>>,
) -> String {
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
    let item_tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&item))));
    let mso_bytes = build_mso(
        mso_version,
        digest_algorithm,
        value_digests,
        valid_from_str,
        valid_until_str,
    );
    let issuer_auth = dummy_cose1(mso_bytes, vec![0xa1u8, 0x01, 0x26]);
    let name_spaces = Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Array(vec![item_tag24]),
    )]);
    issuer_signed_b64(name_spaces, issuer_auth)
}

/// Builds the `#6.24(bstr .cbor IssuerSignedItem)` encoding for one item
/// and returns `(raw_tag24_bytes, real_sha256_digest)`.
///
/// This mirrors exactly what `parse_issuer_signed_item` stores in
/// `IssuerSignedItem::raw_tag24_bytes` so that the digest computed here will
/// match what `verify_digests` recomputes.
pub fn item_tag24_and_digest(
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

// ── Shared CBOR / COSE fixture helpers ──────────────────────────────────────

/// Dummy P-256 COSE_Key used where no device-key verification is performed.
pub fn dummy_device_key() -> Value {
    Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])), // x
        (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])), // y
    ])
}

/// A single-item nameSpaces map used by verifier-test fixtures.
pub fn default_name_spaces() -> Value {
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
    Value::Map(vec![(
        Value::Text("org.iso.18013.5.1".into()),
        Value::Array(vec![item_tag24]),
    )])
}

/// Assembles a real COSE_Sign1 (tag 18) over `mso_bytes` with the given protected
/// header and x5chain value in the unprotected header (label 33). `sign_fn` computes
/// the raw signature over the Sig_Structure bytes; pass `|_| vec![0u8; N]` for
/// fixtures whose error fires before signature verification. Set `tamper = true`
/// to flip one byte so the signature is cryptographically invalid while the CBOR
/// structure remains intact.
pub fn signed_cose1(
    mso_bytes: Vec<u8>,
    protected_header: Vec<u8>,
    x5chain: Value,
    sign_fn: impl Fn(&[u8]) -> Vec<u8>,
    tamper: bool,
) -> Value {
    let tbs = cbor(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_header.clone()),
        Value::Bytes(vec![]), // external AAD = b""
        Value::Bytes(mso_bytes.clone()),
    ]));
    let mut sig = sign_fn(&tbs);
    if tamper {
        sig[0] ^= 0xff;
    }
    let unprotected = Value::Map(vec![(Value::Integer(33.into()), x5chain)]);
    Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header),
            unprotected,
            Value::Bytes(mso_bytes),
            Value::Bytes(sig),
        ])),
    )
}

/// Assembles an unsigned COSE_Sign1 (tag 18) with an empty unprotected header and
/// a 64-byte zero signature. The COSE payload is `#6.24(bstr .cbor mso_bytes)` per
/// ISO 18013-5 §9.1.2. Used by parser-test fixtures where signature validity is
/// irrelevant.
pub fn dummy_cose1(mso_bytes: Vec<u8>, protected_header: Vec<u8>) -> Value {
    let mso_payload = cbor(&Value::Tag(24, Box::new(Value::Bytes(mso_bytes))));
    Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_header),
            Value::Map(vec![]), // empty unprotected header
            Value::Bytes(mso_payload),
            Value::Bytes(vec![0u8; 64]), // dummy signature
        ])),
    )
}

/// Encodes a complete `IssuerSigned` map with `nameSpaces` and `issuerAuth` as an
/// unpadded base64url string.
pub fn issuer_signed_b64(name_spaces: Value, issuer_auth: Value) -> String {
    let issuer_signed = Value::Map(vec![
        (Value::Text("nameSpaces".into()), name_spaces),
        (Value::Text("issuerAuth".into()), issuer_auth),
    ]);
    Base64UrlUnpadded::encode_string(&cbor(&issuer_signed))
}

/// Builds the raw CBOR bytes of a `MobileSecurityObject` map.
///
/// Hardcodes: `docType = "org.iso.18013.5.1.mDL"`, `deviceKey = dummy_device_key()`,
/// `signed = "1999-01-01T00:00:00Z"`. Pass the result directly to `dummy_cose1` or
/// `signed_cose1` as `mso_bytes`.
pub fn build_mso(
    version: &str,
    digest_alg: &str,
    value_digests: Value,
    valid_from: &str,
    valid_until: &str,
) -> Vec<u8> {
    let mso = Value::Map(vec![
        (Value::Text("version".into()), Value::Text(version.into())),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text(digest_alg.into()),
        ),
        (Value::Text("valueDigests".into()), value_digests),
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(Value::Text("deviceKey".into()), dummy_device_key())]),
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
                    Value::Tag(0, Box::new(Value::Text(valid_from.into()))),
                ),
                (
                    Value::Text("validUntil".into()),
                    Value::Tag(0, Box::new(Value::Text(valid_until.into()))),
                ),
            ]),
        ),
    ]);
    cbor(&mso)
}
