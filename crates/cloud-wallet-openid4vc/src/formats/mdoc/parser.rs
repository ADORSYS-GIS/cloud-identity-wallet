//! Parser for ISO 18013-5 `IssuerSigned` mDoc structures.

use std::collections::HashMap;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::Value;
use coset::CborSerializable as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::error::{MdocError, Result};

/// A parsed mDoc `IssuerSigned` structure.
///
/// Structural parsing is complete but temporal validity has **not** been checked.
/// Call [`ParsedMdoc::check_temporal_validity`] with the current time before
/// trusting any credential field, and re-check on cached instances.
#[derive(Debug)]
pub struct ParsedMdoc {
    /// `docType` field from the Mobile Security Object (e.g. `"org.iso.18013.5.1.mDL"`).
    pub doc_type: String,

    /// `validityInfo.signed` timestamp from the MSO.
    pub signed_at: OffsetDateTime,

    /// `validityInfo.validFrom` timestamp from the MSO.
    pub valid_from: OffsetDateTime,

    /// `validityInfo.validUntil` from the MSO.
    pub valid_until: OffsetDateTime,

    /// Hash algorithm named in the MSO `digestAlgorithm` field (e.g. `"SHA-256"`).
    ///
    /// Guaranteed to be one of `"SHA-256"`, `"SHA-384"`, or `"SHA-512"` per
    /// ISO 18013-5 §9.1.2.5. Phase 2 uses this to select the hash function when
    /// verifying [`ParsedMdoc::value_digests`].
    pub digest_algorithm: String,

    /// Per-namespace digest map: `namespace → (digestID → digest bytes)`.
    ///
    /// Phase 2 verifies by hashing each [`IssuerSignedItem::raw_tag24_bytes`] under
    /// [`ParsedMdoc::digest_algorithm`] and comparing the result.
    pub value_digests: HashMap<String, HashMap<u64, Vec<u8>>>,

    /// CBOR-encoded `DeviceKey` COSE_Key from `deviceKeyInfo.deviceKey`.
    ///
    /// Raw bytes; Phase 2 decodes for device-key binding.
    pub device_key: Vec<u8>,

    /// Signed items grouped by namespace.
    pub name_spaces: HashMap<String, Vec<IssuerSignedItem>>,

    /// `issuerAuth` COSE_Sign1; retained for Phase 2 signature verification.
    pub cose_sign1: coset::CoseSign1,

    /// Raw `IssuerSigned` CBOR bytes as received from the issuer.
    pub raw_issuer_signed_bytes: Vec<u8>,
}

/// A single signed data element from an mDoc namespace.
///
/// Phase 2 verifies integrity: `SHA-256(raw_tag24_bytes)` must match the
/// corresponding entry in [`ParsedMdoc::value_digests`].
#[derive(Debug)]
pub struct IssuerSignedItem {
    /// Index into the MSO `valueDigests` for this namespace.
    pub digest_id: u64,

    /// Data element identifier (e.g. `"family_name"`).
    pub element_identifier: String,

    /// Raw CBOR bytes of the element value.
    pub element_value: Vec<u8>,

    /// `#6.24(bstr)` encoding of the item — Phase 2 digest input:
    /// `SHA-256(raw_tag24_bytes)` must equal the [`ParsedMdoc::value_digests`] entry.
    pub raw_tag24_bytes: Vec<u8>,
}

impl ParsedMdoc {
    /// Parses a base64url-encoded CBOR `IssuerSigned` structure.
    ///
    /// Decodes and validates the structure but does **not** check temporal validity.
    /// Call [`ParsedMdoc::check_temporal_validity`] with the current time before
    /// using the returned credential.
    ///
    /// # Errors
    ///
    /// Returns [`MdocError`] on: invalid base64url, malformed CBOR, missing required
    /// fields, or detached COSE_Sign1 payload.
    pub fn parse(base64url: &str) -> Result<Self> {
        let raw = Base64UrlUnpadded::decode_vec(base64url)
            .map_err(|source| MdocError::InvalidBase64 { source })?;

        let issuer_signed_val: Value = ciborium::de::from_reader(raw.as_slice())
            .map_err(|source| MdocError::CborDecode { source })?;

        let mut issuer_signed_map = into_map(issuer_signed_val, "IssuerSigned")?;

        let name_spaces_val = take_entry(&mut issuer_signed_map, "nameSpaces")?;
        let issuer_auth_val = take_entry(&mut issuer_signed_map, "issuerAuth")?;

        // coset::CoseSign1::from_slice expects the bare array, not the CBOR tag 18 wrapper
        // (coset v0.3.x strips the tag when embedded in a containing structure — RFC 9052 §4.2).
        let cose_payload_val = match issuer_auth_val {
            Value::Tag(18, inner) => *inner,
            other => other,
        };

        let issuer_auth_cbor =
            encode_value(&cose_payload_val).map_err(|reason| MdocError::CborEncode { reason })?;

        let cose_sign1 = coset::CoseSign1::from_slice(&issuer_auth_cbor)
            .map_err(|source| MdocError::InvalidCoseSign1 { source })?;

        let mso_payload_bytes = cose_sign1
            .payload
            .clone()
            .ok_or(MdocError::MissingCosePayload)?;

        // ISO 18013-5 §9.1.2: the COSE_Sign1 payload is
        // MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject).
        // Decode the outer Tag(24, Bytes(mso_cbor)) wrapper first, then decode the
        // inner bytes as the MSO map.
        let mso_cbor = match ciborium::de::from_reader::<Value, _>(mso_payload_bytes.as_slice())
            .map_err(|source| MdocError::CborDecode { source })?
        {
            Value::Tag(24, inner) => match *inner {
                Value::Bytes(b) => b,
                _ => {
                    return Err(MdocError::UnexpectedCborType {
                        field: "MobileSecurityObjectBytes",
                    });
                }
            },
            _ => {
                return Err(MdocError::UnexpectedCborType {
                    field: "MobileSecurityObjectBytes",
                });
            }
        };

        let mso_val: Value = ciborium::de::from_reader(mso_cbor.as_slice())
            .map_err(|source| MdocError::CborDecode { source })?;

        let mut mso_map = into_map(mso_val, "MobileSecurityObject")?;

        let doc_type = take_text(&mut mso_map, "docType")?;

        // ISO 18013-5 §9.1.2.4: `version` is a required field. Per §8.1, reject
        // an unknown major version but accept any minor version bump.
        let version = take_text(&mut mso_map, "version")?;
        let major = version.split('.').next().unwrap_or("0");
        if major != "1" {
            return Err(MdocError::UnsupportedMsoVersion { version });
        }

        // ISO 18013-5 §9.1.2.5: only SHA-256, SHA-384, and SHA-512 are valid.
        // Reject anything else at parse time so Phase 2 never sees an unknown hash.
        let digest_algorithm = take_text(&mut mso_map, "digestAlgorithm")?;
        match digest_algorithm.as_str() {
            "SHA-256" | "SHA-384" | "SHA-512" => {}
            _ => {
                return Err(MdocError::UnsupportedDigestAlgorithm {
                    algorithm: digest_algorithm,
                });
            }
        }

        let validity_val = take_entry(&mut mso_map, "validityInfo")?;
        let mut validity_map = into_map(validity_val, "validityInfo")?;

        let signed_at = take_tdate(&mut validity_map, "signed")?;
        let valid_from = take_tdate(&mut validity_map, "validFrom")?;
        let valid_until = take_tdate(&mut validity_map, "validUntil")?;

        let value_digests_val = take_entry(&mut mso_map, "valueDigests")?;
        let value_digests = parse_value_digests(value_digests_val, &digest_algorithm)?;

        let device_key_info_val = take_entry(&mut mso_map, "deviceKeyInfo")?;
        let mut device_key_info_map = into_map(device_key_info_val, "deviceKeyInfo")?;
        let device_key_val = take_entry(&mut device_key_info_map, "deviceKey")?;
        let device_key =
            encode_value(&device_key_val).map_err(|reason| MdocError::CborEncode { reason })?;

        let name_spaces = parse_name_spaces(name_spaces_val)?;

        Ok(Self {
            doc_type,
            digest_algorithm,
            signed_at,
            valid_from,
            valid_until,
            value_digests,
            device_key,
            name_spaces,
            cose_sign1,
            raw_issuer_signed_bytes: raw,
        })
    }

    /// Parses and immediately validates temporal validity in one step.
    ///
    /// Equivalent to calling [`ParsedMdoc::parse`] followed by
    /// [`ParsedMdoc::check_temporal_validity`]. Use this as the default call site
    /// for normal credential consumption; it is impossible to forget the validity
    /// check when using this constructor.
    ///
    /// Pass `OffsetDateTime::now_utc()` in production code.
    ///
    /// # Errors
    ///
    /// Returns [`MdocError`] on any parse failure, or [`MdocError::NotYetValid`] /
    /// [`MdocError::ExpiredCredential`] if `now` falls outside the validity window.
    pub fn parse_and_validate(base64url: &str, now: OffsetDateTime) -> Result<Self> {
        let mdoc = Self::parse(base64url)?;
        mdoc.check_temporal_validity(now)?;
        Ok(mdoc)
    }

    /// Checks that `now` falls within the `[valid_from, valid_until]` validity window
    /// (ISO 18013-5 §9.3.1).
    ///
    /// Pass `OffsetDateTime::now_utc()` for live validation. Pass a fixed timestamp
    /// in tests to cover exact boundary conditions deterministically.
    ///
    /// # Errors
    ///
    /// Returns [`MdocError::NotYetValid`] if `now < valid_from`, or
    /// [`MdocError::ExpiredCredential`] if `now > valid_until`.
    pub fn check_temporal_validity(&self, now: OffsetDateTime) -> Result<()> {
        if now < self.valid_from {
            return Err(MdocError::NotYetValid {
                valid_from: self
                    .valid_from
                    .format(&Rfc3339)
                    .expect("OffsetDateTime always formats to RFC3339"),
            });
        }
        if now > self.valid_until {
            return Err(MdocError::ExpiredCredential {
                valid_until: self
                    .valid_until
                    .format(&Rfc3339)
                    .expect("OffsetDateTime always formats to RFC3339"),
            });
        }
        Ok(())
    }
}

/// Serialises a `ciborium::Value` to CBOR bytes.
fn encode_value(val: &Value) -> std::result::Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(val, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn into_map(val: Value, field: &'static str) -> Result<Vec<(Value, Value)>> {
    match val {
        Value::Map(entries) => Ok(entries),
        _ => Err(MdocError::UnexpectedCborType { field }),
    }
}

fn take_entry(map: &mut Vec<(Value, Value)>, key: &'static str) -> Result<Value> {
    let count = map
        .iter()
        .filter(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .count();
    if count > 1 {
        return Err(MdocError::DuplicateMapKey(key));
    }
    let pos = map
        .iter()
        .position(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .ok_or(MdocError::MissingField(key))?;
    Ok(map.remove(pos).1)
}

fn take_text(map: &mut Vec<(Value, Value)>, key: &'static str) -> Result<String> {
    match take_entry(map, key)? {
        Value::Text(s) => Ok(s),
        _ => Err(MdocError::UnexpectedCborType { field: key }),
    }
}

/// Decodes an ISO 18013-5 `tdate` field: `#6.0(tstr)` → `OffsetDateTime`.
fn take_tdate(map: &mut Vec<(Value, Value)>, key: &'static str) -> Result<OffsetDateTime> {
    // ISO 18013-5 §8.3.3: tdate = #6.0(tstr) — Tag 0 wrapping an RFC 3339 text string.
    let date_str = match take_entry(map, key)? {
        Value::Tag(0, inner) => match *inner {
            Value::Text(s) => s,
            _ => return Err(MdocError::UnexpectedCborType { field: key }),
        },
        _ => return Err(MdocError::UnexpectedCborType { field: key }),
    };

    OffsetDateTime::parse(&date_str, &Rfc3339)
        .map_err(|_| MdocError::UnexpectedCborType { field: key })
}

fn parse_value_digests(
    val: Value,
    digest_algorithm: &str,
) -> Result<HashMap<String, HashMap<u64, Vec<u8>>>> {
    // Expected digest byte length for each permitted algorithm (ISO 18013-5 §9.1.2.5).
    let expected_len: usize = match digest_algorithm {
        "SHA-256" => 32,
        "SHA-384" => 48,
        "SHA-512" => 64,
        // Already validated by the caller; unreachable in practice.
        _ => unreachable!("digest_algorithm was validated before calling parse_value_digests"),
    };

    let ns_map = into_map(val, "valueDigests")?;
    let mut out: HashMap<String, HashMap<u64, Vec<u8>>> = HashMap::new();

    for (ns_key, digests_val) in ns_map {
        let namespace = match ns_key {
            Value::Text(s) => s,
            _ => {
                return Err(MdocError::UnexpectedCborType {
                    field: "valueDigests key",
                });
            }
        };

        let digest_map = into_map(digests_val, "DigestIDs")?;
        let mut ids: HashMap<u64, Vec<u8>> = HashMap::new();

        for (id_val, digest_val) in digest_map {
            let digest_id = cbor_int_to_u64(id_val, "digestID")?;
            let bytes = match digest_val {
                Value::Bytes(b) => b,
                _ => return Err(MdocError::UnexpectedCborType { field: "Digest" }),
            };
            if bytes.len() != expected_len {
                return Err(MdocError::InvalidDigestLength {
                    namespace: namespace.clone(),
                    digest_id,
                    algorithm: digest_algorithm.to_owned(),
                    expected: expected_len,
                    actual: bytes.len(),
                });
            }
            // RFC 8949 §5.6: duplicate keys in security-sensitive CBOR maps must
            // be rejected — a second value behind the same digestID would be silently
            // discarded by HashMap::insert, enabling digest-substitution attacks.
            if ids.insert(digest_id, bytes).is_some() {
                return Err(MdocError::DuplicateMapKey("digestID"));
            }
        }

        if out.insert(namespace, ids).is_some() {
            return Err(MdocError::DuplicateMapKey("namespace"));
        }
    }

    Ok(out)
}

fn parse_name_spaces(val: Value) -> Result<HashMap<String, Vec<IssuerSignedItem>>> {
    let ns_map = into_map(val, "nameSpaces")?;
    let mut out: HashMap<String, Vec<IssuerSignedItem>> = HashMap::new();

    for (ns_key, items_val) in ns_map {
        let namespace = match ns_key {
            Value::Text(s) => s,
            _ => {
                return Err(MdocError::UnexpectedCborType {
                    field: "nameSpaces key",
                });
            }
        };

        let items_arr = match items_val {
            Value::Array(a) => a,
            _ => {
                return Err(MdocError::UnexpectedCborType {
                    field: "IssuerNameSpaces",
                });
            }
        };

        let mut parsed_items = Vec::with_capacity(items_arr.len());
        for item_val in items_arr {
            parsed_items.push(parse_issuer_signed_item(item_val)?);
        }

        out.insert(namespace, parsed_items);
    }

    Ok(out)
}

/// Parses one `IssuerSignedItemBytes` entry (`#6.24(bstr .cbor IssuerSignedItem)`).
fn parse_issuer_signed_item(val: Value) -> Result<IssuerSignedItem> {
    // Encode the original #6.24(bstr) before consuming val.
    // ISO 18013-5 §9.3.1: digest_i = SHA-256(#6.24(bstr .cbor IssuerSignedItem_i)).
    // Encoding directly from val avoids reconstructing the tag after destructuring,
    // which would introduce a superfluous encode step. Correctness relies on
    // deterministic CBOR (RFC 8949 §4.2), which ISO 18013-5 §8.1 mandates.
    let raw_tag24_bytes = encode_value(&val).map_err(|reason| MdocError::CborEncode { reason })?;

    let inner_bytes = match val {
        Value::Tag(24, inner) => match *inner {
            Value::Bytes(b) => b,
            _ => {
                return Err(MdocError::UnexpectedCborType {
                    field: "IssuerSignedItemBytes",
                });
            }
        },
        _ => {
            return Err(MdocError::UnexpectedCborType {
                field: "IssuerSignedItemBytes",
            });
        }
    };

    let item_val: Value = ciborium::de::from_reader(inner_bytes.as_slice())
        .map_err(|source| MdocError::CborDecode { source })?;

    let mut item_map = into_map(item_val, "IssuerSignedItem")?;

    let digest_id_val = take_entry(&mut item_map, "digestID")?;
    let digest_id = cbor_int_to_u64(digest_id_val, "digestID")?;

    let element_identifier = take_text(&mut item_map, "elementIdentifier")?;
    let element_value_raw = take_entry(&mut item_map, "elementValue")?;
    let element_value =
        encode_value(&element_value_raw).map_err(|reason| MdocError::CborEncode { reason })?;

    Ok(IssuerSignedItem {
        digest_id,
        element_identifier,
        element_value,
        raw_tag24_bytes,
    })
}

fn cbor_int_to_u64(val: Value, field: &'static str) -> Result<u64> {
    match val {
        Value::Integer(i) => {
            let n: i128 = i.into();
            u64::try_from(n).map_err(|_| MdocError::UnexpectedCborType { field })
        }
        _ => Err(MdocError::UnexpectedCborType { field }),
    }
}
