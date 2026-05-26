//! Parser for ISO 18013-5 `IssuerSigned` mDoc structures.

use std::collections::HashMap;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::Value;
use coset::CborSerializable as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::error::{MdocError, Result};

/// A successfully parsed and temporally-valid mDoc `IssuerSigned` structure.
///
/// Callers that cache this value must re-check [`valid_from`]/[`valid_until`]
/// against the current clock before each use.
///
/// [`valid_from`]: ParsedMdoc::valid_from
/// [`valid_until`]: ParsedMdoc::valid_until
#[derive(Debug)]
pub struct ParsedMdoc {
    /// `docType` field from the Mobile Security Object (e.g. `"org.iso.18013.5.1.mDL"`).
    pub doc_type: String,

    /// `validityInfo.signed` timestamp from the MSO.
    pub signed_at: OffsetDateTime,

    /// `validityInfo.validFrom` timestamp from the MSO.
    pub valid_from: OffsetDateTime,

    /// `validityInfo.validUntil` from the MSO. Checked at parse time (ISO 18013-5 §9.3.1);
    /// cached instances must re-validate.
    pub valid_until: OffsetDateTime,

    /// Per-namespace digest map: `namespace → (digestID → SHA-256 digest bytes)`.
    ///
    /// Phase 2 verifies by comparing against `SHA-256(`[`IssuerSignedItem::raw_tag24_bytes`]`)`.
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

/// Parses a base64url-encoded CBOR `IssuerSigned` structure.
///
/// Validates the `validityInfo` window (ISO 18013-5 §9.3.1); returns
/// [`MdocError::ExpiredCredential`] or [`MdocError::NotYetValid`] if outside the window.
///
/// # Errors
///
/// Returns [`MdocError`] on: invalid base64url, malformed CBOR, missing required
/// fields, out-of-range validity window, or detached COSE_Sign1 payload.
pub fn parse_issuer_signed(base64url: &str) -> Result<ParsedMdoc> {
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

    let cose_sign1 = coset::CoseSign1::from_slice(&issuer_auth_cbor).map_err(|e| {
        MdocError::InvalidCoseSign1 {
            reason: e.to_string(),
        }
    })?;

    let mso_bytes = cose_sign1
        .payload
        .clone()
        .ok_or(MdocError::MissingCosePayload)?;

    let mso_val: Value = ciborium::de::from_reader(mso_bytes.as_slice())
        .map_err(|source| MdocError::CborDecode { source })?;

    let mut mso_map = into_map(mso_val, "MobileSecurityObject")?;

    let doc_type = take_text(&mut mso_map, "docType")?;

    let validity_val = take_entry(&mut mso_map, "validityInfo")?;
    let mut validity_map = into_map(validity_val, "validityInfo")?;

    let (_, signed_at) = take_tdate(&mut validity_map, "signed")?;
    let (valid_from_str, valid_from) = take_tdate(&mut validity_map, "validFrom")?;
    let (valid_until_str, valid_until) = take_tdate(&mut validity_map, "validUntil")?;

    // validity check (ISO 18013-5 §9.3.1)
    let now = OffsetDateTime::now_utc();
    if now < valid_from {
        return Err(MdocError::NotYetValid {
            valid_from: valid_from_str,
        });
    }
    if now > valid_until {
        return Err(MdocError::ExpiredCredential {
            valid_until: valid_until_str,
        });
    }

    let value_digests_val = take_entry(&mut mso_map, "valueDigests")?;
    let value_digests = parse_value_digests(value_digests_val)?;

    let device_key_info_val = take_entry(&mut mso_map, "deviceKeyInfo")?;
    let mut device_key_info_map = into_map(device_key_info_val, "deviceKeyInfo")?;
    let device_key_val = take_entry(&mut device_key_info_map, "deviceKey")?;
    let device_key =
        encode_value(&device_key_val).map_err(|reason| MdocError::CborEncode { reason })?;

    let name_spaces = parse_name_spaces(name_spaces_val)?;

    Ok(ParsedMdoc {
        doc_type,
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

/// Returns `(raw_rfc3339_str, parsed_datetime)` — raw string is used in error messages.
fn take_tdate(
    map: &mut Vec<(Value, Value)>,
    key: &'static str,
) -> Result<(String, OffsetDateTime)> {
    // ISO 18013-5 tdate = Tag(0, Text(rfc3339))
    let date_str = match take_entry(map, key)? {
        Value::Tag(0, inner) => match *inner {
            Value::Text(s) => s,
            _ => return Err(MdocError::UnexpectedCborType { field: key }),
        },
        // Accept bare text strings as a lenient fallback for test vectors.
        Value::Text(s) => s,
        _ => return Err(MdocError::UnexpectedCborType { field: key }),
    };

    let dt = OffsetDateTime::parse(&date_str, &Rfc3339)
        .map_err(|_| MdocError::UnexpectedCborType { field: key })?;

    Ok((date_str, dt))
}

fn parse_value_digests(val: Value) -> Result<HashMap<String, HashMap<u64, Vec<u8>>>> {
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
            ids.insert(digest_id, bytes);
        }

        out.insert(namespace, ids);
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

    // Preserve #6.24(bstr) bytes for Phase 2 digest check (ISO 18013-5 §9.3.1):
    // digest_i = SHA-256(bstr(#6.24(bstr .cbor IssuerSignedItem_i)))
    let tag24_val = Value::Tag(24, Box::new(Value::Bytes(inner_bytes.clone())));
    let raw_tag24_bytes =
        encode_value(&tag24_val).map_err(|reason| MdocError::CborEncode { reason })?;

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
