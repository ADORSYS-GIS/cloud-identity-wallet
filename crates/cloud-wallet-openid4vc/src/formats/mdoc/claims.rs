//! mdoc claims rendering for presentation and display.
//!
//! Extracts namespace/claim pairs from parsed mdoc CBOR into JSON for DCQL
//! matching and human-readable rendering. See ISO 18013-5 §8.3.2,
//! OID4VCI §4.3.2, HAIP §6.2.

use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value as CborValue;
use serde::Serialize;
use serde_json::Value;

use super::parser::{IssuerSignedItem, ParsedMdoc};
use crate::oid4vci::metadata::{ClaimDescription, ClaimDisplay};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MdocClaimView {
    pub namespace: String,
    pub claim_name: String,
    #[serde(flatten)]
    pub value: ClaimValueView,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "value_type", content = "value")]
pub enum ClaimValueView {
    #[serde(rename = "string")]
    String(String),
    #[serde(rename = "integer")]
    Integer(i128),
    #[serde(rename = "float")]
    Float(f64),
    #[serde(rename = "boolean")]
    Boolean(bool),
    #[serde(rename = "structured")]
    Structured(serde_json::Value),
    #[serde(rename = "binary")]
    Binary {
        media_type: Option<String>,
        size: usize,
    },
    #[serde(rename = "null")]
    Null,
}

#[derive(Debug, Clone)]
pub struct MdocClaimExtractor<'a> {
    mdoc: &'a ParsedMdoc,
}

impl<'a> MdocClaimExtractor<'a> {
    pub fn new(mdoc: &'a ParsedMdoc) -> Self {
        Self { mdoc }
    }

    pub fn to_claim_views(&self) -> Vec<MdocClaimView> {
        let mut views = Vec::new();
        for (namespace, items) in &self.mdoc.name_spaces {
            for item in items {
                views.push(claim_view_from_item(namespace, item));
            }
        }
        views
    }

    pub fn to_namespaced_json(&self) -> Value {
        let mut root = serde_json::Map::new();
        for (namespace, items) in &self.mdoc.name_spaces {
            let mut ns_map = serde_json::Map::new();
            for item in items {
                ns_map.insert(
                    item.element_identifier.clone(),
                    cbor_element_to_json(&item.element_value),
                );
            }
            root.insert(namespace.clone(), Value::Object(ns_map));
        }
        Value::Object(root)
    }

    /// Like [`to_namespaced_json`](Self::to_namespaced_json) but redacts binary
    /// CBOR values to `null`. Use this for API responses where binary claim
    /// payloads (e.g. portrait images) must not leak as base64 strings.
    pub fn to_safe_namespaced_json(&self) -> Value {
        let mut root = serde_json::Map::new();
        for (namespace, items) in &self.mdoc.name_spaces {
            let mut ns_map = serde_json::Map::new();
            for item in items {
                ns_map.insert(
                    item.element_identifier.clone(),
                    cbor_element_to_safe_json(&item.element_value),
                );
            }
            root.insert(namespace.clone(), Value::Object(ns_map));
        }
        Value::Object(root)
    }

    /// Produces namespaced JSON with claim display names resolved per
    /// `preferred_locales`, falling back to element identifiers.
    ///
    /// `claim_descriptions` come from `credential_configurations_supported[].credential_metadata.claims`
    /// per OID4VCI §4.3.2. For mdoc credentials, each `path` should be
    /// `["namespace", "claim_name"]` (e.g. `["org.iso.18013.5.1", "family_name"]`).
    pub fn to_namespaced_json_with_display(
        &self,
        claim_descriptions: &[ClaimDescription],
        preferred_locales: &[String],
    ) -> Value {
        use crate::core::claim_path_pointer::ClaimPathElement;
        let mut root = serde_json::Map::new();
        for (namespace, items) in &self.mdoc.name_spaces {
            let mut ns_map = serde_json::Map::new();
            for item in items {
                let display_name = claim_descriptions
                    .iter()
                    .find(|desc| {
                        let elements = desc.path.elements();
                        elements.len() == 2
                            && matches!(&elements[0], ClaimPathElement::String(s) if s == namespace)
                            && matches!(&elements[1], ClaimPathElement::String(s) if s == &item.element_identifier)
                    })
                    .and_then(|desc| {
                        desc.display.as_deref().and_then(|displays| {
                            select_preferred_display(displays, preferred_locales)
                        })
                    })
                    .unwrap_or(item.element_identifier.as_str());

                ns_map.insert(
                    display_name.to_owned(),
                    cbor_element_to_json(&item.element_value),
                );
            }
            root.insert(namespace.clone(), Value::Object(ns_map));
        }
        Value::Object(root)
    }
}

/// Selects the best matching display name from `displays` based on
/// `preferred_locales`, iterating locales in priority order.
fn select_preferred_display<'a>(
    displays: &'a [ClaimDisplay],
    preferred_locales: &[String],
) -> Option<&'a str> {
    for prefix in preferred_locales {
        for entry in displays {
            if let Some(locale) = &entry.locale
                && locale.starts_with(prefix.as_str())
            {
                return entry.name.as_deref();
            }
        }
    }
    displays.first().and_then(|e| e.name.as_deref())
}

/// Builds an `MdocClaimView` from a single `IssuerSignedItem`.
pub(crate) fn claim_view_from_item(namespace: &str, item: &IssuerSignedItem) -> MdocClaimView {
    MdocClaimView {
        namespace: namespace.to_owned(),
        claim_name: item.element_identifier.clone(),
        value: classify_element_value(&item.element_value),
    }
}

/// Classifies the raw CBOR `element_value` bytes into a `ClaimValueView`.
pub(crate) fn classify_element_value(raw_cbor: &[u8]) -> ClaimValueView {
    let cbor_val = match ciborium::de::from_reader::<CborValue, _>(raw_cbor) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(len = raw_cbor.len(), error = %e, "CBOR decode failed in classify_element_value; treating as opaque binary");
            return ClaimValueView::Binary {
                media_type: None,
                size: raw_cbor.len(),
            };
        }
    };
    cbor_value_to_claim_view(&cbor_val, raw_cbor)
}

#[allow(clippy::only_used_in_recursion)]
fn cbor_value_to_claim_view(cbor_val: &CborValue, raw_bytes: &[u8]) -> ClaimValueView {
    match cbor_val {
        CborValue::Text(s) => ClaimValueView::String(s.clone()),
        CborValue::Integer(i) => ClaimValueView::Integer((*i).into()),
        CborValue::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                ClaimValueView::Null
            } else {
                ClaimValueView::Float(*f)
            }
        }
        CborValue::Bool(b) => ClaimValueView::Boolean(*b),
        CborValue::Null => ClaimValueView::Null,
        CborValue::Tag(_, inner) => cbor_value_to_claim_view(inner, raw_bytes),
        CborValue::Array(items) => {
            let json_arr: Vec<Value> = items.iter().map(cbor_to_json).collect();
            ClaimValueView::Structured(Value::Array(json_arr))
        }
        CborValue::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    CborValue::Text(s) => s.clone(),
                    CborValue::Integer(i) => i128::from(*i).to_string(),
                    other => format!("{other:?}"),
                };
                map.insert(key, cbor_to_json(v));
            }
            ClaimValueView::Structured(Value::Object(map))
        }
        CborValue::Bytes(bytes) => ClaimValueView::Binary {
            media_type: None,
            size: bytes.len(),
        },
        _ => ClaimValueView::Null,
    }
}

/// Decodes raw CBOR element bytes and converts to JSON.
pub(crate) fn cbor_element_to_json(raw_cbor: &[u8]) -> Value {
    let cbor_val = match ciborium::de::from_reader::<CborValue, _>(raw_cbor) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(len = raw_cbor.len(), error = %e, "CBOR decode failed in cbor_element_to_json; falling back to base64url");
            return Value::String(Base64UrlUnpadded::encode_string(raw_cbor));
        }
    };
    cbor_to_json(&cbor_val)
}

/// Decodes raw CBOR element bytes and converts to JSON, redacting binary
/// values to `null`. Use for API response rendering where binary payloads
/// (e.g. portrait images) must not be exposed as base64 strings.
pub(crate) fn cbor_element_to_safe_json(raw_cbor: &[u8]) -> Value {
    let cbor_val = match ciborium::de::from_reader::<CborValue, _>(raw_cbor) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(len = raw_cbor.len(), error = %e, "CBOR decode failed in cbor_element_to_safe_json; treating as null");
            return Value::Null;
        }
    };
    cbor_to_safe_json(&cbor_val)
}

/// Converts a `ciborium::Value` tree into a `serde_json::Value`, redacting
/// binary values to `null`. Use for API response rendering where binary
/// payloads must not be exposed.
pub(crate) fn cbor_to_safe_json(cbor_val: &CborValue) -> Value {
    match cbor_val {
        CborValue::Text(s) => Value::String(s.clone()),
        CborValue::Integer(i) => {
            let n: i128 = (*i).into();
            match i64::try_from(n) {
                Ok(v) => Value::Number(v.into()),
                Err(_) => match u64::try_from(n) {
                    Ok(v) => Value::Number(serde_json::Number::from(v)),
                    Err(_) => Value::String(n.to_string()),
                },
            }
        }
        CborValue::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                Value::Null
            } else {
                serde_json::Number::from_f64(*f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            }
        }
        CborValue::Bool(b) => Value::Bool(*b),
        CborValue::Null => Value::Null,
        CborValue::Tag(_, inner) => cbor_to_safe_json(inner),
        CborValue::Array(items) => Value::Array(items.iter().map(cbor_to_safe_json).collect()),
        CborValue::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    CborValue::Text(s) => s.clone(),
                    CborValue::Integer(i) => i128::from(*i).to_string(),
                    other => format!("{other:?}"),
                };
                map.insert(key, cbor_to_safe_json(v));
            }
            Value::Object(map)
        }
        CborValue::Bytes(_) => Value::Null,
        _ => Value::Null,
    }
}

/// Converts a `ciborium::Value` tree into a `serde_json::Value`.
///
/// Used by the DCQL matching path (`to_rendered_claims`). Binary CBOR
/// values are encoded as base64url strings so that DCQL value constraints
/// (which use string equality) can match binary claims such as portrait.
pub(crate) fn cbor_to_json(cbor_val: &CborValue) -> Value {
    match cbor_val {
        CborValue::Text(s) => Value::String(s.clone()),
        CborValue::Integer(i) => {
            let n: i128 = (*i).into();
            match i64::try_from(n) {
                Ok(v) => Value::Number(v.into()),
                Err(_) => match u64::try_from(n) {
                    Ok(v) => Value::Number(serde_json::Number::from(v)),
                    Err(_) => Value::String(n.to_string()),
                },
            }
        }
        CborValue::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                Value::Null
            } else {
                serde_json::Number::from_f64(*f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            }
        }
        CborValue::Bool(b) => Value::Bool(*b),
        CborValue::Null => Value::Null,
        CborValue::Tag(_, inner) => cbor_to_json(inner),
        CborValue::Array(items) => Value::Array(items.iter().map(cbor_to_json).collect()),
        CborValue::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    CborValue::Text(s) => s.clone(),
                    CborValue::Integer(i) => i128::from(*i).to_string(),
                    other => format!("{other:?}"),
                };
                map.insert(key, cbor_to_json(v));
            }
            Value::Object(map)
        }
        CborValue::Bytes(bytes) => Value::String(Base64UrlUnpadded::encode_string(bytes)),
        _ => Value::Null,
    }
}

impl ParsedMdoc {
    pub fn to_rendered_claims(&self) -> Value {
        MdocClaimExtractor::new(self).to_namespaced_json()
    }

    /// Like [`to_rendered_claims`](Self::to_rendered_claims) but redacts binary
    /// CBOR values to `null`. Intended for API responses where binary payloads
    /// (e.g. portrait) must not be exposed as base64 strings; use
    /// [`to_claim_views`](Self::to_claim_views) for a typed view that includes
    /// `Binary { size, media_type }` metadata without the raw data.
    pub fn to_safe_claims(&self) -> Value {
        MdocClaimExtractor::new(self).to_safe_namespaced_json()
    }

    /// Like [`to_rendered_claims`](Self::to_rendered_claims) but translates
    /// claim names using display metadata and preferred locales.
    pub fn to_rendered_claims_with_display(
        &self,
        claim_descriptions: &[ClaimDescription],
        preferred_locales: &[String],
    ) -> Value {
        MdocClaimExtractor::new(self)
            .to_namespaced_json_with_display(claim_descriptions, preferred_locales)
    }

    pub fn to_claim_views(&self) -> Vec<MdocClaimView> {
        MdocClaimExtractor::new(self).to_claim_views()
    }
}
