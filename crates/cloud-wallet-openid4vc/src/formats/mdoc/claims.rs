//! mdoc claims rendering for presentation and display.
//!
//! Extracts namespace/claim pairs from parsed mdoc CBOR into JSON for DCQL
//! matching and human-readable rendering. See ISO 18013-5 §8.3.2,
//! OID4VCI §4.3.2, HAIP §6.2.

use ciborium::Value as CborValue;
use serde::Serialize;
use serde_json::Value;

use super::parser::{IssuerSignedItem, ParsedMdoc};

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

    pub fn to_namespaced_json_with_display(
        &self,
        claim_descriptions: &[ClaimDescriptionRef<'_>],
        preferred_locales: &[String],
    ) -> Value {
        let mut root = serde_json::Map::new();
        for (namespace, items) in &self.mdoc.name_spaces {
            let mut ns_map = serde_json::Map::new();
            for item in items {
                let display_name = claim_descriptions
                    .iter()
                    .find(|desc| {
                        let elements = desc.path.elements();
                        elements.len() == 2
                            && matches!(&elements[0], ClaimPathElementRef::String(s) if s == namespace)
                            && matches!(&elements[1], ClaimPathElementRef::String(s) if s == &item.element_identifier)
                    })
                    .and_then(|desc| select_preferred_display(&desc.display, preferred_locales))
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

#[derive(Debug, Clone)]
pub struct ClaimDescriptionRef<'a> {
    pub path: ClaimPathRef<'a>,
    pub mandatory: bool,
    pub display: Vec<ClaimDisplayRef<'a>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClaimPathElementRef<'a> {
    String(&'a str),
    Index(u64),
}

#[derive(Debug, Clone)]
pub struct ClaimPathRef<'a> {
    elements: Vec<ClaimPathElementRef<'a>>,
}

impl<'a> ClaimPathRef<'a> {
    pub fn try_from_elements(elements: Vec<ClaimPathElementRef<'a>>) -> Option<Self> {
        if elements.is_empty() {
            return None;
        }
        Some(Self { elements })
    }

    pub fn elements(&self) -> &[ClaimPathElementRef<'a>] {
        &self.elements
    }
}

#[derive(Debug, Clone)]
pub struct ClaimDisplayRef<'a> {
    pub name: Option<&'a str>,
    pub locale: Option<&'a str>,
}

fn select_preferred_display<'a>(
    display: &'a [ClaimDisplayRef<'a>],
    preferred_locales: &[String],
) -> Option<&'a str> {
    if display.is_empty() {
        return None;
    }
    for prefix in preferred_locales {
        for entry in display {
            if let Some(locale) = entry.locale
                && locale.starts_with(prefix.as_str())
            {
                return entry.name;
            }
        }
    }
    display.first().and_then(|e| e.name)
}

fn claim_view_from_item(namespace: &str, item: &IssuerSignedItem) -> MdocClaimView {
    MdocClaimView {
        namespace: namespace.to_owned(),
        claim_name: item.element_identifier.clone(),
        value: classify_element_value(&item.element_value),
    }
}

fn classify_element_value(raw_cbor: &[u8]) -> ClaimValueView {
    let cbor_val = match ciborium::de::from_reader::<CborValue, _>(raw_cbor) {
        Ok(v) => v,
        Err(_) => {
            return ClaimValueView::Binary {
                media_type: None,
                size: raw_cbor.len(),
            };
        }
    };
    cbor_value_to_claim_view(&cbor_val, raw_cbor)
}

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
                    _ => continue,
                };
                map.insert(key, cbor_to_json(v));
            }
            ClaimValueView::Structured(Value::Object(map))
        }
        CborValue::Bytes(_) => ClaimValueView::Binary {
            media_type: None,
            size: raw_bytes.len(),
        },
        _ => ClaimValueView::Null,
    }
}

fn cbor_element_to_json(raw_cbor: &[u8]) -> Value {
    let cbor_val = match ciborium::de::from_reader::<CborValue, _>(raw_cbor) {
        Ok(v) => v,
        Err(_) => {
            return Value::Object(serde_json::Map::from_iter([
                ("type".to_owned(), Value::String("binary".to_owned())),
                ("size".to_owned(), Value::Number(raw_cbor.len().into())),
            ]));
        }
    };
    cbor_to_json(&cbor_val)
}

fn cbor_to_json(cbor_val: &CborValue) -> Value {
    match cbor_val {
        CborValue::Text(s) => Value::String(s.clone()),
        CborValue::Integer(i) => {
            let n: i128 = (*i).into();
            match i64::try_from(n) {
                Ok(v) => Value::Number(v.into()),
                Err(_) => Value::String(n.to_string()),
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
                    _ => continue,
                };
                map.insert(key, cbor_to_json(v));
            }
            Value::Object(map)
        }
        CborValue::Bytes(bytes) => Value::Object(serde_json::Map::from_iter([
            ("type".to_owned(), Value::String("binary".to_owned())),
            ("size".to_owned(), Value::Number(bytes.len().into())),
        ])),
        _ => Value::Null,
    }
}

impl ParsedMdoc {
    pub fn to_rendered_claims(&self) -> Value {
        MdocClaimExtractor::new(self).to_namespaced_json()
    }

    pub fn to_claim_views(&self) -> Vec<MdocClaimView> {
        MdocClaimExtractor::new(self).to_claim_views()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cbor(val: &CborValue) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(val, &mut buf).expect("CBOR encoding must succeed in tests");
        buf
    }

    fn build_item(
        digest_id: u64,
        random: Vec<u8>,
        name: &str,
        value: CborValue,
    ) -> IssuerSignedItem {
        let raw_item = CborValue::Map(vec![
            (
                CborValue::Text("digestID".into()),
                CborValue::Integer(digest_id.into()),
            ),
            (CborValue::Text("random".into()), CborValue::Bytes(random)),
            (
                CborValue::Text("elementIdentifier".into()),
                CborValue::Text(name.into()),
            ),
            (CborValue::Text("elementValue".into()), value.clone()),
        ]);
        let tag24 = CborValue::Tag(24, Box::new(CborValue::Bytes(cbor(&raw_item))));
        IssuerSignedItem {
            digest_id,
            element_identifier: name.to_owned(),
            element_value: cbor(&value),
            raw_tag24_bytes: cbor(&tag24),
        }
    }

    fn create_test_mdoc(items: Vec<IssuerSignedItem>) -> ParsedMdoc {
        ParsedMdoc {
            doc_type: "org.iso.18013.5.1.mDL".to_owned(),
            signed_at: time::OffsetDateTime::now_utc(),
            valid_from: time::OffsetDateTime::now_utc(),
            valid_until: time::OffsetDateTime::now_utc() + time::Duration::days(365),
            digest_algorithm: super::super::DigestAlgorithm::Sha256,
            value_digests: HashMap::new(),
            device_key: vec![],
            name_spaces: HashMap::from([("org.iso.18013.5.1".to_owned(), items)]),
            cose_sign1: coset::CoseSign1 {
                protected: coset::ProtectedHeader::default(),
                unprotected: coset::Header::default(),
                payload: Some(vec![]),
                signature: vec![0u8; 64],
            },
            raw_issuer_signed_bytes: vec![],
        }
    }

    #[test]
    fn cbor_to_json_handles_core_types_and_bytes() {
        assert_eq!(
            cbor_to_json(&CborValue::Text("hello".into())),
            Value::String("hello".into())
        );
        assert_eq!(
            cbor_to_json(&CborValue::Integer(42.into())),
            Value::Number(42.into())
        );
        assert_eq!(cbor_to_json(&CborValue::Bool(true)), Value::Bool(true));
        assert_eq!(cbor_to_json(&CborValue::Null), Value::Null);
        let b = cbor_to_json(&CborValue::Bytes(vec![0xDE, 0xAD]));
        assert_eq!(b["type"], "binary");
        assert_eq!(b["size"], 2);
    }

    #[test]
    fn rendered_claims_produces_namespaced_json() {
        let items = vec![
            build_item(
                0,
                vec![0u8; 16],
                "family_name",
                CborValue::Text("Doe".into()),
            ),
            build_item(
                1,
                vec![0u8; 16],
                "portrait",
                CborValue::Bytes(vec![0xAA; 64]),
            ),
        ];
        let json = create_test_mdoc(items).to_rendered_claims();
        let ns = json.get("org.iso.18013.5.1").expect("namespace");
        assert_eq!(ns["family_name"], "Doe");
        assert_eq!(ns["portrait"]["type"], "binary");
    }

    #[test]
    fn display_metadata_translates_and_falls_back() {
        let items = vec![
            build_item(
                0,
                vec![0u8; 16],
                "family_name",
                CborValue::Text("Doe".into()),
            ),
            build_item(
                1,
                vec![0u8; 16],
                "given_name",
                CborValue::Text("Jane".into()),
            ),
        ];
        let mdoc = create_test_mdoc(items);
        let descs = vec![
            ClaimDescriptionRef {
                path: ClaimPathRef::try_from_elements(vec![
                    ClaimPathElementRef::String("org.iso.18013.5.1"),
                    ClaimPathElementRef::String("family_name"),
                ])
                .unwrap(),
                mandatory: true,
                display: vec![
                    ClaimDisplayRef {
                        name: Some("Familienname"),
                        locale: Some("de"),
                    },
                    ClaimDisplayRef {
                        name: Some("Family Name"),
                        locale: Some("en"),
                    },
                ],
            },
            ClaimDescriptionRef {
                path: ClaimPathRef::try_from_elements(vec![
                    ClaimPathElementRef::String("org.iso.18013.5.1"),
                    ClaimPathElementRef::String("given_name"),
                ])
                .unwrap(),
                mandatory: true,
                display: vec![
                    ClaimDisplayRef {
                        name: Some("Vorname"),
                        locale: Some("de"),
                    },
                    ClaimDisplayRef {
                        name: Some("Given Name"),
                        locale: Some("en"),
                    },
                ],
            },
        ];
        let ext = MdocClaimExtractor::new(&mdoc);

        let en = ext.to_namespaced_json_with_display(&descs, &["en".into()]);
        assert_eq!(en["org.iso.18013.5.1"]["Family Name"], "Doe");
        assert_eq!(en["org.iso.18013.5.1"]["Given Name"], "Jane");

        let de = ext.to_namespaced_json_with_display(&descs, &["de".into()]);
        assert_eq!(de["org.iso.18013.5.1"]["Familienname"], "Doe");

        let no_desc =
            MdocClaimExtractor::new(&mdoc).to_namespaced_json_with_display(&[], &["en".into()]);
        assert_eq!(no_desc["org.iso.18013.5.1"]["family_name"], "Doe");
    }
}
