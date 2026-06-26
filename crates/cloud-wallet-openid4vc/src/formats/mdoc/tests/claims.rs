use super::*;
use crate::core::claim_path_pointer::ClaimPathPointer;
use crate::formats::mdoc::claims::{
    ClaimValueView, MdocClaimExtractor, cbor_to_json, classify_element_value,
};
use crate::formats::mdoc::parser::IssuerSignedItem;
use crate::oid4vci::metadata::{ClaimDescription, ClaimDisplay};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::collections::HashMap;

fn build_item(digest_id: u64, random: Vec<u8>, name: &str, value: Value) -> IssuerSignedItem {
    let raw_item = Value::Map(vec![
        (
            Value::Text("digestID".into()),
            Value::Integer(digest_id.into()),
        ),
        (Value::Text("random".into()), Value::Bytes(random)),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text(name.into()),
        ),
        (Value::Text("elementValue".into()), value.clone()),
    ]);
    let tag24 = Value::Tag(24, Box::new(Value::Bytes(cbor(&raw_item))));
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
        signed_at: OffsetDateTime::now_utc(),
        valid_from: OffsetDateTime::now_utc(),
        valid_until: OffsetDateTime::now_utc() + time::Duration::days(365),
        digest_algorithm: DigestAlgorithm::Sha256,
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
        cbor_to_json(&Value::Text("hello".into())),
        serde_json::Value::String("hello".into())
    );
    assert_eq!(
        cbor_to_json(&Value::Integer(42.into())),
        serde_json::Value::Number(42.into())
    );
    assert_eq!(
        cbor_to_json(&Value::Bool(true)),
        serde_json::Value::Bool(true)
    );
    assert_eq!(cbor_to_json(&Value::Null), serde_json::Value::Null);
    let b = cbor_to_json(&Value::Bytes(vec![0xDE, 0xAD]));
    assert_eq!(
        b,
        serde_json::Value::String(Base64UrlUnpadded::encode_string(&[0xDE, 0xAD]))
    );
}

#[test]
fn cbor_to_json_preserves_large_integer_as_number() {
    let large = u64::MAX;
    assert_eq!(
        cbor_to_json(&Value::Integer(large.into())),
        serde_json::Value::Number(serde_json::Number::from(large))
    );
}

#[test]
fn cbor_to_json_negative_outside_i64_becomes_string() {
    let below_i64_min: i128 = i64::MIN as i128 - 1;
    let cbor_int = ciborium::value::Integer::try_from(below_i64_min).unwrap();
    let result = cbor_to_json(&Value::Integer(cbor_int));
    assert!(
        result.is_string(),
        "negative integer outside i64 range should become a string, got: {result:?}"
    );
    assert_eq!(result.as_str().unwrap(), &below_i64_min.to_string());
}

#[test]
fn cbor_to_json_large_positive_outside_i64_stays_number() {
    let above_i64_max: u64 = u64::MAX;
    let result = cbor_to_json(&Value::Integer(above_i64_max.into()));
    assert!(
        result.is_number(),
        "large positive integer representable as u64 should be a JSON number, got: {result:?}"
    );
}

#[test]
fn cbor_to_json_preserves_non_text_map_keys() {
    let map = Value::Map(vec![
        (Value::Text("key".into()), Value::Text("value".into())),
        (Value::Bool(true), Value::Integer(1.into())),
    ]);
    let json = cbor_to_json(&map);
    assert_eq!(json["key"], "value");
    assert!(
        json.get("Bool(true)").is_some(),
        "boolean key should be preserved via Debug fallback"
    );
    assert_eq!(json["Bool(true)"], 1);
}

#[test]
fn cbor_to_json_encodes_bytes_as_base64url() {
    let bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let json = cbor_to_json(&Value::Bytes(bytes.clone()));
    assert_eq!(
        json,
        serde_json::Value::String(Base64UrlUnpadded::encode_string(&bytes))
    );
}

#[test]
fn rendered_claims_produces_namespaced_json() {
    let items = vec![
        build_item(0, vec![0u8; 16], "family_name", Value::Text("Doe".into())),
        build_item(1, vec![0u8; 16], "portrait", Value::Bytes(vec![0xAA; 64])),
    ];
    let json = create_test_mdoc(items).to_rendered_claims();
    let ns = json.get("org.iso.18013.5.1").expect("namespace");
    assert_eq!(ns["family_name"], "Doe");
    assert!(
        ns["portrait"].is_string(),
        "portrait should be a base64url string, got: {:?}",
        ns["portrait"]
    );
    let portrait_b64 = ns["portrait"].as_str().unwrap();
    let expected = Base64UrlUnpadded::encode_string(&[0xAAu8; 64]);
    assert_eq!(portrait_b64, expected);
}

#[test]
fn claim_view_from_text_item() {
    let item = build_item(0, vec![0u8; 16], "given_name", Value::Text("Alice".into()));
    let mdoc = create_test_mdoc(vec![item]);
    let views = mdoc.to_claim_views();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].namespace, "org.iso.18013.5.1");
    assert_eq!(views[0].claim_name, "given_name");
    assert_eq!(views[0].value, ClaimValueView::String("Alice".to_owned()));
}

#[test]
fn claim_view_from_integer_item() {
    let item = build_item(0, vec![0u8; 16], "age", Value::Integer(42.into()));
    let mdoc = create_test_mdoc(vec![item]);
    let views = mdoc.to_claim_views();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].claim_name, "age");
    assert_eq!(views[0].value, ClaimValueView::Integer(42));
}

#[test]
fn claim_view_from_bytes_item() {
    let portrait_bytes = Value::Bytes(vec![0x89, 0x50, 0x4E, 0x47]);
    let item = build_item(0, vec![0u8; 16], "portrait", portrait_bytes);
    let mdoc = create_test_mdoc(vec![item]);
    let views = mdoc.to_claim_views();
    assert_eq!(views[0].claim_name, "portrait");
    assert_eq!(
        views[0].value,
        ClaimValueView::Binary {
            media_type: None,
            size: 4,
        }
    );
}

#[test]
fn claim_view_from_nested_map_item() {
    let nested = Value::Map(vec![
        (
            Value::Text("street".into()),
            Value::Text("123 Main St".into()),
        ),
        (Value::Text("city".into()), Value::Text("Anytown".into())),
    ]);
    let item = build_item(0, vec![0u8; 16], "address", nested);
    let mdoc = create_test_mdoc(vec![item]);
    let views = mdoc.to_claim_views();
    assert_eq!(views[0].claim_name, "address");
    if let ClaimValueView::Structured(serde_json::Value::Object(map)) = &views[0].value {
        assert_eq!(map["street"], "123 Main St");
        assert_eq!(map["city"], "Anytown");
    } else {
        panic!("expected structured object, got {:?}", views[0].value);
    }
}

#[test]
fn claim_view_from_tag_wrapped_item() {
    let tagged = Value::Tag(0, Box::new(Value::Text("2023-01-01T00:00:00Z".into())));
    let item = build_item(0, vec![0u8; 16], "date_of_birth", tagged);
    let mdoc = create_test_mdoc(vec![item]);
    let views = mdoc.to_claim_views();
    assert_eq!(views[0].claim_name, "date_of_birth");
    assert_eq!(
        views[0].value,
        ClaimValueView::String("2023-01-01T00:00:00Z".to_owned())
    );
}

#[test]
fn claim_view_from_tag1004_full_date() {
    let tagged = Value::Tag(1004, Box::new(Value::Text("1990-01-01".into())));
    let item = build_item(0, vec![0u8; 16], "birth_date", tagged);
    let mdoc = create_test_mdoc(vec![item]);
    let views = mdoc.to_claim_views();
    assert_eq!(views[0].claim_name, "birth_date");
    assert_eq!(
        views[0].value,
        ClaimValueView::String("1990-01-01".to_owned())
    );
}

#[test]
fn classify_element_value_handles_bool_and_null() {
    let bool_val = cbor(&Value::Bool(true));
    assert_eq!(
        classify_element_value(&bool_val),
        ClaimValueView::Boolean(true)
    );

    let null_val = cbor(&Value::Null);
    assert_eq!(classify_element_value(&null_val), ClaimValueView::Null);
}

#[test]
fn classify_element_value_handles_float_with_nan_and_inf() {
    let f = cbor(&Value::Float(42.5));
    if let ClaimValueView::Float(v) = classify_element_value(&f) {
        assert!((v - 42.5).abs() < 1e-10);
    } else {
        panic!("expected Float, got {:?}", classify_element_value(&f));
    }

    let nan_val = cbor(&Value::Float(f64::NAN));
    assert_eq!(classify_element_value(&nan_val), ClaimValueView::Null);

    let inf_val = cbor(&Value::Float(f64::INFINITY));
    assert_eq!(classify_element_value(&inf_val), ClaimValueView::Null);
}

#[test]
fn classify_element_value_preserves_non_text_map_keys() {
    let map = Value::Map(vec![
        (Value::Text("key".into()), Value::Text("val".into())),
        (Value::Bool(true), Value::Integer(1.into())),
    ]);
    let bytes = cbor(&map);
    let result = classify_element_value(&bytes);
    if let ClaimValueView::Structured(serde_json::Value::Object(obj)) = result {
        assert_eq!(obj["key"], "val");
        assert!(
            obj.get("Bool(true)").is_some(),
            "boolean key preserved via Debug fallback"
        );
        assert_eq!(obj["Bool(true)"], 1);
    } else {
        panic!("expected structured object, got {:?}", result);
    }
}

#[test]
fn display_metadata_translates_and_falls_back() {
    let items = vec![
        build_item(0, vec![0u8; 16], "family_name", Value::Text("Doe".into())),
        build_item(1, vec![0u8; 16], "given_name", Value::Text("Jane".into())),
    ];
    let mdoc = create_test_mdoc(items);
    let descs = vec![
        ClaimDescription {
            path: ClaimPathPointer::from_strings(["org.iso.18013.5.1", "family_name"]),
            mandatory: true,
            display: Some(vec![
                ClaimDisplay {
                    name: Some("Familienname".into()),
                    locale: Some("de".into()),
                },
                ClaimDisplay {
                    name: Some("Family Name".into()),
                    locale: Some("en".into()),
                },
            ]),
        },
        ClaimDescription {
            path: ClaimPathPointer::from_strings(["org.iso.18013.5.1", "given_name"]),
            mandatory: true,
            display: Some(vec![
                ClaimDisplay {
                    name: Some("Vorname".into()),
                    locale: Some("de".into()),
                },
                ClaimDisplay {
                    name: Some("Given Name".into()),
                    locale: Some("en".into()),
                },
            ]),
        },
    ];
    let ext = MdocClaimExtractor::new(&mdoc);

    let en = ext.to_namespaced_json_with_display(&descs, &["en".to_string()]);
    assert_eq!(en["org.iso.18013.5.1"]["Family Name"], "Doe");
    assert_eq!(en["org.iso.18013.5.1"]["Given Name"], "Jane");

    let de = ext.to_namespaced_json_with_display(&descs, &["de".to_string()]);
    assert_eq!(de["org.iso.18013.5.1"]["Familienname"], "Doe");

    let no_desc =
        MdocClaimExtractor::new(&mdoc).to_namespaced_json_with_display(&[], &["en".to_string()]);
    assert_eq!(no_desc["org.iso.18013.5.1"]["family_name"], "Doe");
}

#[test]
fn cbor_element_to_json_malformed_falls_back_to_base64url() {
    use crate::formats::mdoc::claims::cbor_element_to_json;
    let malformed = vec![0xFF, 0xFE, 0xFD];
    let result = cbor_element_to_json(&malformed);
    assert!(
        result.is_string(),
        "malformed CBOR should fall back to base64url string, got: {result:?}"
    );
    assert_eq!(
        result.as_str().unwrap(),
        Base64UrlUnpadded::encode_string(&malformed)
    );
}

#[test]
fn classify_element_value_malformed_falls_back_to_binary() {
    let malformed = vec![0xFF, 0xFE, 0xFD];
    let result = classify_element_value(&malformed);
    assert_eq!(
        result,
        ClaimValueView::Binary {
            media_type: None,
            size: 3,
        }
    );
}
