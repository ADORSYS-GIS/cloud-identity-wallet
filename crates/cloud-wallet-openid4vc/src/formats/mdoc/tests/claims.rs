use super::*;
use crate::formats::mdoc::claims::{
    ClaimDescriptionRef, ClaimDisplayRef, ClaimPathElementRef, ClaimPathRef, MdocClaimExtractor,
    cbor_to_json,
};
use crate::formats::mdoc::parser::IssuerSignedItem;
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
    assert_eq!(b["type"], "binary");
    assert_eq!(b["size"], 2);
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
    assert_eq!(ns["portrait"]["type"], "binary");
}

#[test]
fn display_metadata_translates_and_falls_back() {
    let items = vec![
        build_item(0, vec![0u8; 16], "family_name", Value::Text("Doe".into())),
        build_item(1, vec![0u8; 16], "given_name", Value::Text("Jane".into())),
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
