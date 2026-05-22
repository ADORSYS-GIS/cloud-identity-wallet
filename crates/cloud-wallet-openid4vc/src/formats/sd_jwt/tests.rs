use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use super::*;

const EXAMPLE_1_SD_JWT: &str = include_str!("../../../test_data/sd_jwt/1_sd_jwt.txt");
const EXAMPLE_1_ISSUER_PAYLOAD: &str =
    include_str!("../../../test_data/sd_jwt/1_parsed_sd_jwt.json");
const EXAMPLE_1_PROCESSED_PAYLOAD: &str = include_str!("../../../test_data/sd_jwt/1_payload.json");
const EXAMPLE_2_SD_JWT: &str = include_str!("../../../test_data/sd_jwt/2_sd_jwt.txt");
const EXAMPLE_2_ISSUER_PAYLOAD: &str =
    include_str!("../../../test_data/sd_jwt/2_parsed_sd_jwt.json");
const EXAMPLE_2_PROCESSED_PAYLOAD: &str = include_str!("../../../test_data/sd_jwt/2_payload.json");

fn compact_fixture(value: &str) -> String {
    value.split_whitespace().collect()
}

fn json_fixture(value: &str) -> Value {
    serde_json::from_str(value).expect("fixture JSON should parse")
}

fn b64(value: Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("test JSON should serialize"))
}

fn compact_jwt(header: Value, claims: Value) -> String {
    format!("{}.{}.sig", b64(header), b64(claims))
}

fn issuer_claims_as_json(sd_jwt: &SdJwt<'_>) -> Value {
    serde_json::to_value(sd_jwt.jwt().claims()).expect("issuer claims should serialize")
}

/// Parses the SD-JWT VC section 2.3.1 example.
#[test]
fn parses_sd_jwt_vc_section_2_3_1_example() {
    let raw = compact_fixture(EXAMPLE_1_SD_JWT);
    let expected_issuer_payload = json_fixture(EXAMPLE_1_ISSUER_PAYLOAD);
    let expected_processed_payload = json_fixture(EXAMPLE_1_PROCESSED_PAYLOAD);

    let sd_jwt = SdJwt::parse(&raw).expect("SD-JWT VC should parse");

    assert_eq!(sd_jwt.jwt().header().typ.as_deref(), Some("dc+sd-jwt"));
    assert_eq!(issuer_claims_as_json(&sd_jwt), expected_issuer_payload);
    assert!(!sd_jwt.has_key_binding());

    let disclosures = sd_jwt.disclosures();
    assert_eq!(disclosures.len(), 9);

    let expected_disclosures = [
        ("given_name", json!("John")),
        ("family_name", json!("Doe")),
        ("email", json!("johndoe@example.com")),
        ("phone_number", json!("+1-202-555-0101")),
        ("address", expected_processed_payload["address"].clone()),
        ("birthdate", json!("1940-01-01")),
        ("is_over_18", json!(true)),
        ("is_over_21", json!(true)),
        ("is_over_65", json!(true)),
    ];

    for (disclosure, (claim_name, claim_value)) in disclosures.iter().zip(expected_disclosures) {
        assert!(disclosure.is_object_element());
        assert_eq!(disclosure.claim_name.as_deref(), Some(claim_name));
        assert_eq!(disclosure.claim_value, claim_value);
    }

    assert_eq!(
        sd_jwt.jwt().claims().cnf,
        Some(CnfClaim::Jwk(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        })))
    );
}

/// Parses the SD-JWT VC appendix B.1 example.
#[test]
fn parses_sd_jwt_vc_appendix_b_1_example() {
    let raw = compact_fixture(EXAMPLE_2_SD_JWT);
    let expected_issuer_payload = json_fixture(EXAMPLE_2_ISSUER_PAYLOAD);
    let expected_processed_payload = json_fixture(EXAMPLE_2_PROCESSED_PAYLOAD);

    let sd_jwt = SdJwt::parse(&raw).expect("SD-JWT VC should parse");

    assert_eq!(sd_jwt.jwt().header().typ.as_deref(), Some("dc+sd-jwt"));
    assert_eq!(issuer_claims_as_json(&sd_jwt), expected_issuer_payload);
    assert!(!sd_jwt.has_key_binding());

    let disclosures = sd_jwt.disclosures();
    assert_eq!(disclosures.len(), 28);

    assert_eq!(disclosures[0].claim_name.as_deref(), Some("given_name"));
    assert_eq!(
        disclosures[0].claim_value,
        expected_processed_payload["given_name"]
    );
    assert_eq!(disclosures[1].claim_name.as_deref(), Some("family_name"));
    assert_eq!(
        disclosures[1].claim_value,
        expected_processed_payload["family_name"]
    );
    assert_eq!(disclosures[7].claim_name.as_deref(), Some("address"));
    assert_eq!(
        disclosures[7].claim_value["_sd"].as_array().map(Vec::len),
        Some(4)
    );
    assert_eq!(disclosures[8].claim_name.as_deref(), Some("nationalities"));
    assert_eq!(
        disclosures[8].claim_value,
        expected_processed_payload["nationalities"]
    );
    assert_eq!(
        disclosures[13].claim_name.as_deref(),
        Some("place_of_birth")
    );
    assert_eq!(
        disclosures[13].claim_value["_sd"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(disclosures[17].claim_name.as_deref(), Some("18"));
    assert_eq!(disclosures[17].claim_value, json!(true));
    assert_eq!(
        disclosures[20].claim_name.as_deref(),
        Some("age_equal_or_over")
    );
    assert_eq!(
        disclosures[20].claim_value["_sd"].as_array().map(Vec::len),
        Some(6)
    );
    assert_eq!(disclosures[23].claim_name.as_deref(), Some("portrait"));
    assert_eq!(
        disclosures[23].claim_value,
        expected_processed_payload["portrait"]
    );
    assert_eq!(
        disclosures[27].claim_name.as_deref(),
        Some("issuing_country")
    );
    assert_eq!(
        disclosures[27].claim_value,
        expected_processed_payload["issuing_country"]
    );
}

#[test]
fn decodes_typed_status_list_claim() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity",
            "status": {
                "status_list": {
                    "idx": 42,
                    "uri": "https://issuer.example.com/statuslists/1",
                }
            }
        }),
    );
    let raw = format!("{jwt}~");

    let sd_jwt = SdJwt::parse(&raw).expect("SD-JWT status claim should parse");
    let status_list = sd_jwt
        .jwt()
        .claims()
        .status
        .as_ref()
        .and_then(|status| status.status_list.as_ref())
        .expect("status_list should be decoded");

    assert_eq!(status_list.idx, 42);
    assert_eq!(
        status_list.uri.as_str(),
        "https://issuer.example.com/statuslists/1"
    );
}

#[test]
fn parses_key_binding_jwt_with_concrete_claims() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity"
        }),
    );
    let kb_jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "kb+jwt" }),
        json!({
            "iat": 1777056848,
            "aud": "https://example.com/verifier",
            "nonce": "1234567890",
            "sd_hash": "hwQH4nICSf_-be6IA6RD0GCeT4txntVNc153T0MTVgk"
        }),
    );
    let raw = format!("{jwt}~{kb_jwt}");

    let sd_jwt = SdJwt::parse(&raw).expect("SD-JWT+KB should parse");
    let key_binding = sd_jwt
        .key_binding()
        .expect("key binding JWT should be present");

    assert_eq!(key_binding.jwt().header().typ.as_deref(), Some("kb+jwt"));
    assert_eq!(key_binding.claims().iat, 1777056848);
    assert_eq!(key_binding.claims().aud, "https://example.com/verifier");
    assert_eq!(key_binding.claims().nonce, "1234567890");
    assert_eq!(
        key_binding.claims().sd_hash,
        "hwQH4nICSf_-be6IA6RD0GCeT4txntVNc153T0MTVgk"
    );
}

#[test]
fn rejects_key_binding_jwt_with_wrong_typ() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity"
        }),
    );
    let kb_jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "JWT" }),
        json!({
            "iat": 1777056848,
            "aud": "https://example.com/verifier",
            "nonce": "1234567890",
            "sd_hash": "hwQH4nICSf_-be6IA6RD0GCeT4txntVNc153T0MTVgk"
        }),
    );
    let raw = format!("{jwt}~{kb_jwt}");

    assert!(matches!(
        SdJwt::parse(&raw),
        Err(Error::InvalidJwtProfile { component, .. }) if component == "Key Binding JWT"
    ));
}
