use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::digest::HashAlg;
use cloud_wallet_crypto::ecdsa::{Curve as EcdsaCurve, KeyPair as EcdsaKeyPair};
use cloud_wallet_crypto::jwk::{
    Algorithm as JwkAlgorithm, Jwk, JwkSet, KeyUse, Signing as JwkSigning,
};
use jsonwebtoken::{Algorithm as JwtAlgorithm, EncodingKey, Header, get_current_timestamp};
use serde_json::{Value, json};

use crate::formats::sd_jwt::verification::{verify_with_jwks, verify_with_x5c};

use super::*;

const EXAMPLE_1_SD_JWT: &str = include_str!("../../../test_data/sd_jwt/1_sd_jwt.txt");
const EXAMPLE_1_ISSUER_PAYLOAD: &str =
    include_str!("../../../test_data/sd_jwt/1_parsed_sd_jwt.json");
const EXAMPLE_1_PROCESSED_PAYLOAD: &str = include_str!("../../../test_data/sd_jwt/1_payload.json");
const EXAMPLE_2_SD_JWT: &str = include_str!("../../../test_data/sd_jwt/2_sd_jwt.txt");
const EXAMPLE_2_ISSUER_PAYLOAD: &str =
    include_str!("../../../test_data/sd_jwt/2_parsed_sd_jwt.json");
const EXAMPLE_2_PROCESSED_PAYLOAD: &str = include_str!("../../../test_data/sd_jwt/2_payload.json");

// Helper function to remove whitespace from a string
// This is useful for reading test data from files that have been formatted with whitespace
fn compact_fixture(value: &str) -> String {
    value.split_whitespace().collect()
}

// Helper function to parse JSON from a string
fn json_fixture(value: &str) -> Value {
    serde_json::from_str(value).expect("fixture JSON should parse")
}

// Encode the serialized JSON value to base64url
fn b64(value: Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("test JSON should serialize"))
}

// Create a compact JWT from header and claims
fn compact_jwt(header: Value, claims: Value) -> String {
    format!("{}.{}.sig", b64(header), b64(claims))
}

fn signed_sd_jwt() -> (String, JwkSet) {
    signed_sd_jwt_with_claims(json!({
        "iss": "https://issuer.example.com",
        "vct": "https://credentials.example.com/identity",
        "given_name": "Ada"
    }))
}

fn signed_sd_jwt_with_claims(claims: Value) -> (String, JwkSet) {
    let key_pair = EcdsaKeyPair::generate(EcdsaCurve::P256).expect("key generation should work");
    let mut jwk = Jwk::try_from(&key_pair).expect("JWK conversion should work");
    jwk.prm.kid = Some("issuer-key-1".to_string());
    jwk.prm.alg = Some(JwkAlgorithm::Signing(JwkSigning::Es256));
    jwk.prm.key_use = Some(KeyUse::Signing);

    let mut header = Header::new(JwtAlgorithm::ES256);
    header.typ = Some("dc+sd-jwt".to_string());
    header.kid = Some("issuer-key-1".to_string());

    let token = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_ec_der(key_pair.to_pkcs8_der()),
    )
    .expect("test JWT should sign");

    (format!("{token}~"), JwkSet { keys: vec![jwk] })
}

// Create a disclosure from a value
fn disclosure(value: Value) -> String {
    b64(value)
}

// Calculate the digest of a disclosure using SHA-256
fn disclosure_digest(disclosure: &str) -> String {
    disclosure_digest_with(disclosure, HashAlg::Sha256)
}

// Calculate the digest of a disclosure with a specific algorithm
fn disclosure_digest_with(disclosure: &str, algorithm: HashAlg) -> String {
    URL_SAFE_NO_PAD.encode(algorithm.hash(disclosure.as_bytes()).as_ref())
}

// Get the issuer claims as JSON
fn issuer_claims_as_json(sd_jwt: &SdJwt<'_>) -> Value {
    serde_json::to_value(sd_jwt.jwt().claims()).expect("issuer claims should serialize")
}

// Assert that the processed payload contains the expected values
fn assert_contains_expected_payload(processed: &Value, expected: &Value) {
    let expected = expected
        .as_object()
        .expect("expected payload should be object");
    for (claim_name, expected_value) in expected {
        assert_eq!(&processed[claim_name], expected_value, "claim {claim_name}");
    }
}

// Assert that the value does not contain SD metadata
fn assert_no_sd_metadata(value: &Value) {
    match value {
        Value::Object(object) => {
            assert!(!object.contains_key("_sd"));
            assert!(!object.contains_key("_sd_alg"));
            for value in object.values() {
                assert_no_sd_metadata(value);
            }
        }
        Value::Array(array) => {
            for value in array {
                assert_no_sd_metadata(value);
            }
        }
        _ => {}
    }
}

fn assert_no_rendering_metadata(value: &Value) {
    let object = value.as_object().expect("rendered claims should be object");
    for claim_name in [
        "iss",
        "sub",
        "exp",
        "nbf",
        "iat",
        "vct",
        "vct#integrity",
        "cnf",
        "status",
        "_sd",
        "_sd_alg",
    ] {
        assert!(
            !object.contains_key(claim_name),
            "{claim_name} should not be rendered"
        );
    }
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

/// Processes the SD-JWT VC section 2.3.1 example disclosures.
#[test]
fn processes_sd_jwt_vc_disclosures_1() {
    let raw = compact_fixture(EXAMPLE_1_SD_JWT);
    let expected_payload = json_fixture(EXAMPLE_1_PROCESSED_PAYLOAD);
    let sd_jwt = SdJwt::parse(&raw).expect("SD-JWT VC should parse");

    let processed = sd_jwt
        .to_disclosed_payload()
        .expect("disclosures should process");

    // the processed payload should contain the expected values
    assert_contains_expected_payload(&processed, &expected_payload);
    assert_eq!(processed["iss"], json!("https://example.com/issuer"));
    assert_eq!(processed["iat"], json!(1683000000));
    assert_eq!(processed["exp"], json!(1883000000));
    assert!(processed.get("cnf").is_some());
    // after processing, the payload should not contain any SD metadata
    assert_no_sd_metadata(&processed);
}

#[test]
fn parses_sd_jwt_with_no_disclosures() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity",
            "given_name": "Ada"
        }),
    );
    let raw = format!("{jwt}~");

    let sd_jwt = SdJwt::parse(&raw).expect("SD-JWT without disclosures should parse");

    assert!(sd_jwt.disclosures().is_empty());
    assert_eq!(sd_jwt.jwt().claims().properties["given_name"], json!("Ada"));
}

#[test]
fn rejects_missing_issuer_jwt() {
    let disclosed = disclosure(json!(["salt-1", "given_name", "Ada"]));
    let raw = format!("~{disclosed}~");

    assert!(matches!(SdJwt::parse(&raw), Err(Error::MissingIssuerJwt)));
}

#[test]
fn rejects_empty_disclosure_part() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity"
        }),
    );
    let disclosed = disclosure(json!(["salt-1", "given_name", "Ada"]));
    let raw = format!("{jwt}~~{disclosed}~");

    assert!(matches!(
        SdJwt::parse(&raw),
        Err(Error::InvalidDisclosure { index: 0, .. })
    ));
}

#[test]
fn rejects_invalid_disclosure_base64() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity"
        }),
    );
    let raw = format!("{jwt}~***~");

    assert!(matches!(
        SdJwt::parse(&raw),
        Err(Error::InvalidDisclosure { index: 0, .. })
    ));
}

#[test]
fn rejects_disclosure_with_invalid_json() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity"
        }),
    );
    let invalid_json = URL_SAFE_NO_PAD.encode(b"not json");
    let raw = format!("{jwt}~{invalid_json}~");

    assert!(matches!(
        SdJwt::parse(&raw),
        Err(Error::InvalidDisclosure { index: 0, .. })
    ));
}

#[test]
fn rejects_disclosure_with_wrong_array_length() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity"
        }),
    );

    for disclosed in [
        disclosure(json!(["salt-1"])),
        disclosure(json!(["salt-1", "given_name", "Ada", "extra"])),
    ] {
        let raw = format!("{jwt}~{disclosed}~");

        assert!(matches!(
            SdJwt::parse(&raw),
            Err(Error::InvalidDisclosure {
                index: 0,
                source: DisclosureError::InvalidShape
            })
        ));
    }
}

#[test]
fn rejects_issued_sd_jwt_without_trailing_separator() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity"
        }),
    );
    let disclosed = disclosure(json!(["salt-1", "given_name", "Ada"]));
    let raw = format!("{jwt}~{disclosed}");

    assert!(matches!(
        SdJwt::parse(&raw),
        Err(Error::MissingSdJwtTrailingSeparator)
    ));
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
fn processes_sd_jwt_vc_disclosures_recursively() {
    let raw = compact_fixture(EXAMPLE_2_SD_JWT);
    let expected_payload = json_fixture(EXAMPLE_2_PROCESSED_PAYLOAD);
    let sd_jwt = SdJwt::parse(&raw).expect("SD-JWT VC should parse");

    let processed = sd_jwt
        .to_disclosed_payload()
        .expect("disclosures should process");

    assert_contains_expected_payload(&processed, &expected_payload);
    assert_eq!(processed["address"], expected_payload["address"]);
    assert_eq!(
        processed["place_of_birth"],
        expected_payload["place_of_birth"]
    );
    assert_eq!(
        processed["age_equal_or_over"],
        expected_payload["age_equal_or_over"]
    );
    assert_no_sd_metadata(&processed);
}

#[test]
fn processes_array_element_disclosures() {
    let array_disclosure = disclosure(json!(["salt-1", "red"]));
    let digest = disclosure_digest(&array_disclosure);
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity",
            "favorite_colors": [{ "...": digest }, "blue"],
            "_sd_alg": "sha-256"
        }),
    );
    let raw = format!("{jwt}~{array_disclosure}~");

    let processed = SdJwt::parse(&raw)
        .expect("SD-JWT should parse")
        .to_disclosed_payload()
        .expect("array disclosure should process");

    assert_eq!(processed["favorite_colors"], json!(["red", "blue"]));
    assert_no_sd_metadata(&processed);
}

#[test]
fn rejects_unreferenced_disclosures() {
    let unreferenced = disclosure(json!(["salt-1", "given_name", "Ada"]));
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity",
            "_sd_alg": "sha-256"
        }),
    );
    let raw = format!("{jwt}~{unreferenced}~");

    assert!(matches!(
        SdJwt::parse(&raw).and_then(|sd_jwt| sd_jwt.to_disclosed_payload()),
        Err(Error::DisclosureProcessing {
            reason: ProcessingError::UnreferencedDisclosure(_)
        })
    ));
}

#[test]
fn rejects_duplicate_embedded_digest_values() {
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity",
            "_sd": ["digest-1", "digest-1"],
            "_sd_alg": "sha-256"
        }),
    );
    let raw = format!("{jwt}~");

    assert!(matches!(
        SdJwt::parse(&raw).and_then(|sd_jwt| sd_jwt.to_disclosed_payload()),
        Err(Error::DisclosureProcessing {
            reason: ProcessingError::DuplicateEmbeddedDigest(digest)
        }) if digest == "digest-1"
    ));
}

#[test]
fn rejects_duplicate_disclosure_digest_values() {
    let disclosed = disclosure(json!(["salt-1", "given_name", "Ada"]));
    let digest = disclosure_digest(&disclosed);
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity",
            "_sd": [digest],
            "_sd_alg": "sha-256"
        }),
    );
    let raw = format!("{jwt}~{disclosed}~{disclosed}~");

    assert!(matches!(
        SdJwt::parse(&raw).and_then(|sd_jwt| sd_jwt.to_disclosed_payload()),
        Err(Error::DisclosureProcessing {
            reason: ProcessingError::DuplicateDigest(_)
        })
    ));
}

#[test]
fn rejects_reserved_disclosed_claim_name() {
    let disclosed = disclosure(json!(["salt-1", "_sd", "nope"]));
    let digest = disclosure_digest(&disclosed);
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity",
            "_sd": [digest],
            "_sd_alg": "sha-256"
        }),
    );
    let raw = format!("{jwt}~{disclosed}~");

    assert!(matches!(
        SdJwt::parse(&raw).and_then(|sd_jwt| sd_jwt.to_disclosed_payload()),
        Err(Error::DisclosureProcessing {
            reason: ProcessingError::ReservedClaimName(name)
        }) if name == "_sd"
    ));
}

#[test]
fn rejects_duplicate_disclosed_claim_name_in_same_object() {
    let first = disclosure(json!(["salt-1", "given_name", "Ada"]));
    let second = disclosure(json!(["salt-2", "given_name", "Grace"]));
    let first_digest = disclosure_digest(&first);
    let second_digest = disclosure_digest(&second);
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity",
            "_sd": [first_digest, second_digest],
            "_sd_alg": "sha-256"
        }),
    );
    let raw = format!("{jwt}~{first}~{second}~");

    assert!(matches!(
        SdJwt::parse(&raw).and_then(|sd_jwt| sd_jwt.to_disclosed_payload()),
        Err(Error::DisclosureProcessing {
            reason: ProcessingError::DuplicateClaimName(name)
        }) if name == "given_name"
    ));
}

#[test]
fn supports_iana_named_sha2_and_sha3_sd_alg_values() {
    let cases = [
        ("sha-256", HashAlg::Sha256),
        ("sha-384", HashAlg::Sha384),
        ("sha-512", HashAlg::Sha512),
        ("sha3-256", HashAlg::Sha3_256),
        ("sha3-384", HashAlg::Sha3_384),
        ("sha3-512", HashAlg::Sha3_512),
    ];

    for (sd_alg, algorithm) in cases {
        let disclosed = disclosure(json!(["salt-1", "given_name", "Ada"]));
        let digest = disclosure_digest_with(&disclosed, algorithm);
        let jwt = compact_jwt(
            json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
            json!({
                "iss": "https://issuer.example.com",
                "vct": "https://credentials.example.com/identity",
                "_sd": [digest],
                "_sd_alg": sd_alg
            }),
        );
        let raw = format!("{jwt}~{disclosed}~");

        let processed = SdJwt::parse(&raw)
            .and_then(|sd_jwt| sd_jwt.to_disclosed_payload())
            .unwrap_or_else(|err| panic!("{sd_alg} should process: {err}"));

        assert_eq!(processed["given_name"], json!("Ada"), "{sd_alg}");
    }
}

#[test]
fn renders_disclosed_claims_without_protocol_metadata() {
    let disclosed = disclosure(json!(["salt-1", "given_name", "Ada"]));
    let digest = disclosure_digest(&disclosed);
    let jwt = compact_jwt(
        json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
        json!({
            "iss": "https://issuer.example.com",
            "sub": "subject-1",
            "exp": 1883000000,
            "nbf": 1682990000,
            "iat": 1683000000,
            "vct": "https://credentials.example.com/identity",
            "vct#integrity": "sha256-placeholder",
            "cnf": { "kid": "holder-key-1" },
            "status": {
                "status_list": {
                    "idx": 42,
                    "uri": "https://issuer.example.com/statuslists/1",
                }
            },
            "_sd": [digest],
            "_sd_alg": "sha-256",
            "family_name": "Lovelace"
        }),
    );
    let raw = format!("{jwt}~{disclosed}~");

    let rendered = SdJwt::parse(&raw).unwrap().to_rendered_claims().unwrap();

    assert_eq!(
        rendered,
        json!({
            "given_name": "Ada",
            "family_name": "Lovelace"
        })
    );
    assert_no_rendering_metadata(&rendered);
}

#[test]
fn verifies_issuer_signature_with_trusted_jwks() {
    let (raw, jwks) = signed_sd_jwt();
    let sd_jwt = SdJwt::parse(&raw).expect("signed SD-JWT should parse");

    let algorithm = verify_with_jwks(&sd_jwt, &jwks).expect("signature should verify");

    assert_eq!(algorithm, JwtAlgorithm::ES256);
}

#[test]
fn rejects_issuer_signature_when_trusted_jwk_algorithm_differs() {
    let (raw, mut jwks) = signed_sd_jwt();
    jwks.keys[0].prm.alg = Some(JwkAlgorithm::Signing(JwkSigning::Rs256));
    let sd_jwt = SdJwt::parse(&raw).expect("signed SD-JWT should parse");

    assert!(matches!(
        verify_with_jwks(&sd_jwt, &jwks),
        Err(VerificationError::InvalidKey { .. })
    ));
}

#[test]
fn rejects_tampered_issuer_signature() {
    let (raw, jwks) = signed_sd_jwt();
    let token = raw.strip_suffix('~').expect("issued SD-JWT has trailing ~");
    let mut parts = token.split('.').collect::<Vec<_>>();
    parts[2] = "AA";
    let raw = format!("{}.{}.{}~", parts[0], parts[1], parts[2]);
    let sd_jwt = SdJwt::parse(&raw).expect("tampered SD-JWT should still parse");

    assert!(matches!(
        verify_with_jwks(&sd_jwt, &jwks),
        Err(VerificationError::Signature { .. })
    ));
}

#[test]
fn rejects_expired_jwt_claims() {
    let now = get_current_timestamp();
    let (raw, jwks) = signed_sd_jwt_with_claims(json!({
        "iss": "https://issuer.example.com",
        "vct": "https://credentials.example.com/identity",
        "exp": now.saturating_sub(120),
    }));
    let sd_jwt = SdJwt::parse(&raw).expect("signed SD-JWT should parse");

    let result = verify_with_jwks(&sd_jwt, &jwks);
    // Expired JWT should fail signature verification
    assert!(matches!(result, Err(VerificationError::Signature(_))));
}

#[test]
fn rejects_not_yet_valid_jwt_claims() {
    let now = get_current_timestamp();
    let (raw, jwks) = signed_sd_jwt_with_claims(json!({
        "iss": "https://issuer.example.com",
        "vct": "https://credentials.example.com/identity",
        "nbf": now + 120,
    }));
    let sd_jwt = SdJwt::parse(&raw).expect("signed SD-JWT should parse");

    let result = verify_with_jwks(&sd_jwt, &jwks);
    // Future nbf (Not Before) should fail signature verification
    assert!(matches!(result, Err(VerificationError::Signature(_))));
}

#[test]
fn rejects_invalid_x5c_certificate_chain_before_signature_verification() {
    let jwt = compact_jwt(
        json!({
            "alg": "ES256",
            "typ": "dc+sd-jwt",
            "x5c": ["not-base64!"]
        }),
        json!({
            "iss": "https://issuer.example.com",
            "vct": "https://credentials.example.com/identity"
        }),
    );
    let raw = format!("{jwt}~");
    let sd_jwt = SdJwt::parse(&raw).expect("SD-JWT with x5c header should parse");

    assert!(matches!(
        verify_with_x5c(&sd_jwt),
        Err(VerificationError::X5c { .. })
    ));
}
