use cloud_wallet_crypto::ecdh::EcdhPublicKey;
use cloud_wallet_crypto::jwe::{
    ContentEncryptionAlgorithm, JweEncryptKey, JweHeader, KeyManagementAlgorithm,
    encrypt as jwe_encrypt,
};
use cloud_wallet_crypto::jwk::{Algorithm, Jwk, Key, KeyManagement, KeyUse, Operations};
use cloud_wallet_crypto::rsa::oaep::EncryptingKey as RsaEncryptingKey;
use reqwest_middleware::ClientWithMiddleware;
use url::Url;

use crate::oid4vp::{
    authorization::{AuthorizationResponse, DirectPostJwtResponse, DirectPostResponse},
    response_mode::error::{DirectPostError, JarmEncryptError},
};

/// Encrypts an Authorization Response as an unsigned JWE per OID4VP §8.3.
///
/// The payload is the §8.1 response parameters serialised as top-level JSON members
/// (`vp_token`, `state`, `error`, etc.). No JARM claims (`iss`/`aud`/`exp`) are added.
///
/// Header construction follows the §8.3 normative example:
/// - `alg`: derived from `encryption_key.prm.alg` (MUST be present per spec)
/// - `enc`: supplied by the caller from `encrypted_response_enc_values_supported` (default A128GCM)
/// - `kid`: copied from `encryption_key.prm.kid` when present
/// - `typ`: omitted (absent in the §8.3 normative example header)
/// - `epk`: set automatically by the JWE encrypt primitive for ECDH-ES variants
///
/// # Encryption-only scope
///
/// §8.3 mandates **unsigned** encrypted JWTs for `direct_post.jwt`. The
/// sign-then-encrypt (nested JWT) flow defined in the JARM spec is out of scope for
/// this implementation; if it is required in future it should be a separate function
/// (`sign_and_encrypt_authorization_response`) so this API remains stable.
///
/// # Replay protection
///
/// The JWE payload carries no freshness claims (`iat`, `exp`, nonce). Anti-replay
/// relies on the `state` value echoed by the Verifier. Callers **must** include
/// `state` in the `AuthorizationResponse` (via `.with_state(...)`) to enable the
/// Verifier to detect replayed responses.
///
/// # Algorithm negotiation
///
/// This function does not check `encryption_key`/`enc` against the Verifier's
/// `encrypted_response_alg_values_supported` / `encrypted_response_enc_values_supported`
/// (`VerifierMetadata`). It only enforces that the JWE `alg` matches `encryption_key`'s
/// own `alg` parameter, per §8.3. Callers **must** select `encryption_key` and `enc` from
/// the Verifier's advertised metadata themselves; passing a key or `enc` the Verifier never
/// advertised will not be rejected here and may fail only when the Verifier processes the
/// response.
///
/// # Errors
/// [`JarmEncryptError::MissingKeyAlgorithm`] if the JWK has no `alg` field.
/// [`JarmEncryptError::UnsupportedAlgorithm`] if the `alg` is not a supported JWE alg,
/// the JWK `use` is `sig`, or `key_ops` excludes the required operation.
/// [`JarmEncryptError::KeyConstruction`] if the JWK cannot be converted to a crypto key
/// or contains private key material.
/// [`JarmEncryptError::SerializationError`] if the response cannot be serialised to JSON.
/// [`JarmEncryptError::EncryptionFailed`] if the JWE primitive fails.
pub fn encrypt_authorization_response(
    response: &AuthorizationResponse,
    encryption_key: &Jwk,
    enc: ContentEncryptionAlgorithm,
) -> Result<DirectPostJwtResponse, JarmEncryptError> {
    // RFC 7517 §4.2: a key declared for signing must not be used for encryption.
    if let Some(KeyUse::Signing) = &encryption_key.prm.key_use {
        return Err(JarmEncryptError::UnsupportedAlgorithm(
            "JWK has 'use': 'sig' and cannot be used for JWE encryption".to_string(),
        ));
    }

    // RFC 7517 §4.3: if key_ops is present, the required operation must be declared.
    // ECDH-ES derives a shared secret (DeriveKey / DeriveBits); RSA-OAEP encrypts (Encrypt).
    if let Some(ops) = &encryption_key.prm.ops {
        let has_required_op = match &encryption_key.key {
            Key::Rsa(_) => ops.contains(&Operations::Encrypt),
            Key::Ec(_) | Key::Okp(_) => {
                ops.contains(&Operations::DeriveKey) || ops.contains(&Operations::DeriveBits)
            }
            // Oct/unknown → will fail at the unsupported-algorithm check below.
            _ => true,
        };
        if !has_required_op {
            return Err(JarmEncryptError::UnsupportedAlgorithm(
                "JWK 'key_ops' does not permit the required operation for JWE encryption"
                    .to_string(),
            ));
        }
    }

    // §8.3: "The JWE alg algorithm used MUST be equal to the alg value of the chosen jwk."
    let alg = match &encryption_key.prm.alg {
        None => return Err(JarmEncryptError::MissingKeyAlgorithm),
        Some(Algorithm::KeyManagement(km)) => jwk_km_to_jwe_alg(km)?,
        Some(other) => {
            return Err(JarmEncryptError::UnsupportedAlgorithm(format!(
                "algorithm '{other}' is not a JWE key-management algorithm"
            )));
        }
    };

    // §8.3: "If the selected public key contains a kid parameter, the JWE MUST include
    // the same value in the kid JWE Header Parameter."
    let kid = encryption_key.prm.kid.clone();

    let mut header = JweHeader::new(alg, enc);
    header.kid = kid;

    // §8.3: "the payload MUST include the contents of the response as defined in
    // Section 8.1 as top-level JSON members" — vp_token, state, error, etc.
    let plaintext = serde_json::to_vec(response)
        .map_err(|e| JarmEncryptError::SerializationError(e.to_string()))?;

    let compact = match &encryption_key.key {
        Key::Rsa(rsa) => {
            if rsa.prv.is_some() {
                return Err(JarmEncryptError::KeyConstruction(
                    "RSA JWK must not contain private key material; only public keys are accepted \
                     for JWE encryption"
                        .to_string(),
                ));
            }
            let rsa_key = RsaEncryptingKey::try_from(encryption_key)
                .map_err(|e| JarmEncryptError::KeyConstruction(e.to_string()))?;
            jwe_encrypt(header, &plaintext, JweEncryptKey::Rsa(&rsa_key))
                .map_err(|e| JarmEncryptError::EncryptionFailed(e.to_string()))?
        }
        Key::Ec(ec) => {
            if ec.d.is_some() {
                return Err(JarmEncryptError::KeyConstruction(
                    "EC JWK must not contain private key material; only public keys are accepted \
                     for JWE encryption"
                        .to_string(),
                ));
            }
            let ecdh_pub = EcdhPublicKey::try_from(encryption_key)
                .map_err(|e| JarmEncryptError::KeyConstruction(e.to_string()))?;
            jwe_encrypt(header, &plaintext, JweEncryptKey::Ecdh(&ecdh_pub))
                .map_err(|e| JarmEncryptError::EncryptionFailed(e.to_string()))?
        }
        Key::Okp(okp) => {
            if okp.d.is_some() {
                return Err(JarmEncryptError::KeyConstruction(
                    "OKP JWK must not contain private key material; only public keys are accepted \
                     for JWE encryption"
                        .to_string(),
                ));
            }
            let ecdh_pub = EcdhPublicKey::try_from(encryption_key)
                .map_err(|e| JarmEncryptError::KeyConstruction(e.to_string()))?;
            jwe_encrypt(header, &plaintext, JweEncryptKey::Ecdh(&ecdh_pub))
                .map_err(|e| JarmEncryptError::EncryptionFailed(e.to_string()))?
        }
        // Oct (symmetric) keys and any future non-exhaustive Key variants.
        _ => {
            return Err(JarmEncryptError::UnsupportedAlgorithm(
                "symmetric (oct) keys are not supported for JWE key management".to_string(),
            ));
        }
    };

    DirectPostJwtResponse::new(compact).map_err(JarmEncryptError::EncryptionFailed)
}

/// Sends an Authorization Response via `direct_post.jwt` to the Verifier's `response_uri`.
///
/// Per OID4VP §8.3.1, the Wallet POSTs `response=<JWE>` as
/// `application/x-www-form-urlencoded`. The JWE is an unsigned, encrypted JWT
/// whose payload carries the §8.1 Authorization Response parameters.
///
/// # Note on encryption failure
/// If `encrypt_authorization_response` fails, this function returns an error to the
/// caller rather than falling back to an unencrypted §8.2 response. The §8.3.1 MAY
/// fallback is out of scope for this implementation.
///
/// # Security
/// - `response_uri` is validated to use HTTPS.
/// - `response_uri` is validated against `expected_response_uri` from the
///   original Authorization Request to prevent SSRF.
pub async fn send_direct_post_jwt(
    http_client: &ClientWithMiddleware,
    response_uri: &Url,
    expected_response_uri: &Url,
    response: &AuthorizationResponse,
    encryption_key: &Jwk,
    enc: ContentEncryptionAlgorithm,
) -> Result<DirectPostResponse, DirectPostError> {
    super::validate_response_uri(response_uri, expected_response_uri)?;

    let jwt_response = encrypt_authorization_response(response, encryption_key, enc)?;

    execute_direct_post_jwt(http_client, response_uri, &jwt_response).await
}

async fn execute_direct_post_jwt(
    http_client: &ClientWithMiddleware,
    response_uri: &Url,
    jwt_response: &DirectPostJwtResponse,
) -> Result<DirectPostResponse, DirectPostError> {
    let http_response = http_client
        .post(response_uri.as_str())
        .form(jwt_response)
        .send()
        .await
        .map_err(|e| DirectPostError::HttpRequestFailed(e.to_string()))?;

    super::parse_verifier_response(http_response).await
}

/// Maps a JWK `KeyManagement` algorithm to the corresponding JWE `KeyManagementAlgorithm`.
///
/// Delegates to `cloud_wallet_crypto`'s `TryFrom<KeyManagement> for KeyManagementAlgorithm`,
/// which is implemented inside that crate with an exhaustive match (no wildcard arm) over
/// `KeyManagement`. Both enums are `#[non_exhaustive]` at this crate boundary, so matching on
/// either one here would silently swallow any algorithm `cloud_wallet_crypto` adds in the
/// future; delegating means that addition fails to compile in the crypto crate until it is
/// explicitly routed here, rather than silently being unreachable from this JARM layer.
fn jwk_km_to_jwe_alg(km: &KeyManagement) -> Result<KeyManagementAlgorithm, JarmEncryptError> {
    KeyManagementAlgorithm::try_from(*km).map_err(|_| {
        JarmEncryptError::UnsupportedAlgorithm(format!(
            "algorithm '{km}' is not supported for JWE key management"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64ct::{Base64UrlUnpadded, Encoding};
    use cloud_wallet_crypto::ecdh::{EcdhCurve, StaticEcdhKey};
    use cloud_wallet_crypto::jwe::{JweDecryptKey, decrypt as jwe_decrypt};
    use cloud_wallet_crypto::jwk::{
        Algorithm, B64, Curve, Ec, Jwk, Key, KeyManagement, KeyUse, Okp, OkpCurve, Operations,
        Parameters,
    };
    use cloud_wallet_crypto::rsa::RsaKeySize;
    use cloud_wallet_crypto::rsa::oaep::DecryptingKey as RsaDecryptingKey;
    use reqwest_middleware::ClientBuilder;
    use serde_json::json;
    use url::Url;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::oid4vp::authorization::{AuthorizationResponse, Presentation, VpToken};

    fn test_http_client() -> ClientWithMiddleware {
        let inner = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("valid client");
        ClientBuilder::new(inner).build()
    }

    fn sample_response() -> AuthorizationResponse {
        let mut entries = BTreeMap::new();
        entries.insert(
            "pid".to_string(),
            vec![Presentation::String(
                "eyJhbGciOiJFUzI1NiJ9.example".to_string(),
            )],
        );
        AuthorizationResponse::new(VpToken::new(entries).unwrap()).with_state("state-abc")
    }

    fn ecdh_p256_jwk_with_alg(static_key: &StaticEcdhKey) -> Jwk {
        let mut buf = vec![0u8; EcdhCurve::P256.public_key_len()];
        let pub_bytes = static_key.public_key_bytes(&mut buf).unwrap();
        // SEC1 uncompressed: 04 || x(32) || y(32)
        let x = B64::new(&pub_bytes[1..33]);
        let y = B64::new(&pub_bytes[33..65]);

        let mut prm = Parameters::default();
        prm.alg = Some(Algorithm::KeyManagement(KeyManagement::EcdhEs));
        prm.kid = Some("p256-key-1".to_string());

        Jwk {
            key: Key::Ec(Ec {
                crv: Curve::P256,
                x,
                y,
                d: None,
            }),
            prm,
        }
    }

    fn x25519_jwk_with_alg(static_key: &StaticEcdhKey) -> Jwk {
        let mut buf = vec![0u8; EcdhCurve::X25519.public_key_len()];
        let pub_bytes = static_key.public_key_bytes(&mut buf).unwrap();
        let x = B64::new(pub_bytes);

        let mut prm = Parameters::default();
        prm.alg = Some(Algorithm::KeyManagement(KeyManagement::EcdhEs));
        prm.kid = Some("x25519-key-1".to_string());

        Jwk {
            key: Key::Okp(Okp {
                crv: OkpCurve::X25519,
                x,
                d: None,
            }),
            prm,
        }
    }

    fn rsa_jwk_from_keypair(
        key_pair: &cloud_wallet_crypto::rsa::KeyPair,
        alg: KeyManagement,
    ) -> Jwk {
        let mut jwk = Jwk::try_from(key_pair).expect("RSA KeyPair to JWK");
        jwk.prm.alg = Some(Algorithm::KeyManagement(alg));
        jwk.prm.kid = Some("rsa-key-1".to_string());
        jwk
    }

    fn decode_jwe_header(compact: &str) -> serde_json::Value {
        let b64 = compact.split('.').next().expect("compact JWE has 5 parts");
        let bytes = Base64UrlUnpadded::decode_vec(b64).expect("valid base64url header");
        serde_json::from_slice(&bytes).expect("valid JSON header")
    }

    // ── Roundtrip tests ─────────────────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip_ecdh_es_p256() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let jwk = ecdh_p256_jwk_with_alg(&static_key);
        let response = sample_response();

        let jwt_response =
            encrypt_authorization_response(&response, &jwk, ContentEncryptionAlgorithm::A128Gcm)
                .unwrap();

        let plaintext =
            jwe_decrypt(jwt_response.response(), JweDecryptKey::Ecdh(&static_key)).unwrap();

        // Compare semantically via JSON Value (AuthorizationResponse is Serialize-only).
        let expected: serde_json::Value = serde_json::to_value(&response).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_ecdh_es_x25519() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::X25519).unwrap();
        let jwk = x25519_jwk_with_alg(&static_key);
        let response = sample_response();

        let jwt_response =
            encrypt_authorization_response(&response, &jwk, ContentEncryptionAlgorithm::A256Gcm)
                .unwrap();

        let plaintext =
            jwe_decrypt(jwt_response.response(), JweDecryptKey::Ecdh(&static_key)).unwrap();

        let expected: serde_json::Value = serde_json::to_value(&response).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_rsa_oaep256() {
        let key_pair = cloud_wallet_crypto::rsa::KeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        let jwk = rsa_jwk_from_keypair(&key_pair, KeyManagement::RsaOaep256);
        let response = sample_response();

        let jwt_response =
            encrypt_authorization_response(&response, &jwk, ContentEncryptionAlgorithm::A128Gcm)
                .unwrap();

        let mut pkcs8_buf = vec![0u8; 4096];
        let pkcs8_der = key_pair.to_pkcs8_der(&mut pkcs8_buf).unwrap();
        let dec_key = RsaDecryptingKey::from_pkcs8_der(pkcs8_der).unwrap();

        let plaintext = jwe_decrypt(jwt_response.response(), JweDecryptKey::Rsa(&dec_key)).unwrap();

        let expected: serde_json::Value = serde_json::to_value(&response).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered, expected);
    }

    /// RSA-OAEP-384 exercises the SHA-384 OAEP path and the two-byte `der_length`
    /// code path in the SPKI DER constructor for a 2048-bit key.
    #[test]
    fn encrypt_decrypt_roundtrip_rsa_oaep384() {
        let key_pair = cloud_wallet_crypto::rsa::KeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        let jwk = rsa_jwk_from_keypair(&key_pair, KeyManagement::RsaOaep384);
        let response = sample_response();

        let jwt_response =
            encrypt_authorization_response(&response, &jwk, ContentEncryptionAlgorithm::A256Gcm)
                .unwrap();

        let mut pkcs8_buf = vec![0u8; 4096];
        let pkcs8_der = key_pair.to_pkcs8_der(&mut pkcs8_buf).unwrap();
        let dec_key = RsaDecryptingKey::from_pkcs8_der(pkcs8_der).unwrap();

        let plaintext = jwe_decrypt(jwt_response.response(), JweDecryptKey::Rsa(&dec_key)).unwrap();

        let expected: serde_json::Value = serde_json::to_value(&response).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered, expected);
    }

    /// ECDH-ES+A128KW exercises the key-wrap path, which produces a non-empty
    /// encrypted-key segment (unlike direct ECDH-ES which produces an empty one).
    #[test]
    fn encrypt_decrypt_roundtrip_ecdh_es_a128kw() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut buf = vec![0u8; EcdhCurve::P256.public_key_len()];
        let pub_bytes = static_key.public_key_bytes(&mut buf).unwrap();
        let x = B64::new(&pub_bytes[1..33]);
        let y = B64::new(&pub_bytes[33..65]);

        let mut prm = Parameters::default();
        prm.alg = Some(Algorithm::KeyManagement(KeyManagement::EcdhEsA128Kw));
        prm.kid = Some("p256-a128kw-key".to_string());

        let jwk = Jwk {
            key: Key::Ec(Ec {
                crv: Curve::P256,
                x,
                y,
                d: None,
            }),
            prm,
        };
        let response = sample_response();

        let jwt_response =
            encrypt_authorization_response(&response, &jwk, ContentEncryptionAlgorithm::A128Gcm)
                .unwrap();

        // KW mode must produce a non-empty encrypted-key segment (part 2 of the compact JWE).
        let parts: Vec<&str> = jwt_response.response().split('.').collect();
        assert!(
            !parts[1].is_empty(),
            "ECDH-ES+A128KW must produce a non-empty encrypted-key segment"
        );

        let plaintext =
            jwe_decrypt(jwt_response.response(), JweDecryptKey::Ecdh(&static_key)).unwrap();

        let expected: serde_json::Value = serde_json::to_value(&response).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(recovered, expected);
    }

    // ── Header parameter tests ───────────────────────────────────────────────

    #[test]
    fn kid_is_included_in_jwe_header_when_present_in_jwk() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let jwk = ecdh_p256_jwk_with_alg(&static_key); // kid = "p256-key-1"

        let jwt_response = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap();

        let header = decode_jwe_header(jwt_response.response());

        assert_eq!(header["kid"], json!("p256-key-1"));
        assert_eq!(header["alg"], json!("ECDH-ES"));
        assert_eq!(header["enc"], json!("A128GCM"));
        // OID4VP §8.3 normative header example has no `typ`
        assert!(header.get("typ").is_none());
    }

    #[test]
    fn kid_is_absent_from_jwe_header_when_not_in_jwk() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut jwk = ecdh_p256_jwk_with_alg(&static_key);
        jwk.prm.kid = None;

        let jwt_response = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap();

        let header = decode_jwe_header(jwt_response.response());
        assert!(header.get("kid").is_none());
    }

    // ── Error path tests ─────────────────────────────────────────────────────

    #[test]
    fn missing_alg_parameter_returns_error() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut jwk = ecdh_p256_jwk_with_alg(&static_key);
        jwk.prm.alg = None;

        let err = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap_err();

        assert_eq!(err, JarmEncryptError::MissingKeyAlgorithm);
    }

    #[test]
    fn unsupported_alg_returns_error() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut jwk = ecdh_p256_jwk_with_alg(&static_key);
        // RsaOaep (no hash suffix) has no KeyManagementAlgorithm counterpart.
        jwk.prm.alg = Some(Algorithm::KeyManagement(KeyManagement::RsaOaep));

        let err = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap_err();

        assert!(matches!(err, JarmEncryptError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn symmetric_key_returns_unsupported_algorithm_error() {
        use cloud_wallet_crypto::jwk::Oct;
        use cloud_wallet_crypto::secret::Secret;

        let mut prm = Parameters::default();
        prm.alg = Some(Algorithm::KeyManagement(KeyManagement::A256Kw));

        let jwk = Jwk {
            key: Key::Oct(Oct {
                k: Secret::new(b"supersecretkey01supersecretkey01".to_vec()),
            }),
            prm,
        };

        let err = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap_err();

        assert!(matches!(err, JarmEncryptError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn signing_key_use_is_rejected() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut jwk = ecdh_p256_jwk_with_alg(&static_key);
        jwk.prm.key_use = Some(KeyUse::Signing);

        let err = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap_err();

        assert!(
            matches!(&err, JarmEncryptError::UnsupportedAlgorithm(msg) if msg.contains("sig")),
            "expected UnsupportedAlgorithm mentioning 'sig', got: {err:?}"
        );
    }

    #[test]
    fn key_ops_without_derive_key_rejects_ecdh_key() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut jwk = ecdh_p256_jwk_with_alg(&static_key);
        // Only Sign is declared — DeriveKey / DeriveBits are absent.
        let mut ops = std::collections::BTreeSet::new();
        ops.insert(Operations::Sign);
        jwk.prm.ops = Some(ops);

        let err = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap_err();

        assert!(
            matches!(&err, JarmEncryptError::UnsupportedAlgorithm(msg) if msg.contains("key_ops")),
            "expected UnsupportedAlgorithm mentioning 'key_ops', got: {err:?}"
        );
    }

    #[test]
    fn key_ops_with_derive_key_accepts_ecdh_key() {
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut jwk = ecdh_p256_jwk_with_alg(&static_key);
        let mut ops = std::collections::BTreeSet::new();
        ops.insert(Operations::DeriveKey);
        jwk.prm.ops = Some(ops);

        // Should succeed — DeriveKey satisfies the ECDH requirement.
        assert!(
            encrypt_authorization_response(
                &sample_response(),
                &jwk,
                ContentEncryptionAlgorithm::A128Gcm
            )
            .is_ok()
        );
    }

    #[test]
    fn ec_jwk_with_private_key_is_rejected() {
        use cloud_wallet_crypto::secret::Secret;

        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut jwk = ecdh_p256_jwk_with_alg(&static_key);
        // Inject a dummy private key value.
        if let Key::Ec(ref mut ec) = jwk.key {
            ec.d = Some(Secret::new(vec![0u8; 32]));
        }

        let err = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap_err();

        assert!(
            matches!(&err, JarmEncryptError::KeyConstruction(msg) if msg.contains("private")),
            "expected KeyConstruction mentioning 'private', got: {err:?}"
        );
    }

    #[test]
    fn okp_jwk_with_private_key_is_rejected() {
        use cloud_wallet_crypto::secret::Secret;

        let static_key = StaticEcdhKey::generate(EcdhCurve::X25519).unwrap();
        let mut jwk = x25519_jwk_with_alg(&static_key);
        if let Key::Okp(ref mut okp) = jwk.key {
            okp.d = Some(Secret::new(vec![0u8; 32]));
        }

        let err = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap_err();

        assert!(
            matches!(&err, JarmEncryptError::KeyConstruction(msg) if msg.contains("private")),
            "expected KeyConstruction mentioning 'private', got: {err:?}"
        );
    }

    #[test]
    fn rsa_jwk_with_private_key_is_rejected() {
        use cloud_wallet_crypto::jwk::RsaPrivate;
        use cloud_wallet_crypto::secret::Secret;

        // Build a minimal RSA public JWK and inject a fake private exponent.
        let key_pair = cloud_wallet_crypto::rsa::KeyPair::generate(RsaKeySize::Rsa2048).unwrap();
        let mut jwk = rsa_jwk_from_keypair(&key_pair, KeyManagement::RsaOaep256);
        if let Key::Rsa(ref mut rsa) = jwk.key {
            rsa.prv = Some(RsaPrivate {
                d: Secret::new(vec![0u8; 256]),
                opt: None,
            });
        }

        let err = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap_err();

        assert!(
            matches!(&err, JarmEncryptError::KeyConstruction(msg) if msg.contains("private")),
            "expected KeyConstruction mentioning 'private', got: {err:?}"
        );
    }

    // ── HTTP layer tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn send_direct_post_jwt_posts_response_field_as_form_body() {
        let mock_server = MockServer::start().await;
        let uri = Url::parse(&format!("{}/response", mock_server.uri())).unwrap();

        Mock::given(method("POST"))
            .and(path("/response"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string_contains("response="))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&mock_server)
            .await;

        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let jwk = ecdh_p256_jwk_with_alg(&static_key);

        // wiremock URI is http:// so call execute_direct_post_jwt directly
        // to bypass the HTTPS check (which is tested separately below).
        let jwt_response = encrypt_authorization_response(
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .unwrap();
        let client = test_http_client();
        let result = execute_direct_post_jwt(&client, &uri, &jwt_response)
            .await
            .expect("success");

        assert!(result.redirect_uri.is_none());
    }

    #[tokio::test]
    async fn send_direct_post_jwt_rejects_http_url() {
        let response_uri = Url::parse("http://example.com/response").unwrap();
        let expected = response_uri.clone();
        let client = test_http_client();
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let jwk = ecdh_p256_jwk_with_alg(&static_key);

        let err = send_direct_post_jwt(
            &client,
            &response_uri,
            &expected,
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .await
        .unwrap_err();

        assert_eq!(err, DirectPostError::HttpsRequired);
    }

    #[tokio::test]
    async fn send_direct_post_jwt_rejects_uri_mismatch() {
        let response_uri = Url::parse("https://verifier.example.com/response").unwrap();
        let expected = Url::parse("https://other.example.com/response").unwrap();
        let client = test_http_client();
        let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
        let jwk = ecdh_p256_jwk_with_alg(&static_key);

        let err = send_direct_post_jwt(
            &client,
            &response_uri,
            &expected,
            &sample_response(),
            &jwk,
            ContentEncryptionAlgorithm::A128Gcm,
        )
        .await
        .unwrap_err();

        assert_eq!(err, DirectPostError::UriMismatch);
    }
}
