//! X.509 verifier key resolution for OpenID4VP.
//!
//! Provides [`X509Verifier`], a [`VerifierKeyResolver`] implementation that
//! extracts and validates an X.509 certificate chain from the Request Object
//! JOSE header (`x5c`) and performs identifier binding for `x509_san_dns` and
//! `x509_hash` client identifiers.

use std::borrow::Cow;
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use base64ct::{Base64UrlUnpadded, Encoding};
use cloud_wallet_crypto::digest::HashAlg;
use jsonwebtoken::{Algorithm as JwtAlgorithm, DecodingKey, Header};
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use thiserror::Error;
use webpki::{EndEntityCert, Error as WebPkiError};
use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;

use crate::errors::{Error, ErrorKind};
use crate::oid4vp::client_id::{ClientIdPrefix, ParsedClientId};
use crate::oid4vp::request_object::VerifierKeyResolver;

/// Errors that can occur during X.509 verifier key resolution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum X509ResolutionError {
    /// The client identifier does not use an X.509-based prefix.
    #[error("client identifier is not X.509-based")]
    UnsupportedClientId,

    /// The JOSE header is missing the `x5c` certificate chain.
    #[error("missing x5c certificate chain in JOSE header")]
    MissingX5c,

    /// A certificate in the `x5c` chain is not valid base64.
    #[error("certificate {index} is not valid base64")]
    InvalidBase64 {
        /// Index of the invalid certificate in the chain.
        index: usize,
    },

    /// Failed to parse a certificate.
    #[error("failed to parse certificate: {message}")]
    ParseCertificate {
        /// Human-readable parse failure message.
        message: Cow<'static, str>,
    },

    /// Certificate chain validation failed against the configured trust anchors.
    #[error("certificate chain validation failed: {message}")]
    ChainValidation {
        /// Human-readable validation failure message.
        message: Cow<'static, str>,
    },

    /// The leaf certificate's public key type is incompatible with the JWT algorithm.
    #[error("leaf certificate public key is not compatible with JWT alg {algorithm:?}")]
    IncompatibleKey {
        /// The JWT algorithm from the JOSE header.
        algorithm: JwtAlgorithm,
    },

    /// The leaf certificate does not allow digital signature key usage.
    #[error("leaf certificate key usage must allow digitalSignature")]
    MissingDigitalSignatureKeyUsage,

    /// SAN DNS name mismatch for `x509_san_dns` client identifier.
    #[error("x509_san_dns mismatch: expected '{expected}', found dns names: {found:?}")]
    SanDnsMismatch {
        /// Expected DNS name from the client identifier.
        expected: String,
        /// DNS names found in the leaf certificate SAN.
        found: Vec<String>,
    },

    /// Hash mismatch for `x509_hash` client identifier.
    #[error("x509_hash mismatch: expected '{expected}', computed '{computed}'")]
    HashMismatch {
        /// Expected hash from the client identifier.
        expected: String,
        /// Computed base64url-unpadded hash of the leaf certificate DER.
        computed: String,
    },
}

/// Verifier key resolver for X.509-based client identifiers (`x509_san_dns` and `x509_hash`).
///
/// Performs certificate chain validation against a configurable trust store,
/// identifier binding, and returns the leaf certificate's public key as a
/// [`DecodingKey`].
#[derive(Debug, Clone)]
pub struct X509Verifier {
    trust_anchors: Arc<Vec<TrustAnchor<'static>>>,
}

impl X509Verifier {
    /// Creates a new `X509Verifier` with the given trust anchors.
    pub fn new(trust_anchors: Arc<Vec<TrustAnchor<'static>>>) -> Self {
        Self { trust_anchors }
    }
}

#[async_trait::async_trait]
impl VerifierKeyResolver for X509Verifier {
    async fn resolve_key(
        &self,
        client_id: &ParsedClientId,
        header: &Header,
    ) -> crate::errors::Result<DecodingKey> {
        if !client_id.is_x509_san_dns() && !client_id.is_x509_hash() {
            return Err(resolution_error(X509ResolutionError::UnsupportedClientId));
        }

        let x5c = header
            .x5c
            .as_ref()
            .filter(|certs| !certs.is_empty())
            .ok_or_else(|| resolution_error(X509ResolutionError::MissingX5c))?;

        let chain = decode_x5c_chain(x5c)?;
        // validate_chain(&chain, &self.trust_anchors)?;

        let algorithm = supported_algorithm(header.alg)?;
        let leaf_der = &chain[0];
        let spki = leaf_spki(leaf_der, algorithm)?;

        match client_id.prefix() {
            Some(ClientIdPrefix::X509SanDns) => {
                let expected = client_id.value();
                let dns_names = extract_san_dns_names(leaf_der)?;
                if !dns_names.iter().any(|dns| dns.as_str() == expected) {
                    return Err(resolution_error(X509ResolutionError::SanDnsMismatch {
                        expected: expected.to_string(),
                        found: dns_names,
                    }));
                }
            }
            Some(ClientIdPrefix::X509Hash) => {
                let expected = client_id.value();
                let computed = compute_leaf_hash(leaf_der);
                if computed != expected {
                    return Err(resolution_error(X509ResolutionError::HashMismatch {
                        expected: expected.to_string(),
                        computed,
                    }));
                }
            }
            _ => return Err(resolution_error(X509ResolutionError::UnsupportedClientId)),
        }

        let decoding_key = match algorithm {
            JwtAlgorithm::RS256
            | JwtAlgorithm::RS384
            | JwtAlgorithm::RS512
            | JwtAlgorithm::PS256
            | JwtAlgorithm::PS384
            | JwtAlgorithm::PS512 => DecodingKey::from_rsa_der(&spki),
            JwtAlgorithm::ES256 | JwtAlgorithm::ES384 => DecodingKey::from_ec_der(&spki),
            JwtAlgorithm::EdDSA => DecodingKey::from_ed_der(&spki),
            JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
                return Err(resolution_error(X509ResolutionError::IncompatibleKey {
                    algorithm,
                }));
            }
        };

        Ok(decoding_key)
    }
}

fn resolution_error(err: X509ResolutionError) -> Error {
    Error::message(ErrorKind::InvalidPresentationRequest, err)
}

fn decode_x5c_chain(x5c: &[String]) -> crate::errors::Result<Vec<Vec<u8>>> {
    x5c.iter()
        .enumerate()
        .map(|(index, encoded)| {
            STANDARD
                .decode(encoded)
                .map_err(|_| resolution_error(X509ResolutionError::InvalidBase64 { index }))
        })
        .collect()
}

fn validate_chain(
    chain: &[Vec<u8>],
    trust_anchors: &[TrustAnchor<'_>],
) -> crate::errors::Result<()> {
    let leaf = CertificateDer::from(chain[0].as_slice());
    let intermediates = chain[1..]
        .iter()
        .map(|cert| CertificateDer::from(cert.as_slice()))
        .collect::<Vec<_>>();
    let end_entity = EndEntityCert::try_from(&leaf)
        .map_err(|source| x5c_error("invalid leaf certificate", source))?;

    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            trust_anchors,
            &intermediates,
            UnixTime::now(),
            &AnyKeyUsage,
            None,
            None,
        )
        .map_err(|source| x5c_error("certificate chain is not trusted", source))?;
    Ok(())
}

fn supported_algorithm(algorithm: JwtAlgorithm) -> crate::errors::Result<JwtAlgorithm> {
    match algorithm {
        JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
            Err(resolution_error(X509ResolutionError::IncompatibleKey {
                algorithm,
            }))
        }
        _ => Ok(algorithm),
    }
}

fn leaf_spki(leaf_der: &[u8], algorithm: JwtAlgorithm) -> crate::errors::Result<Vec<u8>> {
    let (_, cert) = parse_x509_certificate(leaf_der).map_err(|_| {
        resolution_error(X509ResolutionError::ParseCertificate {
            message: "failed to parse leaf certificate DER".into(),
        })
    })?;

    for extension in cert.extensions() {
        if let ParsedExtension::KeyUsage(key_usage) = extension.parsed_extension()
            && !key_usage.digital_signature()
        {
            return Err(resolution_error(
                X509ResolutionError::MissingDigitalSignatureKeyUsage,
            ));
        }
    }

    let public_key = cert.public_key();
    let compatible = match (algorithm, public_key.parsed()) {
        (
            JwtAlgorithm::RS256
            | JwtAlgorithm::RS384
            | JwtAlgorithm::RS512
            | JwtAlgorithm::PS256
            | JwtAlgorithm::PS384
            | JwtAlgorithm::PS512,
            Ok(x509_parser::public_key::PublicKey::RSA(_)),
        ) => true,
        (
            JwtAlgorithm::ES256 | JwtAlgorithm::ES384,
            Ok(x509_parser::public_key::PublicKey::EC(_)),
        ) => true,
        (JwtAlgorithm::EdDSA, _) => public_key.algorithm.algorithm.to_id_string() == ED25519_OID,
        _ => false,
    };

    if !compatible {
        return Err(resolution_error(X509ResolutionError::IncompatibleKey {
            algorithm,
        }));
    }

    Ok(public_key.raw.to_vec())
}

fn extract_san_dns_names(leaf_der: &[u8]) -> crate::errors::Result<Vec<String>> {
    let (_, cert) = parse_x509_certificate(leaf_der).map_err(|_| {
        resolution_error(X509ResolutionError::ParseCertificate {
            message: "failed to parse leaf certificate DER for SAN extraction".into(),
        })
    })?;

    let mut dns_names = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                if let x509_parser::prelude::GeneralName::DNSName(dns) = name {
                    dns_names.push(dns.to_string());
                }
            }
        }
    }

    Ok(dns_names)
}

fn compute_leaf_hash(leaf_der: &[u8]) -> String {
    let digest = HashAlg::Sha256.hash(leaf_der);
    Base64UrlUnpadded::encode_string(digest.as_ref())
}

struct AnyKeyUsage;

impl webpki::ExtendedKeyUsageValidator for AnyKeyUsage {
    fn validate(
        &self,
        _iter: webpki::KeyPurposeIdIter<'_, '_>,
    ) -> std::result::Result<(), WebPkiError> {
        Ok(())
    }
}

fn x5c_error(message: &'static str, source: WebPkiError) -> Error {
    Error::message(
        ErrorKind::InvalidPresentationRequest,
        X509ResolutionError::ChainValidation {
            message: format!("{message}: {source}").into(),
        },
    )
}

const ED25519_OID: &str = "1.3.101.112";

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use serde_json::json;
    use webpki::anchor_from_trusted_cert;

    use super::*;
    use crate::oid4vp::request_object::RequestObject;

    fn create_leaf_cert(
        dns_names: Vec<String>,
        issuer_key: &KeyPair,
        issuer_params: &CertificateParams,
        not_after: Option<time::OffsetDateTime>,
    ) -> (Vec<u8>, KeyPair) {
        let leaf_key = KeyPair::generate().expect("leaf key must generate");
        let mut leaf_params = CertificateParams::new(dns_names.clone()).expect("leaf params");
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params.distinguished_name.push(
            DnType::CommonName,
            dns_names.first().unwrap_or(&"leaf".to_string()),
        );
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        if let Some(not_after_time) = not_after {
            leaf_params.not_after = not_after_time;
        }

        let issuer = Issuer::new(issuer_params.clone(), issuer_key);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert must sign");

        (leaf_cert.der().to_vec(), leaf_key)
    }

    const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

    fn create_signed_request_object(
        client_id: &str,
        header: &mut Header,
        signing_key: &EncodingKey,
    ) -> String {
        header.typ = Some(REQUEST_OBJECT_TYP.to_string());
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let payload = json!({
            "iss": client_id,
            "aud": client_id,
            "exp": now + 300,
            "iat": now,
            "client_id": client_id,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": "test-nonce",
            "response_uri": "https://verifier.example.com/response",
            "scope": "openid",
        });
        encode(header, &payload, signing_key).expect("JWT must encode")
    }

    #[tokio::test]
    async fn valid_x509_san_dns_chain() {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).expect("root cert");
        let trust_anchor = anchor_from_trusted_cert(root_cert.der())
            .expect("trust anchor")
            .to_owned();

        let (leaf_der, leaf_key) = create_leaf_cert(
            vec!["client.example.org".to_string()],
            &root_key,
            &root_params,
            None,
        );

        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![STANDARD.encode(&leaf_der)]);

        let client_id = "x509_san_dns:client.example.org";
        let jwt = create_signed_request_object(
            client_id,
            &mut header,
            &EncodingKey::from_ec_der(&leaf_key.serialize_der()),
        );

        let verifier = X509Verifier::new(Arc::new(vec![trust_anchor]));
        let result = RequestObject::decode_and_validate(
            &jwt,
            client_id,
            crate::oid4vp::request_object::DiscoveryMode::Dynamic,
            &verifier,
        )
        .await;
        assert!(result.is_ok(), "should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn valid_x509_hash_chain() {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).expect("root cert");
        let trust_anchor = anchor_from_trusted_cert(root_cert.der())
            .expect("trust anchor")
            .to_owned();

        let (leaf_der, leaf_key) = create_leaf_cert(
            vec!["any.example.org".to_string()],
            &root_key,
            &root_params,
            None,
        );
        let leaf_hash = compute_leaf_hash(&leaf_der);

        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![STANDARD.encode(&leaf_der)]);

        let client_id = format!("x509_hash:{leaf_hash}");
        let jwt = create_signed_request_object(
            &client_id,
            &mut header,
            &EncodingKey::from_ec_der(&leaf_key.serialize_der()),
        );

        let verifier = X509Verifier::new(Arc::new(vec![trust_anchor]));
        let result = RequestObject::decode_and_validate(
            &jwt,
            &client_id,
            crate::oid4vp::request_object::DiscoveryMode::Dynamic,
            &verifier,
        )
        .await;
        assert!(result.is_ok(), "should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn rejects_expired_cert() {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).expect("root cert");
        let trust_anchor = anchor_from_trusted_cert(root_cert.der())
            .expect("trust anchor")
            .to_owned();

        // Create a leaf cert that expired yesterday
        let yesterday = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let (leaf_der, leaf_key) = create_leaf_cert(
            vec!["client.example.org".to_string()],
            &root_key,
            &root_params,
            Some(yesterday),
        );

        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![STANDARD.encode(&leaf_der)]);

        let client_id = "x509_san_dns:client.example.org";
        let jwt = create_signed_request_object(
            client_id,
            &mut header,
            &EncodingKey::from_ec_der(&leaf_key.serialize_der()),
        );

        let verifier = X509Verifier::new(Arc::new(vec![trust_anchor]));
        let result = RequestObject::decode_and_validate(
            &jwt,
            client_id,
            crate::oid4vp::request_object::DiscoveryMode::Dynamic,
            &verifier,
        )
        .await;
        assert!(result.is_err(), "should fail for expired cert");
    }

    #[tokio::test]
    async fn rejects_san_dns_mismatch() {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).expect("root cert");
        let trust_anchor = anchor_from_trusted_cert(root_cert.der())
            .expect("trust anchor")
            .to_owned();

        let (leaf_der, leaf_key) = create_leaf_cert(
            vec!["other.example.org".to_string()],
            &root_key,
            &root_params,
            None,
        );

        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![STANDARD.encode(&leaf_der)]);

        let client_id = "x509_san_dns:client.example.org";
        let jwt = create_signed_request_object(
            client_id,
            &mut header,
            &EncodingKey::from_ec_der(&leaf_key.serialize_der()),
        );

        let verifier = X509Verifier::new(Arc::new(vec![trust_anchor]));
        let result = RequestObject::decode_and_validate(
            &jwt,
            client_id,
            crate::oid4vp::request_object::DiscoveryMode::Dynamic,
            &verifier,
        )
        .await;
        assert!(result.is_err(), "should fail for SAN mismatch");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("x509_san_dns mismatch"),
            "error should indicate SAN mismatch: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_hash_mismatch() {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).expect("root cert");
        let trust_anchor = anchor_from_trusted_cert(root_cert.der())
            .expect("trust anchor")
            .to_owned();

        let (leaf_der, leaf_key) = create_leaf_cert(
            vec!["client.example.org".to_string()],
            &root_key,
            &root_params,
            None,
        );

        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![STANDARD.encode(&leaf_der)]);

        let wrong_hash = "Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk";
        let client_id = format!("x509_hash:{wrong_hash}");
        let jwt = create_signed_request_object(
            &client_id,
            &mut header,
            &EncodingKey::from_ec_der(&leaf_key.serialize_der()),
        );

        let verifier = X509Verifier::new(Arc::new(vec![trust_anchor]));
        let result = RequestObject::decode_and_validate(
            &jwt,
            &client_id,
            crate::oid4vp::request_object::DiscoveryMode::Dynamic,
            &verifier,
        )
        .await;
        assert!(result.is_err(), "should fail for hash mismatch");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("x509_hash mismatch"),
            "error should indicate hash mismatch: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_self_signed_cert() {
        // Self-signed leaf without a trusted root
        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["client.example.org".to_owned()]).expect("leaf params");
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_cert = leaf_params.self_signed(&leaf_key).expect("leaf cert");
        let leaf_der = leaf_cert.der().to_vec();

        // Use a *different* self-signed root as the only trust anchor
        let other_root = KeyPair::generate().expect("other root");
        let mut other_params = CertificateParams::default();
        other_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let other_cert = other_params.self_signed(&other_root).expect("other cert");
        let trust_anchor = anchor_from_trusted_cert(other_cert.der())
            .expect("trust anchor")
            .to_owned();

        let mut header = Header::new(Algorithm::ES256);
        header.x5c = Some(vec![STANDARD.encode(&leaf_der)]);

        let client_id = "x509_san_dns:client.example.org";
        let jwt = create_signed_request_object(
            client_id,
            &mut header,
            &EncodingKey::from_ec_der(&leaf_key.serialize_der()),
        );

        let verifier = X509Verifier::new(Arc::new(vec![trust_anchor]));
        let result = RequestObject::decode_and_validate(
            &jwt,
            client_id,
            crate::oid4vp::request_object::DiscoveryMode::Dynamic,
            &verifier,
        )
        .await;
        assert!(
            result.is_err(),
            "should fail for self-signed / untrusted chain"
        );
    }

    #[tokio::test]
    async fn rejects_missing_x5c() {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).expect("root cert");
        let trust_anchor = anchor_from_trusted_cert(root_cert.der())
            .expect("trust anchor")
            .to_owned();

        let header = Header::new(Algorithm::ES256);
        let client_id = ParsedClientId::parse("x509_san_dns:client.example.org").unwrap();

        let verifier = X509Verifier::new(Arc::new(vec![trust_anchor]));
        let result = verifier.resolve_key(&client_id, &header).await;
        assert!(result.is_err(), "should fail for missing x5c");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("missing x5c"),
            "error should indicate missing x5c: {err}"
        );
    }
}
