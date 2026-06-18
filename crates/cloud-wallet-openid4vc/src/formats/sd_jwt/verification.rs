use std::borrow::Cow;

use base64::{Engine, engine::general_purpose::STANDARD};
use cloud_wallet_crypto::jwk::{
    Algorithm as JwkAlgorithm, Curve, Jwk, JwkSet, Key, KeyUse, OkpCurve, Operations, Signing,
};
use jsonwebtoken::{
    Algorithm as JwtAlgorithm, DecodingKey, Validation, decode as decode_jwt,
    errors::Error as JwtError, jwk::Jwk as JwtJwk,
};
use reqwest_middleware::ClientWithMiddleware;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use serde_json::Error as JsonError;
use webpki::{EndEntityCert, Error as WebPkiError};
use x509_parser::{extensions::ParsedExtension, parse_x509_certificate, public_key::PublicKey};

use super::{SdJwt, SdJwtClaims, metadata};

type Result<T> = std::result::Result<T, VerificationError>;

const ED25519_OID: &str = "1.3.101.112";

/// Trust anchors used to validate an issuer-signed JWT `x5c` certificate path.
///
/// Call `X5cTrustAnchors::default()` to use Mozilla's public WebPKI root certificate set.
#[derive(Debug, Clone, Copy, Default)]
pub enum X5cTrustAnchors<'a> {
    /// Mozilla's public WebPKI root certificate set.
    #[default]
    Mozilla,
    /// Caller-provided trust anchors.
    Custom(&'a [TrustAnchor<'a>]),
}

/// Errors returned while establishing issuer trust or verifying the issuer signature.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// The trust material for the issuer could not be resolved.
    #[error("failed to establish issuer trust")]
    Trust(#[from] metadata::IssuerMetadataError),

    /// The trusted key set does not contain an unambiguous signing key.
    #[error("trusted issuer signing key not found: {message}")]
    KeySelection { message: Cow<'static, str> },

    /// The JOSE algorithm or the trusted key parameters are not acceptable.
    #[error("invalid issuer signing key: {message}")]
    InvalidKey { message: Cow<'static, str> },

    /// The trusted key could not be converted for verification.
    #[error("failed to prepare issuer verification key")]
    KeyMaterial {
        /// Underlying conversion/parsing failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The issuer-signed JWT signature is invalid.
    #[error("issuer-signed JWT signature verification failed")]
    Signature(#[from] JwtError),

    /// The `x5c` trust path could not be validated.
    #[error("failed to validate issuer x5c trust chain: {message}")]
    X5c { message: Cow<'static, str> },
}

/// Establishes issuer trust and verifies the issuer-signed JWT signature.
///
/// If the JWT header contains `x5c`, the certificate chain is validated first
/// against the supplied trust anchors. Otherwise, the issuer's trusted JWKS is
/// resolved from JWT VC Issuer Metadata before selecting a verification key.
pub async fn verify_issuer_signature(
    sd_jwt: &SdJwt<'_>,
    http_client: &ClientWithMiddleware,
    trust_anchors: X5cTrustAnchors<'_>,
) -> Result<JwtAlgorithm> {
    if sd_jwt.jwt().header().x5c.is_some() {
        return verify_with_x5c(sd_jwt, trust_anchors);
    }

    let jwks = metadata::resolve(sd_jwt, http_client).await?;
    verify_with_jwks(sd_jwt, &jwks)
}

/// Verifies the issuer-signed JWT with a JWKS that has already been trusted.
pub(super) fn verify_with_jwks(sd_jwt: &SdJwt<'_>, jwks: &JwkSet) -> Result<JwtAlgorithm> {
    let algorithm = supported_public_algorithm(sd_jwt.jwt().header().alg)?;
    let key = select_jwk(sd_jwt, jwks)?;
    validate_jwk_for_algorithm(key, algorithm)?;
    let decoding_key = decoding_key_from_jwk(key)?;
    verify_signature(sd_jwt, &decoding_key, algorithm)?;
    Ok(algorithm)
}

/// Resolves the issuer verification key from the `x5c` JOSE header parameter.
///
/// Validates the certificate chain against the supplied trust anchors, verifies
/// the leaf certificate is not self-signed, and returns the leaf public key as
/// a [`DecodingKey`] together with the JWT algorithm.
pub(super) fn resolve_x5c_key(
    sd_jwt: &SdJwt<'_>,
    trust_anchors: X5cTrustAnchors<'_>,
) -> Result<(JwtAlgorithm, DecodingKey)> {
    let algorithm = supported_public_algorithm(sd_jwt.jwt().header().alg)?;
    let x5c = sd_jwt
        .jwt()
        .header()
        .x5c
        .as_ref()
        .filter(|certs| !certs.is_empty())
        .ok_or_else(|| VerificationError::X5c {
            message: "JWT header x5c must contain at least one certificate".into(),
        })?;

    let chain = decode_x5c_chain(x5c)?;
    let (_, leaf_cert) = parse_x509_certificate(&chain[0]).map_err(|e| VerificationError::X5c {
        message: format!("failed to parse leaf certificate: {e}").into(),
    })?;
    validate_leaf_not_self_signed(&leaf_cert)?;
    validate_x5c_chain(&chain, trust_anchors)?;
    let spki = leaf_spki_from_cert(&leaf_cert, algorithm)?;

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
            return Err(VerificationError::InvalidKey {
                message: "HMAC algorithms are not supported for x5c verification".into(),
            });
        }
    };
    Ok((algorithm, decoding_key))
}

/// Verifies an issuer-signed JWT whose JOSE header carries an `x5c` chain.
///
/// The leaf certificate is only used for signature verification after the
/// supplied certificate chain validates against a trust anchor.
pub(super) fn verify_with_x5c(
    sd_jwt: &SdJwt<'_>,
    trust_anchors: X5cTrustAnchors<'_>,
) -> Result<JwtAlgorithm> {
    let (algorithm, decoding_key) = resolve_x5c_key(sd_jwt, trust_anchors)?;
    verify_signature(sd_jwt, &decoding_key, algorithm)?;
    Ok(algorithm)
}

fn verify_signature(
    sd_jwt: &SdJwt<'_>,
    decoding_key: &DecodingKey,
    algorithm: JwtAlgorithm,
) -> Result<SdJwtClaims> {
    let mut validation = Validation::new(algorithm);
    validation.required_spec_claims.clear();
    validation.validate_exp = sd_jwt.jwt().claims().rfc7519.exp.is_some();
    validation.validate_nbf = sd_jwt.jwt().claims().rfc7519.nbf.is_some();

    validation.validate_aud = false;

    decode_jwt::<SdJwtClaims>(sd_jwt.jwt().raw(), decoding_key, &validation)
        .map(|token| token.claims)
        .map_err(Into::into)
}

fn supported_public_algorithm(algorithm: JwtAlgorithm) -> Result<JwtAlgorithm> {
    match algorithm {
        JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
            Err(VerificationError::InvalidKey {
                message: "issuer verification keys must not use symmetric HMAC algorithms".into(),
            })
        }
        _ => Ok(algorithm),
    }
}

fn select_jwk<'a>(sd_jwt: &SdJwt<'_>, jwks: &'a JwkSet) -> Result<&'a Jwk> {
    if let Some(kid) = sd_jwt.jwt().header().kid.as_deref() {
        return metadata::key_by_id(jwks, kid).ok_or_else(|| VerificationError::KeySelection {
            message: format!("no trusted key matches kid '{kid}'").into(),
        });
    }

    match jwks.keys.as_slice() {
        [key] => Ok(key),
        [] => Err(VerificationError::KeySelection {
            message: "trusted JWKS is empty".into(),
        }),
        _ => Err(VerificationError::KeySelection {
            message: "JWT header kid is required when the trusted JWKS has multiple keys".into(),
        }),
    }
}

fn validate_jwk_for_algorithm(jwk: &Jwk, algorithm: JwtAlgorithm) -> Result<()> {
    if jwk
        .prm
        .key_use
        .is_some_and(|key_use| key_use != KeyUse::Signing)
    {
        return Err(VerificationError::InvalidKey {
            message: "trusted key use must be sig when present".into(),
        });
    }

    if jwk
        .prm
        .ops
        .as_ref()
        .is_some_and(|ops| !ops.contains(&Operations::Verify))
    {
        return Err(VerificationError::InvalidKey {
            message: "trusted key_ops must be verify when present".into(),
        });
    }

    if let Some(key_algorithm) = jwk.prm.alg.as_ref().and_then(jwk_algorithm_to_jwt)
        && key_algorithm != algorithm
    {
        return Err(VerificationError::InvalidKey {
            message: format!(
                "JWT alg {algorithm:?} does not match trusted JWK alg {key_algorithm:?}"
            )
            .into(),
        });
    }

    let compatible = match (algorithm, &jwk.key) {
        (
            JwtAlgorithm::RS256
            | JwtAlgorithm::RS384
            | JwtAlgorithm::RS512
            | JwtAlgorithm::PS256
            | JwtAlgorithm::PS384
            | JwtAlgorithm::PS512,
            Key::Rsa(_),
        ) => true,
        (JwtAlgorithm::ES256, Key::Ec(ec)) => ec.crv == Curve::P256,
        (JwtAlgorithm::ES384, Key::Ec(ec)) => ec.crv == Curve::P384,
        (JwtAlgorithm::EdDSA, Key::Okp(okp)) => {
            matches!(okp.crv, OkpCurve::Ed25519 | OkpCurve::Ed448)
        }
        _ => false,
    };

    if compatible {
        Ok(())
    } else {
        Err(VerificationError::InvalidKey {
            message: format!("trusted key type is not compatible with JWT alg {algorithm:?}")
                .into(),
        })
    }
}

fn jwk_algorithm_to_jwt(algorithm: &JwkAlgorithm) -> Option<JwtAlgorithm> {
    match algorithm {
        JwkAlgorithm::Signing(Signing::EdDsa) => Some(JwtAlgorithm::EdDSA),
        JwkAlgorithm::Signing(Signing::Es256) => Some(JwtAlgorithm::ES256),
        JwkAlgorithm::Signing(Signing::Es384) => Some(JwtAlgorithm::ES384),
        JwkAlgorithm::Signing(Signing::Ps256) => Some(JwtAlgorithm::PS256),
        JwkAlgorithm::Signing(Signing::Ps384) => Some(JwtAlgorithm::PS384),
        JwkAlgorithm::Signing(Signing::Ps512) => Some(JwtAlgorithm::PS512),
        JwkAlgorithm::Signing(Signing::Rs256) => Some(JwtAlgorithm::RS256),
        JwkAlgorithm::Signing(Signing::Rs384) => Some(JwtAlgorithm::RS384),
        JwkAlgorithm::Signing(Signing::Rs512) => Some(JwtAlgorithm::RS512),
        JwkAlgorithm::Signing(Signing::Hs256 | Signing::Hs384 | Signing::Hs512) => None,
        JwkAlgorithm::Signing(Signing::Es256K | Signing::Es512 | Signing::Null) => None,
        _ => None,
    }
}

fn decoding_key_from_jwk(jwk: &Jwk) -> Result<DecodingKey> {
    let jwt_jwk = serde_json::to_value(jwk)
        .and_then(serde_json::from_value::<JwtJwk>)
        .map_err(key_material_error)?;

    DecodingKey::from_jwk(&jwt_jwk).map_err(key_material_error)
}

fn decode_x5c_chain(x5c: &[String]) -> Result<Vec<Vec<u8>>> {
    x5c.iter()
        .enumerate()
        .map(|(index, encoded)| {
            STANDARD
                .decode(encoded)
                .map_err(|_| VerificationError::X5c {
                    message: format!("certificate {index} is not valid base64").into(),
                })
        })
        .collect()
}

fn validate_x5c_chain(chain: &[Vec<u8>], trust_anchors: X5cTrustAnchors<'_>) -> Result<()> {
    match trust_anchors {
        X5cTrustAnchors::Mozilla => {
            validate_with_trust_anchors(chain, webpki_roots::TLS_SERVER_ROOTS)
        }
        X5cTrustAnchors::Custom(trust_anchors) => validate_with_trust_anchors(chain, trust_anchors),
    }
}

fn validate_with_trust_anchors(chain: &[Vec<u8>], trust_anchors: &[TrustAnchor<'_>]) -> Result<()> {
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

struct AnyKeyUsage;

impl webpki::ExtendedKeyUsageValidator for AnyKeyUsage {
    fn validate(
        &self,
        _iter: webpki::KeyPurposeIdIter<'_, '_>,
    ) -> std::result::Result<(), WebPkiError> {
        Ok(())
    }
}

/// Validates that the leaf certificate is not self-signed.
///
/// Per HAIP §6.1.1, the issuer's signing certificate MUST NOT be self-signed.
/// A self-signed certificate would indicate an untrusted issuer that cannot
/// be authenticated through a trust chain.
fn validate_leaf_not_self_signed(
    leaf_cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<()> {
    if leaf_cert.issuer() == leaf_cert.subject() {
        return Err(VerificationError::X5c {
            message: "leaf certificate must not be self-signed".into(),
        });
    }
    Ok(())
}

fn leaf_spki_from_cert(
    leaf_cert: &x509_parser::certificate::X509Certificate<'_>,
    algorithm: JwtAlgorithm,
) -> Result<Vec<u8>> {
    validate_leaf_key_usage(leaf_cert)?;

    let public_key = leaf_cert.public_key();
    let compatible = match (algorithm, public_key.parsed()) {
        (
            JwtAlgorithm::RS256
            | JwtAlgorithm::RS384
            | JwtAlgorithm::RS512
            | JwtAlgorithm::PS256
            | JwtAlgorithm::PS384
            | JwtAlgorithm::PS512,
            Ok(PublicKey::RSA(_)),
        ) => true,
        (JwtAlgorithm::ES256 | JwtAlgorithm::ES384, Ok(PublicKey::EC(_))) => true,
        (JwtAlgorithm::EdDSA, _) => public_key.algorithm.algorithm.to_id_string() == ED25519_OID,
        _ => false,
    };

    if !compatible {
        return Err(VerificationError::InvalidKey {
            message: format!(
                "leaf certificate public key is not compatible with JWT alg {algorithm:?}"
            )
            .into(),
        });
    }
    Ok(public_key.raw.to_vec())
}

fn validate_leaf_key_usage(cert: &x509_parser::certificate::X509Certificate<'_>) -> Result<()> {
    for extension in cert.extensions() {
        if let ParsedExtension::KeyUsage(key_usage) = extension.parsed_extension()
            && !key_usage.digital_signature()
        {
            return Err(VerificationError::InvalidKey {
                message: "leaf certificate key usage must allow digitalSignature".into(),
            });
        }
    }
    Ok(())
}

fn key_material_error(source: impl std::error::Error + Send + Sync + 'static) -> VerificationError {
    VerificationError::KeyMaterial {
        source: Box::new(source),
    }
}

fn x5c_error(message: &'static str, source: WebPkiError) -> VerificationError {
    VerificationError::X5c {
        message: format!("{message}: {source}").into(),
    }
}

impl From<JsonError> for VerificationError {
    fn from(source: JsonError) -> Self {
        key_material_error(source)
    }
}
