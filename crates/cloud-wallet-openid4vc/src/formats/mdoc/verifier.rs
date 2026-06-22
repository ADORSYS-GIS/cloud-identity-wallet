//! Digest integrity and issuer signature verification for ISO 18013-5 mDoc credentials.
//!
//! Implements verify_digests (MSO digest check) and verify_issuer_signature
//! (COSE_Sign1 + certificate chain validation) as required by ISO/IEC 18013-5 §9.1.2.

use ciborium::Value;
use coset::Label;
use coset::iana::EnumI64 as _;
use subtle::ConstantTimeEq as _;

use cloud_wallet_crypto::digest::HashAlg;
use cloud_wallet_crypto::ecdsa::VerifyingKey as EcdsaKey;
use cloud_wallet_crypto::ed25519::VerifyingKey as Ed25519Key;
use cloud_wallet_crypto::jwk::{Jwk, Key, OkpCurve};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use super::cert_chain::{
    check_country_consistency, check_dsc_eku, check_dsc_key_usage, check_dsc_validity_period,
    check_signed_within_dsc_validity, extract_spki, validate_cert_chain,
};
use super::error::{MdocError, Result};
use super::parser::ParsedMdoc;
use super::revocation::{RevocationPolicy, check_revocation};

/// COSE unprotected header label for the X.509 certificate chain (RFC 9360).
const X5CHAIN_LABEL: i64 = 33;

/// COSE algorithm identifier for ES256 (ECDSA P-256 + SHA-256).
const ALG_ES256: i64 = -7;
/// COSE algorithm identifier for ES384 (ECDSA P-384 + SHA-384).
const ALG_ES384: i64 = -35;
/// COSE algorithm identifier for ES512 (ECDSA P-521 + SHA-512).
const ALG_ES512: i64 = -36;
/// COSE algorithm identifier for EdDSA / Ed25519.
const ALG_EDDSA: i64 = -8;
/// COSE algorithm identifier for ECDSA on Brainpool P-256r1 (ISO 18013-5 Annex B).
const ALG_BRAINPOOL_P256: i64 = -38;
/// COSE algorithm identifier for ECDSA on Brainpool P-384r1 (ISO 18013-5 Annex B).
const ALG_BRAINPOOL_P384: i64 = -47;
/// COSE algorithm identifier for ECDSA on Brainpool P-512r1 (ISO 18013-5 Annex B).
const ALG_BRAINPOOL_P512: i64 = -48;

/// Verifies that every `IssuerSignedItem` in `parsed` hashes to its corresponding
/// entry in the MSO `valueDigests` map (ISO/IEC 18013-5 §9.1.2).
///
/// # Errors
///
/// - [`MdocError::MissingDigest`] — no `valueDigests` entry for a presented item's
///   namespace + `digestID`.
/// - [`MdocError::DigestMismatch`] — the computed hash does not match the stored digest.
#[must_use = "digest verification failure must be handled"]
pub(crate) fn verify_digests(parsed: &ParsedMdoc) -> Result<()> {
    let alg = HashAlg::from(parsed.digest_algorithm);

    for (namespace, items) in &parsed.name_spaces {
        for item in items {
            let computed = alg.hash(&item.raw_tag24_bytes);

            let stored = parsed
                .value_digests
                .get(namespace)
                .and_then(|ns_map| ns_map.get(&item.digest_id))
                .ok_or_else(|| MdocError::MissingDigest {
                    namespace: namespace.clone(),
                    digest_id: item.digest_id,
                })?;

            // Both slices are guaranteed equal-length, so ct_eq runs in constant
            // time over all bytes (subtle only guarantees this for equal-length inputs).
            let digest_ok: bool = computed.as_ref().ct_eq(stored.as_slice()).into();
            if !digest_ok {
                return Err(MdocError::DigestMismatch {
                    namespace: namespace.clone(),
                    digest_id: item.digest_id,
                });
            }
        }
    }

    Ok(())
}

/// A source of trusted IACA root certificates used to validate the `issuerAuth`
/// certificate chain (ISO 18013-5 §9.1.2).
///
/// Implement this trait to plug in any trust store backend: a static list of DER
/// bytes loaded at startup, a database-backed store, or a per-tenant store.
///
/// The `Send + Sync` bounds allow the trust store to be shared across threads and
/// passed as `&dyn IacaTrustStore` through async contexts.
pub trait IacaTrustStore: Send + Sync {
    /// Returns the DER-encoded trusted IACA root certificates.
    fn trusted_roots(&self) -> &[Vec<u8>];
}

/// A simple trust store backed by an in-memory list of DER-encoded root certificates.
///
/// Suitable for tests and deployments where roots are known at compile time or loaded
/// from disk at startup.
#[derive(Clone, Debug)]
pub struct StaticTrustStore {
    roots: Vec<Vec<u8>>,
}

impl StaticTrustStore {
    /// Creates a new [`StaticTrustStore`] from a list of DER-encoded root certificates.
    pub fn new(roots: Vec<Vec<u8>>) -> Self {
        Self { roots }
    }
}

impl IacaTrustStore for StaticTrustStore {
    fn trusted_roots(&self) -> &[Vec<u8>] {
        &self.roots
    }
}

/// Information about the issuer extracted from a successfully verified `issuerAuth`.
///
/// Returned by verify_issuer_signature after the full verification pipeline
/// (chain validation, EKU check, signature check) succeeds.
#[derive(Debug)]
pub struct IssuerInfo {
    /// Full certificate chain as DER bytes, leaf-first (index 0 is the DSC).
    pub cert_chain: Vec<Vec<u8>>,

    /// Subject distinguished name of the Document Signer Certificate as a
    /// human-readable string (e.g. `"C=DE, O=Example Issuer, CN=DSC-01"`).
    pub issuer_subject: String,

    /// ISO 3166-1 alpha-2 country code from the DSC subject `CountryName` attribute,
    /// or an empty string if the attribute is absent.
    pub issuer_country: String,
}

/// Verifies the `issuerAuth` COSE_Sign1 signature against a trusted IACA certificate chain
/// (ISO/IEC 18013-5 §9.1.2): chain validation, EKU/key-usage check, docType match,
/// validity-window check, signature verification, and revocation checking.
///
/// The DSC (`chain[0]`) is parsed once and the parsed certificate is passed to all
/// per-certificate helpers, avoiding redundant DER parsing.
///
/// # Parameters
///
/// - `outer_doc_type`: the `docType` from the enclosing document structure, checked
///   against the MSO `docType` field (§9.3.1 step 4).
/// - `revocation_policy`: policy for DSC revocation checking (ISO 18013-5 §9.3.3).
///
/// # Errors
///
/// - [`MdocError::MissingAlgorithm`] — algorithm field is absent or is not an integer label.
/// - [`MdocError::UnsupportedAlgorithm`] — alg is not ES256 (-7), ES384 (-35),
///   ES512 (-36), or EdDSA/Ed25519 (-8).
/// - [`MdocError::MissingX5Chain`] — COSE unprotected header label 33 is absent.
/// - [`MdocError::InvalidCertificateChain`] — chain is malformed, untrusted, the IACA
///   root appears in the chain, or the DSC validity period exceeds 457 days.
/// - [`MdocError::CountryMismatch`] — DSC and IACA have different country codes.
/// - [`MdocError::MissingDocSignerEku`] — DSC does not carry OID 1.0.18013.5.1.2.
/// - [`MdocError::MissingDigitalSignatureKeyUsage`] — DSC Key Usage extension is absent or
///   `digitalSignature` bit is not set.
/// - [`MdocError::NonCriticalKeyUsage`] — DSC Key Usage extension is present and bit is set
///   but the extension is not marked critical.
/// - [`MdocError::DocTypeMismatch`] — outer `docType` differs from MSO `docType`.
/// - [`MdocError::SignedOutsideDscValidity`] — MSO `signed` is outside DSC validity.
/// - [`MdocError::InvalidIssuerSignature`] — signature does not verify.
/// - [`MdocError::CertificateRevoked`] — DSC is revoked (depends on policy).
/// - [`MdocError::RevocationCheckFailed`] — CRL fetch/validation failed (HardFail only).
#[must_use = "issuer signature verification failure must be handled"]
pub(crate) async fn verify_issuer_signature(
    parsed: &ParsedMdoc,
    outer_doc_type: &str,
    trust_store: &dyn IacaTrustStore,
    revocation_policy: RevocationPolicy,
) -> Result<IssuerInfo> {
    let alg = read_cose_alg(parsed)?;

    // x5chain is a leaf-first CBOR bstr array (RFC 9360 §2); chain[0] is the DSC.
    let chain = extract_x5chain(parsed)?;

    // validate_cert_chain returns the specific anchoring root DER so that subsequent
    // checks (e.g. country-code consistency) are performed against that root alone,
    // not against every root in the trust store (which would incorrectly fail in a
    // multi-country trust store).
    let anchoring_root_der = validate_cert_chain(&chain, trust_store.trusted_roots())?;

    // Parse the DSC exactly once and pass the parsed certificate to all helpers.
    let (_, dsc) =
        X509Certificate::from_der(&chain[0]).map_err(|e| MdocError::InvalidCertificateChain {
            reason: format!("failed to parse DSC: {e}"),
        })?;

    // DSC validity period must not exceed 457 days (ISO 18013-5 Annex B Table B.3).
    check_dsc_validity_period(&dsc)?;

    // DSC subject country must match the anchoring IACA country (ISO 18013-5 §9.3.3).
    check_country_consistency(&dsc, &anchoring_root_der)?;

    check_dsc_eku(&dsc)?;

    // digitalSignature key usage bit required by ISO 18013-5 Annex B Table B.3.
    check_dsc_key_usage(&dsc)?;

    if parsed.doc_type != outer_doc_type {
        return Err(MdocError::DocTypeMismatch {
            mso: parsed.doc_type.clone(),
            document: outer_doc_type.to_owned(),
        });
    }

    // tbs_data uses the wire bytes of the protected header (original_data) so we
    // never re-encode and silently change the byte sequence that was signed.
    let tbs = parsed.cose_sign1.tbs_data(b"");

    // MSO signed timestamp must fall within the DSC validity window (ISO 18013-5 §9.3.1).
    check_signed_within_dsc_validity(&dsc, parsed.signed_at)?;

    let spki = extract_spki(&dsc);
    let sig = &parsed.cose_sign1.signature;

    // Reject Ed448 (OID 1.3.101.113) before dispatch; only Ed25519 (OID 1.3.101.112)
    // is supported.  Checking the OID via the properly-parsed SubjectPublicKeyInfo
    // (already available in `dsc`) is safe against SPKI byte patterns that happen to
    // contain the OID bytes at a non-OID position.
    const ED448_OID: &str = "1.3.101.113";
    if alg == ALG_EDDSA && dsc.public_key().algorithm.algorithm.to_id_string() == ED448_OID {
        return Err(MdocError::UnsupportedAlgorithm { alg });
    }

    dispatch_verify(alg, &spki, &tbs, sig)?;

    // Revocation check (ISO 18013-5 §9.3.3) — fetches CRL and verifies DSC is not revoked.
    // Run after COSE signature verification to avoid network calls for tampered payloads.
    // The CRL must be signed by the DSC's immediate issuer, not the IACA root.
    // For single-level chains (DSC → IACA), the issuer is the anchoring root.
    // For multi-level chains (DSC → Intermediate → IACA), the issuer is chain[1].
    let dsc_issuer_der = if chain.len() > 1 {
        // Multi-level chain: DSC issuer is the intermediate CA at chain[1]
        chain[1].clone()
    } else {
        // Single-level chain: DSC is directly signed by the IACA root
        anchoring_root_der.clone()
    };
    check_revocation(&dsc, &dsc_issuer_der, revocation_policy).await?;

    let issuer_subject = dsc.subject().to_string();
    let issuer_country = dsc
        .subject()
        .iter_country()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or("")
        .to_owned();

    Ok(IssuerInfo {
        cert_chain: chain,
        issuer_subject,
        issuer_country,
    })
}

/// Reads the COSE algorithm integer from the `issuerAuth` protected header.
fn read_cose_alg(parsed: &ParsedMdoc) -> Result<i64> {
    use coset::RegisteredLabelWithPrivate;

    let alg = parsed
        .cose_sign1
        .protected
        .header
        .alg
        .as_ref()
        .ok_or(MdocError::MissingAlgorithm)?;

    let alg_i64 = match alg {
        RegisteredLabelWithPrivate::Assigned(a) => a.to_i64(),
        RegisteredLabelWithPrivate::PrivateUse(i) => *i,
        RegisteredLabelWithPrivate::Text(_) => {
            // A text-label algorithm cannot be an integer COSE algorithm identifier.
            return Err(MdocError::MissingAlgorithm);
        }
    };

    match alg_i64 {
        ALG_ES256 | ALG_ES384 | ALG_ES512 | ALG_EDDSA | ALG_BRAINPOOL_P256 | ALG_BRAINPOOL_P384
        | ALG_BRAINPOOL_P512 => Ok(alg_i64),
        other => Err(MdocError::UnsupportedAlgorithm { alg: other }),
    }
}

/// Extracts the DER-encoded certificate chain from COSE unprotected header label 33.
///
/// Per RFC 9360 §2, the value is either a single bstr (single cert) or an array of
/// bstr (chain, leaf first).  We normalise both forms to `Vec<Vec<u8>>`.
fn extract_x5chain(parsed: &ParsedMdoc) -> Result<Vec<Vec<u8>>> {
    let x5chain_val = parsed
        .cose_sign1
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Int(X5CHAIN_LABEL))
        .map(|(_, v)| v)
        .ok_or(MdocError::MissingX5Chain)?;

    match x5chain_val {
        // Single certificate (bstr).
        Value::Bytes(der) => Ok(vec![der.clone()]),

        // Certificate chain: array of bstr, leaf first.
        Value::Array(entries) => {
            let chain: Option<Vec<Vec<u8>>> = entries
                .iter()
                .map(|v| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .collect();
            chain.ok_or(MdocError::MissingX5Chain)
        }

        _ => Err(MdocError::MissingX5Chain),
    }
}

/// Dispatches the COSE signature verification to the correct crypto backend.
fn dispatch_verify(alg: i64, spki: &[u8], tbs: &[u8], signature: &[u8]) -> Result<()> {
    match alg {
        ALG_ES256 => {
            let key =
                EcdsaKey::from_spki_der(spki).map_err(|_| MdocError::InvalidIssuerSignature)?;
            key.verify_sha256(tbs, signature)
                .map_err(|_| MdocError::InvalidIssuerSignature)
        }
        ALG_ES384 => {
            let key =
                EcdsaKey::from_spki_der(spki).map_err(|_| MdocError::InvalidIssuerSignature)?;
            key.verify_sha384(tbs, signature)
                .map_err(|_| MdocError::InvalidIssuerSignature)
        }
        ALG_ES512 => {
            let key =
                EcdsaKey::from_spki_der(spki).map_err(|_| MdocError::InvalidIssuerSignature)?;
            key.verify_sha512(tbs, signature)
                .map_err(|_| MdocError::InvalidIssuerSignature)
        }
        ALG_EDDSA => {
            // Ed448 is rejected earlier in `verify_issuer_signature` via the parsed OID.
            // By the time we reach here the key is guaranteed to be Ed25519.
            let key =
                Ed25519Key::from_spki_der(spki).map_err(|_| MdocError::InvalidIssuerSignature)?;
            key.verify(tbs, signature)
                .map_err(|_| MdocError::InvalidIssuerSignature)
        }
        // TODO: Brainpool P-256r1/P-384r1/P-512r1 (ISO 18013-5 Annex B) — not yet supported.
        ALG_BRAINPOOL_P256 | ALG_BRAINPOOL_P384 | ALG_BRAINPOOL_P512 => {
            Err(MdocError::UnsupportedAlgorithm { alg })
        }
        _ => unreachable!("dispatch_verify received alg={alg} — not handled in read_cose_alg"),
    }
}

/// Verifies that the holder public key embedded in the MSO `deviceKeyInfo.deviceKey`
/// matches the key presented in the OID4VCI proof JWT (ISO/IEC 18013-5 §9.1.2.4).
///
/// # Errors
///
/// - [`MdocError::MalformedDeviceKey`] — COSE_Key CBOR is invalid or missing required fields.
/// - [`MdocError::UnsupportedDeviceKeyType`] — unsupported kty/crv, compressed EC2 y, or
///   non-EC/non-OKP proof JWK.
/// - [`MdocError::CurveMismatch`] — COSE curve differs from proof JWK curve.
/// - [`MdocError::DeviceKeyMismatch`] — constant-time coordinate comparison failed.
#[must_use = "device key binding failure must be handled"]
pub(crate) fn verify_device_key_binding(
    parsed: &ParsedMdoc,
    holder_binding_public_jwk: &Jwk,
) -> Result<()> {
    let cose_key_val: Value =
        ciborium::de::from_reader(parsed.device_key.as_slice()).map_err(|_| {
            MdocError::MalformedDeviceKey {
                reason: "invalid CBOR".to_owned(),
            }
        })?;

    let entries = match cose_key_val {
        Value::Map(m) => m,
        _ => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "COSE_Key must be a CBOR map".to_owned(),
            });
        }
    };

    // RFC 7049 §3.1 forbids duplicate keys in CBOR maps. Reject to prevent
    // split-key constructions where the same integer label appears twice.
    // COSE_Keys have at most ~6 entries; the O(n²) scan avoids a heap allocation.
    for i in 0..entries.len() {
        if let Value::Integer(a) = &entries[i].0 {
            for item in entries.iter().skip(i + 1) {
                if let Value::Integer(b) = &item.0
                    && i128::from(*a) == i128::from(*b)
                {
                    return Err(MdocError::MalformedDeviceKey {
                        reason: "COSE_Key map contains duplicate integer label".to_owned(),
                    });
                }
            }
        }
    }

    // kty (label 1) — determines EC2 vs OKP dispatch.
    let kty: i128 = match cose_key_get(&entries, 1) {
        Some(Value::Integer(n)) => i128::from(*n),
        Some(_) => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "kty (label 1) must be an integer".to_owned(),
            });
        }
        None => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "missing kty (label 1)".to_owned(),
            });
        }
    };

    match kty {
        2 => verify_ec2_binding(&entries, holder_binding_public_jwk),
        1 => verify_okp_binding(&entries, holder_binding_public_jwk),
        _ => Err(MdocError::UnsupportedDeviceKeyType {
            reason: "kty is not EC2 (2) or OKP (1)",
        }),
    }
}

/// EC2 device-key binding check (kty=2, ISO 18013-5 Table 22 NIST curves).
fn verify_ec2_binding(entries: &[(Value, Value)], holder_binding_public_jwk: &Jwk) -> Result<()> {
    // crv (label -1): map integer to (curve name string, JWK Curve variant).
    let (cose_crv_name, jwk_curve) = match cose_key_get(entries, -1) {
        Some(Value::Integer(n)) => match i128::from(*n) {
            1 => ("P-256", cloud_wallet_crypto::jwk::Curve::P256),
            2 => ("P-384", cloud_wallet_crypto::jwk::Curve::P384),
            3 => ("P-521", cloud_wallet_crypto::jwk::Curve::P521),
            _ => {
                return Err(MdocError::UnsupportedDeviceKeyType {
                    reason: "EC2 crv is not P-256 (1), P-384 (2), or P-521 (3)",
                });
            }
        },
        Some(_) => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "crv (label -1) must be an integer".to_owned(),
            });
        }
        None => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "missing crv (label -1)".to_owned(),
            });
        }
    };

    // x (label -2): must be bytes.
    let cose_x = match cose_key_get(entries, -2) {
        Some(Value::Bytes(b)) => b.as_slice(),
        Some(_) => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "x coordinate (label -2) must be bytes".to_owned(),
            });
        }
        None => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "missing x coordinate (label -2)".to_owned(),
            });
        }
    };

    // y (label -3): bytes (uncompressed) or bool (compressed — explicitly unsupported).
    let cose_y = match cose_key_get(entries, -3) {
        Some(Value::Bytes(b)) => b.as_slice(),
        // RFC 8152 §13.1 permits y as a bool for compressed EC2 points. We cannot
        // compare compressed-only keys against the uncompressed JWK y without EC
        // decompression. Reject explicitly rather than silently skipping.
        Some(Value::Bool(_)) => {
            return Err(MdocError::UnsupportedDeviceKeyType {
                reason: "compressed EC2 y (bool); uncompressed form required",
            });
        }
        Some(_) => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "y coordinate (label -3) must be bytes or bool".to_owned(),
            });
        }
        None => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "missing y coordinate (label -3)".to_owned(),
            });
        }
    };

    // Match proof JWK against Key::Ec.
    let ec = match &holder_binding_public_jwk.key {
        Key::Ec(ec) => ec,
        _ => {
            return Err(MdocError::UnsupportedDeviceKeyType {
                reason: "proof JWK key type is not EC",
            });
        }
    };

    // Curve consistency check.
    let jwk_crv_name = match ec.crv {
        cloud_wallet_crypto::jwk::Curve::P256 => "P-256",
        cloud_wallet_crypto::jwk::Curve::P384 => "P-384",
        cloud_wallet_crypto::jwk::Curve::P521 => "P-521",
        cloud_wallet_crypto::jwk::Curve::P256K1 => "secp256k1",
        // Curve is #[non_exhaustive]; future variants are unsupported.
        _ => {
            return Err(MdocError::UnsupportedDeviceKeyType {
                reason: "proof JWK EC curve is not P-256, P-384, or P-521",
            });
        }
    };
    if ec.crv != jwk_curve {
        return Err(MdocError::CurveMismatch {
            cose_crv: cose_crv_name.to_owned(),
            jwk_crv: jwk_crv_name.to_owned(),
        });
    }

    // Validate coordinate byte lengths match the curve before ct_eq: subtle's
    // ConstantTimeEq for &[u8] short-circuits (non-constant-time) on length
    // mismatch; an equal-length gate here guarantees the comparison is always
    // constant-time over the full coordinate.
    let expected_coord_len: usize = match jwk_curve {
        cloud_wallet_crypto::jwk::Curve::P256 => 32,
        cloud_wallet_crypto::jwk::Curve::P384 => 48,
        cloud_wallet_crypto::jwk::Curve::P521 => 66,
        _ => unreachable!("jwk_curve was matched from a P-256/P-384/P-521 COSE crv"),
    };
    if cose_x.len() != expected_coord_len
        || cose_y.len() != expected_coord_len
        || ec.x.as_ref().len() != expected_coord_len
        || ec.y.as_ref().len() != expected_coord_len
    {
        return Err(MdocError::MalformedDeviceKey {
            reason: "coordinate length does not match curve".to_owned(),
        });
    }
    // Both slices are guaranteed equal-length; ct_eq runs in constant time over all bytes.
    let x_eq: bool = cose_x.ct_eq(ec.x.as_ref()).into();
    let y_eq: bool = cose_y.ct_eq(ec.y.as_ref()).into();
    if !x_eq || !y_eq {
        return Err(MdocError::DeviceKeyMismatch);
    }

    Ok(())
}

/// OKP Ed25519 device-key binding check (kty=1, crv=6, x-only, RFC 8152 §13.2).
fn verify_okp_binding(entries: &[(Value, Value)], holder_binding_public_jwk: &Jwk) -> Result<()> {
    // crv (label -1): must be 6 (Ed25519). All other OKP curves are unsupported.
    match cose_key_get(entries, -1) {
        Some(Value::Integer(n)) => match i128::from(*n) {
            6 => {} // Ed25519 — proceed
            _ => {
                return Err(MdocError::UnsupportedDeviceKeyType {
                    reason: "OKP crv is not Ed25519 (6)",
                });
            }
        },
        Some(_) => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "crv (label -1) must be an integer".to_owned(),
            });
        }
        None => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "missing crv (label -1)".to_owned(),
            });
        }
    }

    // x (label -2): must be bytes. OKP has no y (RFC 8152 §13.2).
    let cose_x = match cose_key_get(entries, -2) {
        Some(Value::Bytes(b)) => b.as_slice(),
        Some(_) => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "x (label -2) must be bytes".to_owned(),
            });
        }
        None => {
            return Err(MdocError::MalformedDeviceKey {
                reason: "missing x (label -2)".to_owned(),
            });
        }
    };

    // Match proof JWK — must be OKP Ed25519.
    let okp = match &holder_binding_public_jwk.key {
        Key::Okp(okp) if okp.crv == OkpCurve::Ed25519 => okp,
        _ => {
            return Err(MdocError::UnsupportedDeviceKeyType {
                reason: "proof JWK key type is not OKP Ed25519",
            });
        }
    };

    // Ed25519 x must be exactly 32 bytes; validate before ct_eq to ensure the
    // constant-time property holds for equal-length slices.
    if cose_x.len() != 32 || okp.x.as_ref().len() != 32 {
        return Err(MdocError::MalformedDeviceKey {
            reason: "Ed25519 x coordinate must be 32 bytes".to_owned(),
        });
    }
    // Both slices are guaranteed 32 bytes; ct_eq runs in constant time over all bytes.
    let x_eq: bool = cose_x.ct_eq(okp.x.as_ref()).into();
    if !x_eq {
        return Err(MdocError::DeviceKeyMismatch);
    }

    Ok(())
}

/// Runs the full ISO 18013-5 §9.1.2 verification chain for an already-parsed mdoc.
/// Using this function rather than calling the four checks individually ensures
/// that no check is accidentally omitted or reordered at a call site.
///
/// # Arguments
///
/// * `parsed` — the structurally-parsed mdoc (from [`ParsedMdoc::parse`]).
/// * `outer_doc_type` — the `docType` string from the credential configuration,
///   matched against the MSO `docType` field.
/// * `trust_store` — IACA root certificates accepted for this wallet deployment.
/// * `holder_binding_public_jwk` — the holder's public key from the OID4VCI proof JWT header.
/// * `now` — the current time; use `OffsetDateTime::now_utc()` in production.
/// * `revocation_policy` — policy for DSC revocation checking (ISO 18013-5 §9.3.3).
///
/// # Errors
///
/// Propagates errors from any of the underlying checks.
pub async fn verify_mdoc_for_issuance(
    parsed: &ParsedMdoc,
    outer_doc_type: &str,
    trust_store: &dyn IacaTrustStore,
    holder_binding_public_jwk: &Jwk,
    now: OffsetDateTime,
    revocation_policy: RevocationPolicy,
) -> Result<IssuerInfo> {
    parsed.check_temporal_validity(now)?;
    let issuer_info =
        verify_issuer_signature(parsed, outer_doc_type, trust_store, revocation_policy).await?;
    verify_digests(parsed)?;
    verify_device_key_binding(parsed, holder_binding_public_jwk)?;
    Ok(issuer_info)
}

/// Returns the value associated with the given integer label in a COSE_Key map,
/// or `None` if no entry with that label is present.
#[inline]
fn cose_key_get(entries: &[(Value, Value)], label: i64) -> Option<&Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Integer(n) if i128::from(*n) == i128::from(label) => Some(v),
        _ => None,
    })
}
