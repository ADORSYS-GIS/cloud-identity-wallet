//! Digest integrity and issuer signature verification for ISO 18013-5 mDoc credentials.
//!
//! Implements [`verify_digests`] (MSO digest check) and [`verify_issuer_signature`]
//! (COSE_Sign1 + certificate chain validation) as required by ISO/IEC 18013-5 §9.1.2.

use ciborium::Value;
use coset::Label;
use coset::iana::EnumI64 as _;
use subtle::ConstantTimeEq as _;

use cloud_wallet_crypto::digest::HashAlg;
use cloud_wallet_crypto::ecdsa::VerifyingKey as EcdsaKey;
use cloud_wallet_crypto::ed25519::VerifyingKey as Ed25519Key;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use super::cert_chain::{
    check_country_consistency, check_dsc_eku, check_dsc_key_usage, check_dsc_validity_period,
    check_signed_within_dsc_validity, extract_spki, validate_cert_chain,
};
use super::error::{MdocError, Result};
use super::parser::ParsedMdoc;

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
pub fn verify_digests(parsed: &ParsedMdoc) -> Result<()> {
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
/// Returned by [`verify_issuer_signature`] after the full verification pipeline
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
/// validity-window check, and signature verification.
///
/// The DSC (`chain[0]`) is parsed once and the parsed certificate is passed to all
/// per-certificate helpers, avoiding redundant DER parsing.
///
/// # Parameters
///
/// - `outer_doc_type`: the `docType` from the enclosing document structure, checked
///   against the MSO `docType` field (§9.3.1 step 4).
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
/// - [`MdocError::DocTypeMismatch`] — outer `docType` differs from MSO `docType`.
/// - [`MdocError::SignedOutsideDscValidity`] — MSO `signed` is outside DSC validity.
/// - [`MdocError::InvalidIssuerSignature`] — signature does not verify.
///
/// # Known Limitations
///
/// Certificate revocation (CRL / OCSP) is not checked. A credential signed by a revoked
/// DSC will pass all current checks.
#[must_use = "issuer signature verification failure must be handled"]
pub fn verify_issuer_signature(
    parsed: &ParsedMdoc,
    outer_doc_type: &str,
    trust_store: &dyn IacaTrustStore,
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
