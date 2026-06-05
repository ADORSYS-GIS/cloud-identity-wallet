//! X.509 certificate chain validation helpers for ISO 18013-5 mDoc issuer authentication.
//!
//! This module provides utilities to:
//! - Validate a DER-encoded certificate chain against a set of trusted IACA roots
//!   (RFC 5280, ISO 18013-5 §9.1.2).
//! - Check that a Document Signer Certificate (DSC) carries the mandatory Extended Key
//!   Usage OID `1.0.18013.5.1.2` (ISO 18013-5 §9.1.2).
//! - Extract the raw SubjectPublicKeyInfo (SPKI) bytes from a parsed certificate
//!   so they can be passed to `cloud_wallet_crypto` verifying-key constructors.
//!
//! All functions are `pub(super)` — they are internal to the `mdoc` module and are not
//! part of the public crate API.
//!
//! Callers are expected to parse the DSC once (`X509Certificate::from_der`) and pass a
//! reference to the parsed certificate rather than raw DER bytes, avoiding redundant
//! ASN.1 parsing for every validation step.

use time::OffsetDateTime;
use x509_parser::prelude::{FromDer as _, ParsedExtension, X509Certificate};

use super::error::{MdocError, Result};

/// The OID required in the DSC Extended Key Usage extension (ISO 18013-5 §9.1.2).
const DSC_EKU_OID: &str = "1.0.18013.5.1.2";

/// Validates that `chain[0]` (the Document Signer Certificate) chains up to at least
/// one certificate in `trusted_roots` via standard X.509 path validation.
///
/// The chain must be ordered leaf-first: `chain[0]` is the DSC, subsequent entries are
/// intermediate CAs, and the last entry should be signed by a trusted root (or itself
/// be a trusted root).
///
/// # Returns
///
/// The DER bytes of the specific trusted root that anchors the chain.  Callers use
/// this to perform per-certificate consistency checks (e.g. country code) against the
/// one root that actually signed the chain, not against every root in the trust store.
///
/// # Errors
///
/// - [`MdocError::InvalidCertificateChain`] — the chain is empty, a certificate is
///   malformed, a signature in the chain is invalid, or no trusted root anchors it.
pub(super) fn validate_cert_chain(chain: &[Vec<u8>], trusted_roots: &[Vec<u8>]) -> Result<Vec<u8>> {
    if chain.is_empty() {
        return Err(MdocError::InvalidCertificateChain {
            reason: "certificate chain is empty".into(),
        });
    }

    // ISO 18013-5 Annex B §B.1: IACA root must not appear in x5chain (prevents trust-anchor bypass).
    for cert_der in chain {
        if trusted_roots.iter().any(|root| root == cert_der) {
            return Err(MdocError::InvalidCertificateChain {
                reason: "IACA root certificate must not appear in the x5chain \
                         (ISO 18013-5 Annex B section B.1)"
                    .into(),
            });
        }
    }

    // Full RFC 5280 path validation (name constraints, CRL/OCSP) is out of scope;
    // we verify signatures and root anchoring only.
    let parsed_chain: Vec<X509Certificate<'_>> = chain
        .iter()
        .enumerate()
        .map(|(i, der)| {
            let (_, cert) =
                X509Certificate::from_der(der).map_err(|e| MdocError::InvalidCertificateChain {
                    reason: format!("failed to parse certificate at chain index {i}: {e}"),
                })?;
            Ok(cert)
        })
        .collect::<Result<_>>()?;

    for i in 0..parsed_chain.len().saturating_sub(1) {
        let subject = &parsed_chain[i];
        let issuer = &parsed_chain[i + 1];

        subject.verify_signature(Some(issuer.public_key())).map_err(|_| {
            MdocError::InvalidCertificateChain {
                reason: format!(
                    "signature of certificate at index {i} does not verify under the next certificate"
                ),
            }
        })?;
    }

    let last = parsed_chain
        .last()
        .expect("chain is non-empty; checked above");

    // Find the specific trusted root that anchors this chain and return its DER bytes.
    // Returning the anchoring root (rather than a boolean) lets callers check per-cert
    // attributes (country code, state) against the one root that actually signed the chain.
    let anchoring_root = trusted_roots
        .iter()
        .find(|root_der| {
            let Ok((_, root_cert)) = X509Certificate::from_der(root_der) else {
                return false;
            };
            // A self-signed root matches if it is structurally equal to the last chain cert
            // (i.e. the chain already ends with the root itself), or if the last cert is
            // signed by this root.
            last.verify_signature(Some(root_cert.public_key())).is_ok()
        })
        .ok_or_else(|| MdocError::InvalidCertificateChain {
            reason: "chain does not terminate at a trusted IACA root".into(),
        })?;

    Ok(anchoring_root.clone())
}

/// Checks that the Document Signer Certificate carries the mandatory Extended Key Usage
/// OID `1.0.18013.5.1.2` (ISO 18013-5 §9.1.2).
///
/// # Errors
///
/// - [`MdocError::MissingDocSignerEku`] — the EKU extension is absent or does not
///   include the required OID.
pub(super) fn check_dsc_eku(dsc: &X509Certificate<'_>) -> Result<()> {
    let has_required_eku = dsc
        .extensions()
        .iter()
        .filter_map(|ext| {
            if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
                Some(eku)
            } else {
                None
            }
        })
        .any(|eku| {
            eku.other
                .iter()
                .any(|oid| oid.to_id_string() == DSC_EKU_OID)
        });

    if !has_required_eku {
        return Err(MdocError::MissingDocSignerEku);
    }

    Ok(())
}

/// Checks that the Document Signer Certificate has the `digitalSignature` key usage bit
/// set (ISO 18013-5 Annex B Table B.3).
///
/// # Errors
///
/// - [`MdocError::MissingDigitalSignatureKeyUsage`] — the Key Usage extension is absent
///   or the `digitalSignature` bit is not set.
pub(super) fn check_dsc_key_usage(dsc: &X509Certificate<'_>) -> Result<()> {
    let digital_signature_set = dsc
        .extensions()
        .iter()
        .find_map(|ext| {
            if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
                Some(ku.digital_signature())
            } else {
                None
            }
        })
        .unwrap_or(false); // absent extension → treat as not set

    if !digital_signature_set {
        return Err(MdocError::MissingDigitalSignatureKeyUsage);
    }

    Ok(())
}

/// Extracts the raw SubjectPublicKeyInfo (SPKI) DER bytes from a parsed certificate.
///
/// The returned bytes are suitable for passing directly to
/// `cloud_wallet_crypto::ecdsa::VerifyingKey::from_spki_der` or
/// `cloud_wallet_crypto::ed25519::VerifyingKey::from_spki_der`.
pub(super) fn extract_spki(dsc: &X509Certificate<'_>) -> Vec<u8> {
    dsc.public_key().raw.to_vec()
}

/// Checks that the Document Signer Certificate validity period does not exceed the
/// 457-day maximum mandated by ISO 18013-5 Annex B Table B.3.
///
/// # Errors
///
/// - [`MdocError::InvalidCertificateChain`] — the validity period exceeds 457 days,
///   or `notAfter` is not strictly after `notBefore` (structurally invalid cert).
pub(super) fn check_dsc_validity_period(dsc: &X509Certificate<'_>) -> Result<()> {
    let not_before = dsc.validity().not_before.timestamp();
    let not_after = dsc.validity().not_after.timestamp();

    // Reject certs with an inverted or zero-length validity window before checking duration.
    if not_after <= not_before {
        return Err(MdocError::InvalidCertificateChain {
            reason: "DSC notAfter is not strictly after notBefore".into(),
        });
    }

    const MAX_VALIDITY_SECS: i64 = 457 * 24 * 60 * 60;
    if not_after - not_before > MAX_VALIDITY_SECS {
        return Err(MdocError::InvalidCertificateChain {
            reason: format!(
                "DSC validity period ({} days) exceeds the 457-day maximum \
                 (ISO 18013-5 Annex B Table B.3)",
                (not_after - not_before) / 86_400
            ),
        });
    }

    Ok(())
}

/// Verifies that the MSO `validityInfo.signed` timestamp falls within the Document
/// Signer Certificate's validity window (ISO 18013-5 §9.3.1 step 5).
///
/// # Errors
///
/// - [`MdocError::SignedOutsideDscValidity`] - `signed_at` is before `notBefore` or
///   after `notAfter`.
pub(super) fn check_signed_within_dsc_validity(
    dsc: &X509Certificate<'_>,
    signed_at: OffsetDateTime,
) -> Result<()> {
    let not_before = dsc.validity().not_before.timestamp();
    let not_after = dsc.validity().not_after.timestamp();
    let signed_ts = signed_at.unix_timestamp();

    if signed_ts < not_before || signed_ts > not_after {
        return Err(MdocError::SignedOutsideDscValidity {
            signed_at: signed_ts,
            not_before,
            not_after,
        });
    }

    Ok(())
}

/// Checks that the Document Signer Certificate subject country code matches the
/// anchoring IACA root certificate subject country code (ISO 18013-5 §9.3.3).
///
/// Accepts the DER of the **specific root that anchored the chain** (returned by
/// [`validate_cert_chain`]) rather than the full trust store.  Checking all roots
/// would incorrectly reject a valid DSC in a multi-country trust store whenever any
/// root from a different country is also present.
///
/// The check is only performed when both the DSC and the anchoring root carry a
/// `CountryName` attribute.  If either party omits the attribute the check is
/// skipped (conservative — absence is not itself an error).
///
/// # Errors
///
/// - [`MdocError::InvalidCertificateChain`] — the anchoring root DER fails to parse.
/// - [`MdocError::CountryMismatch`] — the DSC and the anchoring root both have country
///   codes and they differ.
/// - [`MdocError::StateMismatch`] — the DSC and the anchoring root both have a
///   `stateOrProvinceName` attribute and the values differ (ISO 18013-5 §9.3.3).
pub(super) fn check_country_consistency(
    dsc: &X509Certificate<'_>,
    anchoring_root_der: &[u8],
) -> Result<()> {
    let dsc_country: Option<String> = dsc
        .subject()
        .iter_country()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_owned);

    let dsc_state: Option<String> = dsc
        .subject()
        .iter_state_or_province()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_owned);

    let (_, root) = X509Certificate::from_der(anchoring_root_der).map_err(|e| {
        MdocError::InvalidCertificateChain {
            reason: format!(
                "failed to parse anchoring IACA root for country-consistency check: {e}"
            ),
        }
    })?;

    let iaca_country: Option<String> = root
        .subject()
        .iter_country()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_owned);

    if let (Some(dsc_c), Some(iaca_c)) = (&dsc_country, iaca_country)
        && dsc_c != &iaca_c
    {
        return Err(MdocError::CountryMismatch {
            dsc_country: dsc_c.clone(),
            iaca_country: iaca_c,
        });
    }

    let iaca_state: Option<String> = root
        .subject()
        .iter_state_or_province()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_owned);

    if let (Some(dsc_s), Some(iaca_s)) = (&dsc_state, iaca_state)
        && dsc_s != &iaca_s
    {
        return Err(MdocError::StateMismatch {
            dsc_state: dsc_s.clone(),
            iaca_state: iaca_s,
        });
    }

    Ok(())
}
