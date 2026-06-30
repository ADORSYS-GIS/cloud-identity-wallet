//! X.509 certificate chain validation helpers for ISO 18013-5 mDoc issuer authentication.
//!
//! This module provides utilities to:
//! - Validate a DER-encoded certificate chain against a set of trusted IACA roots
//!   (RFC 5280, ISO 18013-5 §9.1.2).
//! - Check that a Document Signer Certificate (DSC) carries the mandatory Extended Key
//!   Usage OID `1.0.18013.5.1.2` (ISO 18013-5 §9.1.2).
//! - Check that a DSC carries the mandatory `digitalSignature` Key Usage bit, marked
//!   critical (ISO 18013-5 Annex B Table B.3).
//! - Check that a DSC's EC public key uses a curve on the ISO 18013-5 Table 22
//!   permitted list (NIST P-256, P-384, P-521).
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
use x509_parser::der_parser::{Oid, oid};
use x509_parser::prelude::{FromDer as _, ParsedExtension, X509Certificate};

use super::error::{MdocError, Result};

/// The OID required in the DSC Extended Key Usage extension (ISO 18013-5 §9.1.2).
///
/// Compile-time `Oid` (not a `&str`) so the EKU check compares OIDs directly rather
/// than allocating a `String` per extension entry via `to_id_string()`.
const DSC_EKU_OID: Oid<'static> = oid!(1.0.18013.5.1.2);

/// Top-level SPKI algorithm OID for all EC public keys (`id-ecPublicKey`, RFC 5480).
/// The specific curve is carried in the SPKI algorithm *parameters*, not here.
///
/// Compile-time `Oid` so this is comparable directly against a parsed certificate's
/// algorithm OID without allocating a `String` via `to_id_string()`.
const OID_EC_PUBLIC_KEY: Oid<'static> = oid!(1.2.840.10045.2.1);

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
        .any(|eku| eku.other.iter().any(|oid| oid == &DSC_EKU_OID));

    if !has_required_eku {
        return Err(MdocError::MissingDocSignerEku);
    }

    Ok(())
}

/// Checks that the Document Signer Certificate has the `digitalSignature` key usage bit
/// set **and** that the Key Usage extension is marked critical
/// (ISO 18013-5 Annex B Table B.3).
///
/// # Errors
///
/// - [`MdocError::MissingDigitalSignatureKeyUsage`] — the Key Usage extension is absent
///   or the `digitalSignature` bit is not set.
/// - [`MdocError::NonCriticalKeyUsage`] — the `digitalSignature` bit is set but the
///   extension is not marked critical.
pub(super) fn check_dsc_key_usage(dsc: &X509Certificate<'_>) -> Result<()> {
    // Collect both the bit value and the criticality flag in one pass.
    let key_usage_ext = dsc.extensions().iter().find_map(|ext| {
        if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
            Some((ku.digital_signature(), ext.critical))
        } else {
            None
        }
    });

    match key_usage_ext {
        // Extension absent or digitalSignature bit not set.
        None | Some((false, _)) => Err(MdocError::MissingDigitalSignatureKeyUsage),
        // Bit set but extension is non-critical — distinct violation per Annex B Table B.3.
        Some((true, false)) => Err(MdocError::NonCriticalKeyUsage),
        // Bit set and extension is critical — compliant.
        Some((true, true)) => Ok(()),
    }
}

/// Rejects a Document Signer Certificate whose EC public key is not on an ISO 18013-5
/// Table 22 permitted curve (NIST P-256, P-384, or P-521).
///
/// Only applies to EC keys (SPKI algorithm OID `id-ecPublicKey`); any other SPKI
/// algorithm OID passes through unchecked, since "curve" only has meaning for EC keys.
/// ISO 18013-5 Table 22 itself only enumerates permitted *curves* (the NIST triad here,
/// plus Brainpool — see note below), not algorithms in general, so there is nothing in
/// Table 22 for a non-EC key to be checked against in the first place.
///
/// This notably includes Ed25519 and Ed448, both OKP keys: their SPKI algorithm OID is
/// never `id-ecPublicKey`, so neither carries a `parameters` field to check here, and
/// the curve restriction simply does not apply to them. Ed25519 is supported by this
/// implementation; Ed448 rejection is handled separately by the OID guard in
/// `verify_issuer_signature`. A non-EC, non-OKP SPKI (e.g. RSA) is left for
/// `dispatch_verify` to reject when it fails to construct a verifying key from it.
///
/// Closes the gap where a non-permitted EC curve (e.g. secp256k1) that the underlying
/// ECDSA verification table happens to define for an unrelated hash combination would
/// otherwise verify successfully under an algorithm identifier that claims a different
/// curve (e.g. ESP256/-9, which RFC 9864 defines as P-256-specifically). Rejecting the
/// curve once here, at chain-validation time, closes it for every algorithm at once
/// rather than requiring a per-algorithm curve check in `dispatch_verify`.
///
/// Curve OIDs are resolved via [`cloud_wallet_crypto::ecdsa::Curve::from_oid`] rather
/// than a locally-hardcoded OID list, so this check and the crypto layer's notion of
/// "which curve does this OID mean" can never silently diverge. secp256k1
/// (`Curve::P256K1`) is recognized by that lookup — it's a curve the crypto crate
/// supports for other purposes — but is deliberately excluded from the permitted set
/// here, since the ISO 18013-5 policy decision ("which curves may a DSC use") belongs
/// to this module, not to the crypto crate.
///
/// **Note on Brainpool:** `Curve::from_oid` does not recognize Brainpool curve OIDs
/// (the crypto crate has no `Curve` variant for them yet), so a DSC carrying a
/// Brainpool key is rejected *here*, with [`MdocError::UnsupportedDscCurve`] — not
/// later in `dispatch_verify`, which would otherwise reject it with
/// `MdocError::UnsupportedAlgorithm` once it inspected the alg header. This is a
/// behavioral side effect of this function's existence: Brainpool rejection now
/// happens earlier and under a different error variant than before, regardless of
/// what algorithm the credential's protected header claims. Any caller matching on
/// `UnsupportedAlgorithm` specifically for Brainpool DSCs needs to also handle
/// `UnsupportedDscCurve`. Add a `Curve` variant (and update this allow-list) once
/// Brainpool *verification* lands in `dispatch_verify` — see that function's TODO.
///
/// # Errors
///
/// - [`MdocError::UnsupportedDscCurve`] — the SPKI is an EC key whose curve is not
///   P-256, P-384, or P-521, or the curve OID is missing/malformed. This includes
///   Brainpool-keyed DSCs (see note above).
pub(super) fn check_dsc_curve(dsc: &X509Certificate<'_>) -> Result<()> {
    use cloud_wallet_crypto::ecdsa::Curve;

    let algorithm = &dsc.public_key().algorithm;

    if algorithm.algorithm != OID_EC_PUBLIC_KEY {
        // Not an EC key (e.g. Ed25519/Ed448 OKP keys) — no curve to restrict here.
        return Ok(());
    }

    let curve_oid = algorithm
        .parameters
        .as_ref()
        .and_then(|params| Oid::try_from(params).ok());

    match curve_oid {
        Some(oid)
            if matches!(
                Curve::from_oid(&oid.to_id_string()),
                Some(Curve::P256 | Curve::P384 | Curve::P521)
            ) =>
        {
            Ok(())
        }
        Some(oid) => Err(MdocError::UnsupportedDscCurve {
            curve: oid.to_id_string(),
        }),
        None => Err(MdocError::UnsupportedDscCurve {
            curve: "missing or malformed EC curve parameters".to_owned(),
        }),
    }
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
