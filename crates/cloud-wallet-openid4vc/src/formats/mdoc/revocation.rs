//! DSC revocation checking via CRL (ISO 18013-5 §9.3.3, Annex B §B.2).
//!
//! ISO/IEC 18013-5 §9.3.3 requires verifiers "shall have access to certificate revocation
//! information," and Annex B §B.2 defines a normative CRL profile. This module implements
//! CRL-based revocation checking with configurable policy.
//!
//! # Policy
//!
//! - `Skip`: Bypass revocation checking entirely (offline/test mode)
//! - `SoftFail`: Reject on revoked DSC, but tolerate CRL fetch/parse failures (logged)
//! - `HardFail`: Reject on revoked DSC or on CRL fetch/parse failure

use reqwest::Client;
use std::sync::LazyLock;
use x509_parser::extensions::CRLDistributionPoint;
use x509_parser::prelude::GeneralName;
use x509_parser::prelude::{FromDer, ParsedExtension, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

use super::error::{MdocError, Result};

/// Policy for DSC revocation checking (ISO 18013-5 §9.3.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RevocationPolicy {
    /// Bypass revocation checking entirely.
    ///
    /// Use for offline mode, test environments, or when revocation information
    /// is obtained through out-of-band means.
    Skip,

    /// Reject if DSC is revoked; tolerate CRL fetch/parse failures.
    ///
    /// Logs warnings on CRL fetch/parse errors but does not reject the credential.
    /// Suitable for production where network issues should not block valid credentials.
    #[default]
    SoftFail,

    /// Reject if DSC is revoked OR if CRL fetch/parse fails.
    ///
    /// Strict mode: any failure in revocation checking results in rejection.
    /// Use when revocation checking is mandatory and network access is guaranteed.
    HardFail,
}

/// HTTP client for CRL fetching. Lazily initialized with rustls TLS.
static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("HTTP client with rustls must initialize")
});

/// Extracts the first HTTP/HTTPS CRL Distribution Point URI from a DSC.
///
/// Per ISO 18013-5 Annex B §B.2 and RFC 5280 §4.2.1.13, the CRL Distribution Points
/// extension contains URIs where CRLs can be retrieved. We extract the first HTTP(S) URI.
fn extract_crl_uri(dsc: &X509Certificate<'_>) -> Result<Option<String>> {
    let crl_dp_ext = dsc
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == "2.5.29.31");

    let ext = match crl_dp_ext {
        Some(e) => e,
        None => return Ok(None),
    };

    let parsed = match &ext.parsed_extension() {
        ParsedExtension::CRLDistributionPoints(dp) => dp,
        _ => return Ok(None),
    };

    for point in &parsed.points {
        if let Some(uri) = extract_https_uri_from_distribution_point(point) {
            return Ok(Some(uri));
        }
    }

    Ok(None)
}

/// Extracts the first HTTP/HTTPS URI from a CRL Distribution Point.
fn extract_https_uri_from_distribution_point<'a>(dp: &CRLDistributionPoint<'a>) -> Option<String> {
    let uri_general_names = dp.distribution_point.as_ref()?;
    match uri_general_names {
        x509_parser::extensions::DistributionPointName::FullName(names) => {
            for general_name in names {
                if let GeneralName::URI(uri) = general_name {
                    if uri.starts_with("https://") || uri.starts_with("http://") {
                        return Some(uri.to_string());
                    }
                }
            }
            None
        }
        x509_parser::extensions::DistributionPointName::NameRelativeToCRLIssuer(_) => None,
    }
}

/// Checks whether a DSC is revoked by fetching and checking its CRL.
///
/// # Parameters
///
/// - `dsc`: The parsed Document Signer Certificate.
/// - `anchoring_root_der`: DER bytes of the IACA root that anchors the chain, used to
///   verify the CRL signature.
/// - `policy`: Revocation checking policy.
///
/// # Returns
///
/// - `Ok(())` if the DSC is not revoked (or policy is `Skip`).
/// - `Err(MdocError::CertificateRevoked)` if the DSC serial is on the CRL.
/// - `Err(MdocError::RevocationCheckFailed)` on CRL fetch/parse/validation failure
///   (only for `HardFail` policy).
pub async fn check_revocation(
    dsc: &X509Certificate<'_>,
    anchoring_root_der: &[u8],
    policy: RevocationPolicy,
) -> Result<()> {
    if policy == RevocationPolicy::Skip {
        return Ok(());
    }

    let serial_bytes = dsc.tbs_certificate.serial.to_bytes_be();

    let crl_uri = match extract_crl_uri(dsc)? {
        Some(uri) => uri,
        None => {
            return handle_missing_crl_uri(policy);
        }
    };

    let crl_bytes = match fetch_crl(&crl_uri).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return handle_crl_fetch_error(&crl_uri, e, policy);
        }
    };

    let crl = match parse_and_validate_crl(&crl_bytes, anchoring_root_der) {
        Ok(crl) => crl,
        Err(e) => {
            return handle_crl_parse_error(&crl_uri, e, policy);
        }
    };

    for revoked_cert in crl.iter_revoked_certificates() {
        let revoked_serial = revoked_cert.serial().to_bytes_be();
        if revoked_serial == serial_bytes {
            return Err(MdocError::CertificateRevoked {
                serial: hex_encode_serial(&serial_bytes),
                reason: revoked_cert
                    .reason_code()
                    .map(|r| format!("{:?}", r.1))
                    .unwrap_or_else(|| "unspecified".to_owned()),
            });
        }
    }

    Ok(())
}

/// Handles missing CRL Distribution Point URI.
fn handle_missing_crl_uri(policy: RevocationPolicy) -> Result<()> {
    match policy {
        RevocationPolicy::Skip | RevocationPolicy::SoftFail => {
            tracing::warn!("DSC has no CRL Distribution Point URI; skipping revocation check");
            Ok(())
        }
        RevocationPolicy::HardFail => Err(MdocError::RevocationCheckFailed {
            reason: "DSC has no CRL Distribution Point URI".to_owned(),
        }),
    }
}

/// Handles CRL fetch errors according to policy.
fn handle_crl_fetch_error(
    uri: &str,
    error: reqwest::Error,
    policy: RevocationPolicy,
) -> Result<()> {
    match policy {
        RevocationPolicy::Skip | RevocationPolicy::SoftFail => {
            tracing::warn!(
                "CRL fetch from {} failed: {error}; skipping revocation check",
                uri
            );
            Ok(())
        }
        RevocationPolicy::HardFail => Err(MdocError::RevocationCheckFailed {
            reason: format!("CRL fetch from {} failed: {error}", uri),
        }),
    }
}

/// Handles CRL parse/validation errors according to policy.
fn handle_crl_parse_error(uri: &str, error: MdocError, policy: RevocationPolicy) -> Result<()> {
    match policy {
        RevocationPolicy::Skip | RevocationPolicy::SoftFail => {
            tracing::warn!(
                "CRL parse/validation from {} failed: {error:?}; skipping revocation check",
                uri
            );
            Ok(())
        }
        RevocationPolicy::HardFail => Err(error),
    }
}

/// Fetches CRL bytes from the given HTTP(S) URI.
async fn fetch_crl(uri: &str) -> std::result::Result<Vec<u8>, reqwest::Error> {
    let response = HTTP_CLIENT.get(uri).send().await?;
    let bytes = response.error_for_status()?.bytes().await?;
    Ok(bytes.to_vec())
}

/// Parses a DER-encoded CRL and verifies its signature against the anchoring IACA root.
///
/// Per ISO 18013-5 Annex B §B.2, the CRL must be signed by the issuing CA (IACA or intermediate).
/// We verify against the IACA root for simplicity (single-level chains are typical for mdoc).
fn parse_and_validate_crl<'a>(
    crl_der: &'a [u8],
    iaca_root_der: &[u8],
) -> Result<CertificateRevocationList<'a>> {
    let (_, crl) = CertificateRevocationList::from_der(crl_der).map_err(|e| {
        MdocError::RevocationCheckFailed {
            reason: format!("failed to parse CRL: {e}"),
        }
    })?;

    let (_, root_cert) =
        X509Certificate::from_der(iaca_root_der).map_err(|e| MdocError::RevocationCheckFailed {
            reason: format!("failed to parse IACA root for CRL verification: {e}"),
        })?;

    crl.verify_signature(root_cert.public_key())
        .map_err(|e| MdocError::RevocationCheckFailed {
            reason: format!("CRL signature verification failed: {e}"),
        })?;

    Ok(crl)
}

/// Converts a serial number to a hexadecimal string for error messages.
fn hex_encode_serial(serial: &[u8]) -> String {
    serial.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_policy_default_is_soft_fail() {
        assert_eq!(RevocationPolicy::default(), RevocationPolicy::SoftFail);
    }

    #[test]
    fn hex_encode_serial_produces_uppercase_hex() {
        let serial = vec![0x01, 0x23, 0xAB, 0xCD];
        let hex = hex_encode_serial(&serial);
        assert_eq!(hex, "0123ABCD");
    }
}
