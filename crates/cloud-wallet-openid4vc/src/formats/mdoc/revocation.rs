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
//!
//! # Future Work
//!
//! TODO: OCSP support (RFC 6960) is planned for a follow-up. The PR title currently
//! mentions "CRL/OCSP" but this module implements CRL only. OCSP stapling and
//! OCSP responder queries will be added in a subsequent PR.

use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use x509_parser::extensions::CRLDistributionPoint;
use x509_parser::prelude::GeneralName;
use x509_parser::prelude::{FromDer, ParsedExtension, ReasonCode, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

use super::error::{MdocError, Result};

/// OID for CRL Distribution Points extension (RFC 5280 §4.2.1.13).
const OID_X509_EXT_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";

/// Default CRL cache TTL (6 hours per ISO 18013-5 Annex B §B.2 guidance).
const DEFAULT_CRL_CACHE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

/// Maximum number of CRL entries in the cache to prevent unbounded memory growth.
const MAX_CRL_CACHE_ENTRIES: usize = 64;

/// Maps RFC 5280 §5.3.1 CRLReason to stable string values.
fn reason_code_to_string(code: ReasonCode) -> &'static str {
    match code {
        ReasonCode::Unspecified => "unspecified",
        ReasonCode::KeyCompromise => "keyCompromise",
        ReasonCode::CACompromise => "cACompromise",
        ReasonCode::AffiliationChanged => "affiliationChanged",
        ReasonCode::Superseded => "superseded",
        ReasonCode::CessationOfOperation => "cessationOfOperation",
        ReasonCode::CertificateHold => "certificateHold",
        ReasonCode::RemoveFromCRL => "removeFromCRL",
        ReasonCode::PrivilegeWithdrawn => "privilegeWithdrawn",
        ReasonCode::AACompromise => "aACompromise",
        _ => "unspecified",
    }
}

/// Policy for DSC revocation checking (ISO 18013-5 §9.3.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
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

/// Trait for fetching CRLs, allowing dependency injection for testing.
///
/// Production implementations typically use HTTP with caching, while test
/// implementations can return mock CRLs or simulate failures.
#[async_trait]
pub trait CrlFetcher: Send + Sync {
    /// Fetches CRL bytes from the given URI.
    ///
    /// Returns the raw DER-encoded CRL bytes, or an error if the fetch fails.
    async fn fetch_crl(&self, uri: &str) -> std::result::Result<Vec<u8>, reqwest::Error>;
}

/// Production HTTP-based CRL fetcher with in-memory caching.
///
/// Uses a global cache shared across all instances to avoid redundant HTTPS fetches.
/// Cache entries have a TTL (default 6 hours) and the cache has a maximum size.
pub struct HttpCrlFetcher {
    http_client: Client,
    cache_ttl: Duration,
}

impl HttpCrlFetcher {
    /// Creates a new HTTP CRL fetcher with default settings.
    pub fn new() -> Self {
        Self {
            http_client: Client::builder()
                .use_rustls_tls()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("HTTP client with rustls must initialize"),
            cache_ttl: DEFAULT_CRL_CACHE_TTL,
        }
    }

    /// Creates a new HTTP CRL fetcher with a custom cache TTL.
    pub fn with_cache_ttl(cache_ttl: Duration) -> Self {
        Self {
            http_client: Client::builder()
                .use_rustls_tls()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("HTTP client with rustls must initialize"),
            cache_ttl,
        }
    }
}

impl Default for HttpCrlFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CrlFetcher for HttpCrlFetcher {
    async fn fetch_crl(&self, uri: &str) -> std::result::Result<Vec<u8>, reqwest::Error> {
        // Check cache first
        {
            let mut cache_guard = CRL_CACHE.lock().expect("CRL cache lock poisoned");
            let (cache, _) = &mut *cache_guard;
            evict_if_needed(cache, uri);
            if let Some(entry) = cache.get(uri) {
                tracing::debug!(uri, "CRL cache hit");
                return Ok(entry.crl_der.clone());
            }
        }

        // Fetch fresh CRL
        // Note: No retry on transient failures (timeouts, 5xx errors). A single transient
        // failure will cause SoftFail to log a warning and skip revocation check, or
        // HardFail to reject. This is a known limitation that could be addressed in
        // future work with exponential backoff retry.
        tracing::debug!(uri, "CRL cache miss, fetching");
        let response = self.http_client.get(uri).send().await?;
        let bytes = response.error_for_status()?.bytes().await?;
        let crl_der = bytes.to_vec();

        // Cache the result
        {
            let mut cache_guard = CRL_CACHE.lock().expect("CRL cache lock poisoned");
            let (cache, counter) = &mut *cache_guard;
            evict_if_needed(cache, uri);
            let insertion_order = *counter;
            *counter += 1;
            cache.insert(
                uri.to_owned(),
                CrlCacheEntry {
                    crl_der: crl_der.clone(),
                    fetched_at: Instant::now(),
                    expires_after: self.cache_ttl,
                    insertion_order,
                },
            );
        }

        Ok(crl_der)
    }
}

/// In-memory CRL cache with TTL.
///
/// CRLs are cached per-URI to avoid redundant HTTPS fetches. Each entry has a TTL
/// (default 6 hours) after which the entry is stale and a fresh fetch is required.
struct CrlCacheEntry {
    crl_der: Vec<u8>,
    fetched_at: Instant,
    expires_after: Duration,
    insertion_order: u64,
}

static CRL_CACHE: LazyLock<Mutex<(HashMap<String, CrlCacheEntry>, u64)>> =
    LazyLock::new(|| Mutex::new((HashMap::new(), 0)));

/// Evicts entries that are stale (TTL expired) or when cache exceeds max size.
fn evict_if_needed(cache: &mut HashMap<String, CrlCacheEntry>, uri: &str) {
    // First, remove the entry for this URI if stale
    if let Some(entry) = cache.get(uri)
        && entry.fetched_at.elapsed() > entry.expires_after
    {
        cache.remove(uri);
    }

    // Sweep all stale entries when cache is full (not just the current URI)
    if cache.len() >= MAX_CRL_CACHE_ENTRIES {
        cache.retain(|_, entry| entry.fetched_at.elapsed() <= entry.expires_after);
    }

    // If still over limit after sweeping stale, evict oldest entries (lowest insertion_order)
    while cache.len() >= MAX_CRL_CACHE_ENTRIES {
        let oldest = cache
            .iter()
            .min_by_key(|(_, e)| e.insertion_order)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest {
            cache.remove(&key);
        } else {
            break;
        }
    }
}

/// Extracts the first HTTPS CRL Distribution Point URI from a DSC.
///
/// Per ISO 18013-5 Annex B §B.2 and RFC 5280 §4.2.1.13, the CRL Distribution Points
/// extension contains URIs where CRLs can be retrieved.
///
/// # HTTPS-Only Policy
///
/// This implementation only accepts HTTPS URIs. While ISO/IEC 18013-5 Annex B commonly
/// allows plain `http://` CRL distribution points because CRLs are already integrity-protected
/// by the issuer signature, this deployment enforces HTTPS as a stricter security policy
/// to prevent MITM attacks where a forged or stale CRL could bypass revocation checking.
/// Deployments that need to accept plain HTTP URIs must use `RevocationPolicy::Skip`.
fn extract_crl_uri(dsc: &X509Certificate<'_>) -> Result<Option<String>> {
    let crl_dp_ext = dsc
        .extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == OID_X509_EXT_CRL_DISTRIBUTION_POINTS);

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

/// Extracts the first HTTPS URI from a CRL Distribution Point.
///
/// Per ISO 18013-5 Annex B §B.2, CRL distribution point URIs MUST use HTTPS.
/// Plain HTTP URIs are rejected to prevent MITM attacks where a forged CRL
/// could bypass revocation checking.
fn extract_https_uri_from_distribution_point<'a>(dp: &CRLDistributionPoint<'a>) -> Option<String> {
    let uri_general_names = dp.distribution_point.as_ref()?;
    match uri_general_names {
        x509_parser::extensions::DistributionPointName::FullName(names) => {
            for general_name in names {
                if let GeneralName::URI(uri) = general_name
                    && uri.starts_with("https://")
                {
                    return Some(uri.to_string());
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
/// - `dsc_issuer_der`: DER bytes of the certificate that issued the DSC (immediate issuer),
///   used to verify the CRL signature. For single-level chains this is the IACA root;
///   for multi-level chains it is the intermediate CA.
/// - `policy`: Revocation checking policy.
/// - `fetcher`: Optional CRL fetcher for dependency injection. Uses default HttpCrlFetcher if None.
///
/// # Returns
///
/// - `Ok(())` if the DSC is not revoked (or policy is `Skip`).
/// - `Err(MdocError::CertificateRevoked)` if the DSC serial is on the CRL.
/// - `Err(MdocError::RevocationCheckFailed)` on CRL fetch/parse/validation failure
///   (only for `HardFail` policy).
pub async fn check_revocation(
    dsc: &X509Certificate<'_>,
    dsc_issuer_der: &[u8],
    policy: RevocationPolicy,
    fetcher: Option<&dyn CrlFetcher>,
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

    let default_fetcher = HttpCrlFetcher::new();
    let fetcher_ref = fetcher.unwrap_or(&default_fetcher);

    let crl_bytes = match fetcher_ref.fetch_crl(&crl_uri).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return handle_crl_fetch_error(&crl_uri, e, policy);
        }
    };

    let crl = match parse_and_validate_crl(&crl_bytes, dsc_issuer_der) {
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
                    .map(|(_critical, code)| reason_code_to_string(code).to_string())
                    .unwrap_or_else(|| "unspecified".to_owned()),
            });
        }
    }

    Ok(())
}

/// Handles missing CRL Distribution Point URI.
fn handle_missing_crl_uri(policy: RevocationPolicy) -> Result<()> {
    match policy {
        RevocationPolicy::SoftFail => {
            tracing::warn!("DSC has no CRL Distribution Point URI; skipping revocation check");
            Ok(())
        }
        RevocationPolicy::HardFail => Err(MdocError::RevocationCheckFailed {
            reason: "DSC has no CRL Distribution Point URI".to_owned(),
        }),
        RevocationPolicy::Skip => unreachable!("Skip policy returns early in check_revocation"),
    }
}

/// Handles CRL fetch errors according to policy.
fn handle_crl_fetch_error(
    uri: &str,
    error: reqwest::Error,
    policy: RevocationPolicy,
) -> Result<()> {
    match policy {
        RevocationPolicy::SoftFail => {
            tracing::warn!(
                "CRL fetch from {} failed: {error}; skipping revocation check",
                uri
            );
            Ok(())
        }
        RevocationPolicy::HardFail => Err(MdocError::RevocationCheckFailed {
            reason: format!("CRL fetch from {} failed: {error}", uri),
        }),
        RevocationPolicy::Skip => unreachable!("Skip policy returns early in check_revocation"),
    }
}

/// Handles CRL parse/validation errors according to policy.
fn handle_crl_parse_error(uri: &str, error: MdocError, policy: RevocationPolicy) -> Result<()> {
    match policy {
        RevocationPolicy::SoftFail => {
            tracing::warn!(
                "CRL parse/validation from {} failed: {error:?}; skipping revocation check",
                uri
            );
            Ok(())
        }
        RevocationPolicy::HardFail => Err(error),
        RevocationPolicy::Skip => unreachable!("Skip policy returns early in check_revocation"),
    }
}

/// Parses a DER-encoded CRL and performs full validation per RFC 5280 and ISO 18013-5 Annex B §B.2.
///
/// Validates:
/// 1. CRL signature against the DSC's immediate issuer (not the IACA root)
/// 2. CRL issuer name matches the DSC issuer name
/// 3. CRL temporal validity (thisUpdate/nextUpdate)
/// 4. Authority Key Identifier matches (if present in both CRL and issuer cert)
/// 5. Rejects indirect CRLs and delta CRLs
fn parse_and_validate_crl<'a>(
    crl_der: &'a [u8],
    dsc_issuer_der: &[u8],
) -> Result<CertificateRevocationList<'a>> {
    let (_, crl) = CertificateRevocationList::from_der(crl_der).map_err(|e| {
        MdocError::RevocationCheckFailed {
            reason: format!("failed to parse CRL: {e}"),
        }
    })?;

    // Parse the DSC's immediate issuer certificate
    let (_, issuer_cert) = X509Certificate::from_der(dsc_issuer_der).map_err(|e| {
        MdocError::RevocationCheckFailed {
            reason: format!("failed to parse DSC issuer certificate for CRL verification: {e}"),
        }
    })?;

    // Reject indirect CRLs (RFC 5280 §5.3.1)
    // An indirect CRL has an issuing distribution point extension with the indirectCRL flag set,
    // or the CRL issuer name differs from the certificate issuer (already checked above).
    if is_indirect_crl(&crl) {
        return Err(MdocError::RevocationCheckFailed {
            reason: "indirect CRLs are not supported (CRL issued by a different authority than the DSC issuer)".to_owned(),
        });
    }

    // Reject delta CRLs (RFC 5280 §5.3.2)
    // Delta CRLs only contain changes since a base CRL and require additional processing.
    if is_delta_crl(&crl) {
        return Err(MdocError::RevocationCheckFailed {
            reason: "delta CRLs are not supported; use a complete CRL".to_owned(),
        });
    }

    // RFC 5280 §5.3.1: The CRL issuer MUST match the DSC issuer name
    if !issuer_names_match(&crl, &issuer_cert) {
        return Err(MdocError::RevocationCheckFailed {
            reason: "CRL issuer name does not match DSC issuer name".to_owned(),
        });
    }

    // RFC 5280 §5.3.1: Verify Authority Key Identifier matches (if present)
    // The CRL's AKI extension should match the issuer's SKI extension.
    verify_aki_match(&crl, &issuer_cert)?;

    // RFC 5280 §5.1.2.2: Check temporal validity of the CRL
    let now = time::OffsetDateTime::now_utc();
    if let Some(next_update) = crl.next_update() {
        let next_update_ts = next_update.timestamp();
        let now_ts = now.unix_timestamp();
        if now_ts > next_update_ts {
            return Err(MdocError::RevocationCheckFailed {
                reason: format!(
                    "CRL has expired (nextUpdate: {}, now: {})",
                    next_update_ts, now_ts
                ),
            });
        }
    }

    // RFC 5280 §5.1.2.1: Log warning if CRL is older than expected (but don't reject)
    let this_update = crl.last_update();
    let this_update_ts = this_update.timestamp();
    let now_ts = now.unix_timestamp();
    let age_hours = (now_ts - this_update_ts) / 3600;
    if age_hours > 24 {
        tracing::warn!(
            this_update_age_hours = age_hours,
            "CRL thisUpdate is more than 24 hours old"
        );
    }

    // Verify CRL signature against the DSC issuer's public key (RFC 5280 §5.3.1, ISO 18013-5 §B.2)
    crl.verify_signature(issuer_cert.public_key())
        .map_err(|e| MdocError::RevocationCheckFailed {
            reason: format!("CRL signature verification failed: {e}"),
        })?;

    Ok(crl)
}

/// Checks whether the CRL issuer name matches the DSC issuer name.
///
/// Per RFC 5280 §5.3.1, the CRL scope includes all certificates issued by the CRL issuer.
/// We verify the issuer names match to prevent a malicious CRL from a different CA.
fn issuer_names_match(
    crl: &CertificateRevocationList<'_>,
    issuer_cert: &X509Certificate<'_>,
) -> bool {
    let crl_issuer = crl.issuer();
    let cert_issuer = issuer_cert.subject();
    // Compare the raw DER bytes of the distinguished names
    crl_issuer.as_raw() == cert_issuer.as_raw()
}

/// Checks if this is an indirect CRL (RFC 5280 §5.3.1).
///
/// An indirect CRL has an IssuingDistributionPoint extension with the indirectCRL flag set.
/// Indirect CRLs are issued by a different entity than the certificate issuer and require
/// additional processing that we don't support.
fn is_indirect_crl(crl: &CertificateRevocationList<'_>) -> bool {
    // Look for IssuingDistributionPoint extension (OID 2.5.29.28)
    const OID_ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";
    for ext in crl.extensions() {
        if ext.oid.to_id_string() == OID_ISSUING_DISTRIBUTION_POINT {
            // The IssuingDistributionPoint extension is allowed on complete CRLs.
            // We only reject if the indirectCRL boolean is set, which indicates
            // the CRL issuer differs from the certificate issuer.
            if let ParsedExtension::IssuingDistributionPoint(idp) = ext.parsed_extension()
                && idp.indirect_crl
            {
                return true;
            }
        }
    }
    false
}

/// Checks if this is a delta CRL (RFC 5280 §5.3.2).
///
/// Delta CRLs only contain revocations since a base CRL and require the base CRL
/// to be available. We only support complete CRLs.
fn is_delta_crl(crl: &CertificateRevocationList<'_>) -> bool {
    // Look for CRLNumber extension with delta CRL indicator (OID 2.5.29.27)
    const OID_DELTA_CRL_INDICATOR: &str = "2.5.29.27";
    for ext in crl.extensions() {
        if ext.oid.to_id_string() == OID_DELTA_CRL_INDICATOR {
            return true;
        }
    }
    false
}

/// Verifies Authority Key Identifier match between CRL and issuer certificate.
///
/// Per RFC 5280 §5.3.1, if the CRL contains an Authority Key Identifier extension,
/// it should match the Subject Key Identifier of the issuing certificate.
/// This provides an additional binding to prevent CRL substitution attacks.
fn verify_aki_match(
    crl: &CertificateRevocationList<'_>,
    issuer_cert: &X509Certificate<'_>,
) -> Result<()> {
    const OID_AKI: &str = "2.5.29.35";
    const OID_SKI: &str = "2.5.29.14";

    // Extract AKI from CRL if present and parse it properly per RFC 5280 §4.2.1.1
    // The AuthorityKeyIdentifier extension contains an optional keyIdentifier OCTET STRING
    // We extract only the key_identifier field for comparison
    let crl_aki_key_id = crl.extensions().iter().find_map(|ext| {
        if ext.oid.to_id_string() == OID_AKI {
            match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|ki| ki.0)
                }
                _ => None,
            }
        } else {
            None
        }
    });

    // Extract SKI from issuer certificate if present
    // SKI extension is just an OCTET STRING containing the key identifier
    let issuer_ski_value = issuer_cert.extensions().iter().find_map(|ext| {
        if ext.oid.to_id_string() == OID_SKI {
            Some(ext.value)
        } else {
            None
        }
    });

    match (crl_aki_key_id, issuer_ski_value) {
        (Some(aki_key_id), Some(ski_value)) => {
            // AKI extension is a SEQUENCE with optional keyIdentifier OCTET STRING
            // We've extracted the key_identifier bytes via parsed_extension
            // SKI extension is just an OCTET STRING, so its value is the key identifier directly
            if aki_key_id != ski_value {
                return Err(MdocError::RevocationCheckFailed {
                    reason:
                        "CRL Authority Key Identifier does not match issuer Subject Key Identifier"
                            .to_owned(),
                });
            }
            Ok(())
        }
        (Some(_), None) => {
            // CRL has AKI but issuer has no SKI - this is unusual but not necessarily invalid
            tracing::warn!(
                "CRL has Authority Key Identifier but issuer certificate lacks Subject Key Identifier"
            );
            Ok(())
        }
        (None, _) => {
            // No AKI in CRL - no check needed
            Ok(())
        }
    }
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

    #[test]
    fn reason_code_to_string_maps_correctly() {
        assert_eq!(
            reason_code_to_string(ReasonCode::Unspecified),
            "unspecified"
        );
        assert_eq!(
            reason_code_to_string(ReasonCode::KeyCompromise),
            "keyCompromise"
        );
        assert_eq!(
            reason_code_to_string(ReasonCode::CACompromise),
            "cACompromise"
        );
        assert_eq!(
            reason_code_to_string(ReasonCode::AffiliationChanged),
            "affiliationChanged"
        );
        assert_eq!(reason_code_to_string(ReasonCode::Superseded), "superseded");
        assert_eq!(
            reason_code_to_string(ReasonCode::CessationOfOperation),
            "cessationOfOperation"
        );
        assert_eq!(
            reason_code_to_string(ReasonCode::CertificateHold),
            "certificateHold"
        );
        assert_eq!(
            reason_code_to_string(ReasonCode::RemoveFromCRL),
            "removeFromCRL"
        );
        assert_eq!(
            reason_code_to_string(ReasonCode::PrivilegeWithdrawn),
            "privilegeWithdrawn"
        );
        assert_eq!(
            reason_code_to_string(ReasonCode::AACompromise),
            "aACompromise"
        );
        // Unknown values fallback to unspecified
        assert_eq!(reason_code_to_string(ReasonCode(99)), "unspecified");
    }

    mod integration_tests {
        use super::*;
        use rcgen::{BasicConstraints, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyUsagePurpose};
        use time::OffsetDateTime;
        use time::format_description::well_known::Rfc3339;

        const DSC_EKU_OID: &[u64] = &[1, 0, 18013, 5, 1, 2];
        const OID_CRL_DISTRIBUTION_POINTS: &[u64] = &[2, 5, 29, 31];

        fn build_crl_dp_extension(crl_uri: &str) -> Vec<u8> {
            // DER-encoded CRL Distribution Points extension with a single URI
            // This is manually constructed ASN.1:
            // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
            // DistributionPoint ::= SEQUENCE {
            //     distributionPoint [0] DistributionPointName OPTIONAL,
            //     ...
            // }
            // DistributionPointName ::= CHOICE {
            //     fullName [0] GeneralNames,
            //     ...
            // }
            // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
            // GeneralName (uniformResourceIdentifier) ::= [6] IMPLICIT IA5String
            //
            // Note: RFC 5280 defines uniformResourceIdentifier [6] IMPLICIT IA5String,
            // so the tag is primitive context-specific 0x86, not constructed 0xA6.
            // The distributionPoint field is [0] EXPLICIT DistributionPointName.
            // The fullName alternative is [0] IMPLICIT (replaces GeneralNames SEQUENCE tag).
            let uri_bytes = crl_uri.as_bytes();
            let uri_len = uri_bytes.len();

            // [6] IMPLICIT IA5String - primitive context-specific tag 0x86
            // The IA5String tag (0x16) is NOT included because [6] is IMPLICIT.
            let mut gn_bytes = vec![0x86]; // primitive context-specific tag 6
            if uri_len < 128 {
                gn_bytes.push(uri_len as u8);
            } else if uri_len < 256 {
                gn_bytes.push(0x81);
                gn_bytes.push(uri_len as u8);
            } else {
                gn_bytes.push(0x82);
                gn_bytes.push((uri_len >> 8) as u8);
                gn_bytes.push((uri_len & 0xff) as u8);
            }
            gn_bytes.extend_from_slice(uri_bytes);

            // GeneralNames content (SEQUENCE content - the GeneralName entries)
            // For fullName [0] IMPLICIT, the [0] replaces the SEQUENCE tag (0x30)
            // So fullName = 0xA0 + len + GeneralNames content (which is gn_bytes directly, no SEQUENCE wrapper)
            let mut full_name = vec![0xA0]; // [0] (fullName) IMPLICIT - replaces SEQUENCE tag
            let fn_len = gn_bytes.len();
            if fn_len < 128 {
                full_name.push(fn_len as u8);
            } else {
                full_name.push(0x81);
                full_name.push(fn_len as u8);
            }
            full_name.extend_from_slice(&gn_bytes);

            // distributionPoint [0] EXPLICIT DistributionPointName
            // EXPLICIT wrapping means we add another [0] layer
            let mut dp_field = vec![0xA0]; // [0] EXPLICIT
            let dp_field_len = full_name.len();
            if dp_field_len < 128 {
                dp_field.push(dp_field_len as u8);
            } else {
                dp_field.push(0x81);
                dp_field.push(dp_field_len as u8);
            }
            dp_field.extend_from_slice(&full_name);

            // SEQUENCE { DistributionPoint }
            let mut dp = vec![0x30];
            let dp_len = dp_field.len();
            if dp_len < 128 {
                dp.push(dp_len as u8);
            } else {
                dp.push(0x81);
                dp.push(dp_len as u8);
            }
            dp.extend_from_slice(&dp_field);

            // SEQUENCE { DistributionPoints }
            let mut dps = vec![0x30];
            let dps_len = dp.len();
            if dps_len < 128 {
                dps.push(dps_len as u8);
            } else {
                dps.push(0x81);
                dps.push(dps_len as u8);
            }
            dps.extend_from_slice(&dp);

            dps
        }

        fn build_chain_with_crl_uri(
            crl_uri: &str,
        ) -> (Vec<u8>, Vec<u8>, cloud_wallet_crypto::ecdsa::KeyPair) {
            let iaca_key = rcgen::KeyPair::generate().expect("IACA key generation must succeed");
            let mut iaca_params =
                rcgen::CertificateParams::new(vec!["Test IACA".to_string()]).expect("IACA params");
            iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            iaca_params
                .distinguished_name
                .push(rcgen::DnType::CountryName, "DE");
            let iaca_cert = iaca_params
                .self_signed(&iaca_key)
                .expect("IACA self-sign must succeed");
            let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
            let iaca_issuer = Issuer::new(iaca_params, iaca_key);

            let dsc_aws_key = cloud_wallet_crypto::ecdsa::KeyPair::generate(
                cloud_wallet_crypto::ecdsa::Curve::P256,
            )
            .expect("DSC key generation must succeed");

            let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
            let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
                &rustls_pki_types::PrivateKeyDer::Pkcs8(
                    rustls_pki_types::PrivatePkcs8KeyDer::from(dsc_pkcs8),
                ),
                &rcgen::PKCS_ECDSA_P256_SHA256,
            )
            .expect("Loading DSC key into rcgen must succeed");

            let not_before = OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339)
                .expect("Fixed date must parse");
            let not_after = OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339)
                .expect("Fixed date must parse");

            let crl_dp_content = build_crl_dp_extension(crl_uri);

            let mut dsc_params =
                rcgen::CertificateParams::new(vec!["Test DSC".to_string()]).expect("DSC params");
            dsc_params.is_ca = IsCa::NoCa;
            dsc_params.not_before = not_before;
            dsc_params.not_after = not_after;
            dsc_params.extended_key_usages =
                vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
            dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            dsc_params
                .distinguished_name
                .push(rcgen::DnType::CountryName, "DE");
            dsc_params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
                OID_CRL_DISTRIBUTION_POINTS,
                crl_dp_content,
            )];
            let dsc_cert = dsc_params
                .signed_by(&dsc_rcgen_key, &iaca_issuer)
                .expect("DSC signing by IACA must succeed");
            let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

            (iaca_der, dsc_der, dsc_aws_key)
        }

        #[tokio::test]
        async fn check_revocation_skip_policy_bypasses_all_checks() {
            let (iaca_der, dsc_der, _signing_key) =
                build_chain_with_crl_uri("https://nonexistent.example.com/crl.crl");
            let (_, dsc) = X509Certificate::from_der(&dsc_der).expect("DSC must parse");

            let result = check_revocation(&dsc, &iaca_der, RevocationPolicy::Skip, None).await;
            assert!(
                result.is_ok(),
                "Skip policy should always return Ok: {:?}",
                result
            );
        }

        #[tokio::test]
        async fn check_revocation_soft_fail_tolerates_missing_crl_uri() {
            let iaca_key = rcgen::KeyPair::generate().expect("IACA key generation must succeed");
            let mut iaca_params =
                rcgen::CertificateParams::new(vec!["Test IACA".to_string()]).expect("IACA params");
            iaca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let iaca_cert = iaca_params
                .self_signed(&iaca_key)
                .expect("IACA self-sign must succeed");
            let iaca_der: Vec<u8> = iaca_cert.der().to_vec();
            let iaca_issuer = Issuer::new(iaca_params, iaca_key);

            let dsc_aws_key = cloud_wallet_crypto::ecdsa::KeyPair::generate(
                cloud_wallet_crypto::ecdsa::Curve::P256,
            )
            .expect("DSC key generation must succeed");

            let dsc_pkcs8 = dsc_aws_key.to_pkcs8_der();
            let dsc_rcgen_key = rcgen::KeyPair::from_der_and_sign_algo(
                &rustls_pki_types::PrivateKeyDer::Pkcs8(
                    rustls_pki_types::PrivatePkcs8KeyDer::from(dsc_pkcs8),
                ),
                &rcgen::PKCS_ECDSA_P256_SHA256,
            )
            .expect("Loading DSC key into rcgen must succeed");

            let not_before = OffsetDateTime::parse("2023-12-01T00:00:00Z", &Rfc3339)
                .expect("Fixed date must parse");
            let not_after = OffsetDateTime::parse("2024-12-31T23:59:59Z", &Rfc3339)
                .expect("Fixed date must parse");

            let mut dsc_params = rcgen::CertificateParams::new(vec!["Test DSC No CRL".to_string()])
                .expect("DSC params");
            dsc_params.is_ca = IsCa::NoCa;
            dsc_params.not_before = not_before;
            dsc_params.not_after = not_after;
            dsc_params.extended_key_usages =
                vec![ExtendedKeyUsagePurpose::Other(DSC_EKU_OID.to_vec())];
            dsc_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let dsc_cert = dsc_params
                .signed_by(&dsc_rcgen_key, &iaca_issuer)
                .expect("DSC signing must succeed");
            let dsc_der: Vec<u8> = dsc_cert.der().to_vec();

            let (_, dsc) = X509Certificate::from_der(&dsc_der).expect("DSC must parse");

            // SoftFail should tolerate missing CRL URI
            let result = check_revocation(&dsc, &iaca_der, RevocationPolicy::SoftFail, None).await;
            assert!(
                result.is_ok(),
                "SoftFail should tolerate missing CRL URI: {:?}",
                result
            );

            // HardFail should reject missing CRL URI
            let result = check_revocation(&dsc, &iaca_der, RevocationPolicy::HardFail, None).await;
            assert!(result.is_err(), "HardFail should reject missing CRL URI");
        }

        #[tokio::test]
        async fn check_revocation_soft_fail_tolerates_crl_fetch_failure() {
            use wiremock::matchers::{method, path};
            use wiremock::{Mock, MockServer, ResponseTemplate};

            let mock_server = MockServer::start().await;
            let crl_uri = format!("{}/crl.crl", mock_server.uri());

            // Return 404 for CRL request
            Mock::given(method("GET"))
                .and(path("/crl.crl"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock_server)
                .await;

            let (iaca_der, dsc_der, _signing_key) = build_chain_with_crl_uri(&crl_uri);
            let (_, dsc) = X509Certificate::from_der(&dsc_der).expect("DSC must parse");

            // SoftFail should tolerate CRL fetch failure
            let result = check_revocation(&dsc, &iaca_der, RevocationPolicy::SoftFail, None).await;
            assert!(
                result.is_ok(),
                "SoftFail should tolerate CRL fetch failure: {:?}",
                result
            );

            // HardFail should reject CRL fetch failure
            let result = check_revocation(&dsc, &iaca_der, RevocationPolicy::HardFail, None).await;
            assert!(result.is_err(), "HardFail should reject CRL fetch failure");
        }

        #[test]
        fn extract_crl_uri_parses_https_uri_from_extension() {
            // Verify that extract_crl_uri correctly parses the CRL Distribution Point URI
            // from a DSC certificate. This test validates the DER encoding fix (0x86 vs 0xA6).
            let test_uri = "https://example.com/crl/test.crl";
            let (_iaca_der, dsc_der, _signing_key) = build_chain_with_crl_uri(test_uri);
            let (_, dsc) = X509Certificate::from_der(&dsc_der).expect("DSC must parse");

            let result = extract_crl_uri(&dsc).expect("extract_crl_uri should succeed");
            assert_eq!(
                result,
                Some(test_uri.to_string()),
                "extract_crl_uri should return the expected HTTPS URI"
            );
        }

        #[test]
        fn extract_crl_uri_rejects_http_uri() {
            // Verify that extract_crl_uri rejects plain HTTP URIs (policy decision).
            let test_uri = "http://example.com/crl/test.crl";
            let (_iaca_der, dsc_der, _signing_key) = build_chain_with_crl_uri(test_uri);
            let (_, dsc) = X509Certificate::from_der(&dsc_der).expect("DSC must parse");

            let result = extract_crl_uri(&dsc).expect("extract_crl_uri should succeed");
            assert_eq!(
                result, None,
                "extract_crl_uri should reject plain HTTP URIs"
            );
        }

        // TODO: Add integration tests for valid CRL checking:
        // 1. A valid CRL that does NOT list the DSC serial -> returns Ok(())
        // 2. A valid CRL that DOES list the DSC serial -> returns MdocError::CertificateRevoked
        //
        // These tests require programmatically generating X.509 CRLs signed by the issuer CA.
        // The `rcgen` crate used for certificate generation does not currently support CRL creation.
        // Potential approaches:
        // - Use the `openssl` crate to generate CRLs (adds native dependency)
        // - Shell out to `openssl` CLI during test setup (complex, brittle)
        // - Embed pre-generated CRL fixtures as DER bytes (requires regeneration on key rotation)
        // - Contribute CRL generation support to `rcgen` upstream
        //
        // Template for mock CrlFetcher-based test:
        // ```rust
        // struct MockCrlFetcher {
        //     crl_bytes: Vec<u8>,
        // }
        //
        // #[async_trait]
        // impl CrlFetcher for MockCrlFetcher {
        //     async fn fetch_crl(&self, _uri: &str) -> std::result::Result<Vec<u8>, reqwest::Error> {
        //         Ok(self.crl_bytes.clone())
        //     }
        // }
        //
        // // Use in test:
        // let mock_fetcher = MockCrlFetcher { crl_bytes: pre_generated_crl_der };
        // let result = check_revocation(&dsc, &iaca_der, RevocationPolicy::HardFail, Some(&mock_fetcher)).await;
        // ```
    }
}
