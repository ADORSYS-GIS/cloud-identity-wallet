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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use url::Url;
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

/// Checks if an IP address is in a blocked range that should not be accessed for CRL fetching.
///
/// Blocked ranges include:
/// - Loopback addresses (127.0.0.0/8, ::1)
/// - Private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - CGNAT/Shared address space 100.64.0.0/10 (RFC 6598)
/// - Private IPv6 ranges (fc00::/7, ::ffff:0:0/96)
/// - Link-local addresses (169.254.0.0/16, fe80::/10)
/// - Cloud metadata endpoints (169.254.169.254 specifically - AWS, GCP, Azure)
/// - Broadcast addresses
/// - Documentation/test ranges
/// - IPv4-mapped IPv6 addresses that resolve to blocked IPv4 ranges
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_blocked_ipv4(ipv4),
        IpAddr::V6(ipv6) => {
            // Check for IPv4-mapped IPv6 addresses (::ffff:0:0/96)
            // IPv6.is_loopback() does NOT treat IPv4-mapped loopback as loopback
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                return is_blocked_ipv4(&ipv4);
            }
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || is_ipv6_private(ipv6)
                || is_ipv6_link_local(ipv6)
                || is_ipv6_documentation(ipv6)
        }
    }
}

fn is_blocked_ipv4(ipv4: &Ipv4Addr) -> bool {
    let octets = ipv4.octets();
    match octets[0] {
        0 => true,                                          // 0.0.0.0/8 - "This network"
        10 => true,                                         // 10.0.0.0/8 - Private
        100 if octets[1] >= 64 && octets[1] <= 127 => true, // 100.64.0.0/10 - CGNAT (RFC 6598)
        127 => true,                                        // 127.0.0.0/8 - Loopback
        169 if octets[1] == 254 => true, // 169.254.0.0/16 - Link-local (includes metadata)
        172 if octets[1] >= 16 && octets[1] <= 31 => true, // 172.16.0.0/12 - Private
        192 if octets[1] == 0 && octets[2] == 0 => true, // 192.0.0.0/24 - IETF Protocol Assignments
        192 if octets[1] == 0 && octets[2] == 2 => true, // 192.0.2.0/24 - Documentation (TEST-NET-1)
        192 if octets[1] == 88 && octets[2] == 99 => true, // 192.88.99.0/24 - 6to4 Relay Anycast
        192 if octets[1] == 168 => true,                 // 192.168.0.0/16 - Private
        198 if octets[1] >= 18 && octets[1] <= 19 => true, // 198.18.0.0/15 - Benchmark testing
        198 if octets[1] == 51 && octets[2] == 100 => true, // 198.51.100.0/24 - Documentation (TEST-NET-2)
        203 if octets[1] == 0 && octets[2] == 113 => true, // 203.0.113.0/24 - Documentation (TEST-NET-3)
        224..=239 => true,                                 // 224.0.0.0/4 - Multicast
        240..=255 => true,                                 // 240.0.0.0/4 - Reserved
        _ => ipv4.is_broadcast() || ipv4.is_unspecified(),
    }
}

fn is_ipv6_private(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00 // fc00::/7 - Unique local addresses
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] & 0xffc0 == 0xfe80 // fe80::/10 - Link-local
}

fn is_ipv6_documentation(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8 // 2001:db8::/32 - Documentation
}

/// CRL URL validation error type.
///
/// Distinguishes between SSRF-blocked IPs (security boundary, always hard-fail)
/// and DNS/network failures (route through the revocation policy handler so
/// SoftFail can tolerate them).
#[derive(Debug)]
pub(crate) enum CrlUrlValidationError {
    /// The URL resolves to a blocked IP address (SSRF attack prevention).
    SsrfBlocked(String),
    /// DNS resolution or other network failure occurred while validating URL.
    NetworkFailure(String),
}

/// Validates that a CRL URL is safe to fetch from, protecting against SSRF attacks.
///
/// This function:
/// 1. Validates that the URL uses HTTPS (already checked by `extract_crl_uri`)
/// 2. Resolves the hostname to IP addresses
/// 3. Rejects URLs that resolve to blocked IP ranges (loopback, private, link-local, metadata)
///
/// Returns `Ok(())` if the URL is safe, or a `CrlUrlValidationError` describing why
/// validation failed.
pub(crate) async fn validate_crl_url(uri: &str) -> std::result::Result<(), CrlUrlValidationError> {
    let url = Url::parse(uri)
        .map_err(|e| CrlUrlValidationError::NetworkFailure(format!("Invalid URL: {e}")))?;

    if url.scheme() != "https" {
        return Err(CrlUrlValidationError::SsrfBlocked(format!(
            "CRL URL must use HTTPS, got: {}",
            url.scheme()
        )));
    }

    let host = url
        .host_str()
        .ok_or_else(|| CrlUrlValidationError::NetworkFailure("CRL URL missing host".to_string()))?;

    // Check if host is already an IP address (IPv4 or IPv6 in brackets)
    // For IPv6, url.host_str() returns the address with brackets, e.g., "[::1]"
    // so we need to strip the brackets before parsing
    let ip_str = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };

    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        if is_blocked_ip(&ip) {
            return Err(CrlUrlValidationError::SsrfBlocked(format!(
                "CRL URL resolves to blocked IP address: {ip}"
            )));
        }
        return Ok(());
    }

    // Resolve hostname to IP addresses and check each one
    let socket_addrs = tokio::net::lookup_host((host, url.port().unwrap_or(443)))
        .await
        .map_err(|e| {
            CrlUrlValidationError::NetworkFailure(format!(
                "Failed to resolve hostname '{host}': {e}"
            ))
        })?;

    for addr in socket_addrs {
        if is_blocked_ip(&addr.ip()) {
            return Err(CrlUrlValidationError::SsrfBlocked(format!(
                "CRL URL hostname '{host}' resolves to blocked IP address: {}",
                addr.ip()
            )));
        }
    }

    Ok(())
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

/// Global singleton HTTP CRL fetcher.
///
/// Lazily initialized to avoid creating reqwest::Client until first use.
/// The singleton ensures a single shared reqwest::Client and connection pool
/// across all revocation checks.
static DEFAULT_CRL_FETCHER: LazyLock<HttpCrlFetcher> = LazyLock::new(HttpCrlFetcher::new);

/// Production HTTP-based CRL fetcher with in-memory caching.
///
/// Uses a global cache shared across all instances to avoid redundant HTTPS fetches.
/// Cache entries have a TTL (default 6 hours) and the cache has a maximum size.
pub struct HttpCrlFetcher {
    http_client: Client,
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
        }
    }

    /// Returns a reference to the global singleton fetcher.
    ///
    /// This is the recommended way to obtain a fetcher for production use,
    /// as it reuses the same HTTP client and connection pool.
    pub fn global() -> &'static HttpCrlFetcher {
        &DEFAULT_CRL_FETCHER
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
                    expires_after: DEFAULT_CRL_CACHE_TTL,
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
///
/// Eviction policy: TTL-expired entries are removed on access. When the cache reaches
/// `MAX_CRL_CACHE_ENTRIES`, the oldest entry by insertion order is evicted (FIFO).
struct CrlCacheEntry {
    crl_der: Vec<u8>,
    fetched_at: Instant,
    expires_after: Duration,
    insertion_order: u64,
}

static CRL_CACHE: LazyLock<Mutex<(HashMap<String, CrlCacheEntry>, u64)>> =
    LazyLock::new(|| Mutex::new((HashMap::new(), 0)));

/// Evicts entries that are stale (TTL expired) or when cache exceeds max size.
///
/// This implements a simple FIFO eviction policy: when the cache is full after
/// removing stale entries, the oldest entry by insertion order is removed.
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

    // If still over limit after sweeping stale, evict oldest entry (FIFO policy)
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
/// - `now`: Current time for CRL temporal validity checks. Injected for testability.
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
    now: time::OffsetDateTime,
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

    // SSRF protection: validate the CRL URL before fetching to prevent
    // server-side request forgery attacks against internal infrastructure
    // or cloud metadata endpoints.
    //
    // When a custom fetcher is provided (testing), URL validation is skipped
    // since the fetcher doesn't make real HTTP calls and DNS lookups cannot
    // be mocked.
    if fetcher.is_none() {
        match validate_crl_url(&crl_uri).await {
            Ok(()) => {}
            Err(CrlUrlValidationError::SsrfBlocked(reason)) => {
                return Err(MdocError::RevocationCheckFailed {
                    reason: format!("CRL URL validation failed: {reason}"),
                });
            }
            Err(CrlUrlValidationError::NetworkFailure(reason)) => {
                return handle_crl_url_network_error(&crl_uri, &reason, policy);
            }
        }
    }

    let fetcher_ref = fetcher.unwrap_or_else(|| HttpCrlFetcher::global());

    let crl_bytes = match fetcher_ref.fetch_crl(&crl_uri).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return handle_crl_fetch_error(&crl_uri, e, policy);
        }
    };

    let crl = match parse_and_validate_crl(&crl_bytes, dsc_issuer_der, now) {
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

/// Handles CRL URL network errors (DNS resolution failures, etc.) according to policy.
///
/// Unlike SSRF-blocked IP errors which always produce a hard failure (security boundary),
/// network failures during URL validation are routed through the policy handler so that
/// SoftFail can tolerate them.
fn handle_crl_url_network_error(uri: &str, reason: &str, policy: RevocationPolicy) -> Result<()> {
    match policy {
        RevocationPolicy::SoftFail => {
            tracing::warn!(
                "CRL URL validation for {} failed: {reason}; skipping revocation check",
                uri
            );
            Ok(())
        }
        RevocationPolicy::HardFail => Err(MdocError::RevocationCheckFailed {
            reason: format!("CRL URL validation for {} failed: {reason}", uri),
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
///
/// # Parameters
///
/// - `crl_der`: DER-encoded CRL bytes.
/// - `dsc_issuer_der`: DER bytes of the certificate that issued the DSC.
/// - `now`: Current time for temporal validity checks. Injected for testability.
fn parse_and_validate_crl<'a>(
    crl_der: &'a [u8],
    dsc_issuer_der: &[u8],
    now: time::OffsetDateTime,
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
    let now_ts = now.unix_timestamp();

    // RFC 5280 §5.1.2.4: Reject CRL with thisUpdate in the future
    let this_update = crl.last_update();
    let this_update_ts = this_update.timestamp();
    if this_update_ts > now_ts {
        return Err(MdocError::RevocationCheckFailed {
            reason: format!(
                "CRL thisUpdate is in the future (thisUpdate: {}, now: {})",
                this_update_ts, now_ts
            ),
        });
    }

    if let Some(next_update) = crl.next_update() {
        let next_update_ts = next_update.timestamp();
        if now_ts > next_update_ts {
            return Err(MdocError::RevocationCheckFailed {
                reason: format!(
                    "CRL has expired (nextUpdate: {}, now: {})",
                    next_update_ts, now_ts
                ),
            });
        }
    } else {
        // RFC 5280 §5.1.2.5: nextUpdate is optional but CRL issuers SHOULD include it.
        // A CRL without nextUpdate has no upper freshness bound, weakening revocation assurance.
        tracing::warn!("CRL missing nextUpdate field; cannot verify CRL freshness boundary");
    }

    // RFC 5280 §5.1.2.1: Log warning if CRL is older than expected (but don't reject)
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

    let issuer_ski_key_id = issuer_cert.extensions().iter().find_map(|ext| {
        if ext.oid.to_id_string() == OID_SKI {
            match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(ski) => Some(ski.0),
                _ => None,
            }
        } else {
            None
        }
    });

    match (crl_aki_key_id, issuer_ski_key_id) {
        (Some(aki_key_id), Some(ski_key_id)) => {
            if aki_key_id != ski_key_id {
                return Err(MdocError::RevocationCheckFailed {
                    reason:
                        "CRL Authority Key Identifier does not match issuer Subject Key Identifier"
                            .to_owned(),
                });
            }
            Ok(())
        }
        (Some(_), None) => {
            tracing::warn!(
                "CRL has Authority Key Identifier but issuer certificate lacks Subject Key Identifier"
            );
            Ok(())
        }
        (None, _) => Ok(()),
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
            let now = OffsetDateTime::now_utc();

            let result = check_revocation(&dsc, &iaca_der, RevocationPolicy::Skip, None, now).await;
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

            let now = OffsetDateTime::now_utc();

            // SoftFail should tolerate missing CRL URI
            let result =
                check_revocation(&dsc, &iaca_der, RevocationPolicy::SoftFail, None, now).await;
            assert!(
                result.is_ok(),
                "SoftFail should tolerate missing CRL URI: {:?}",
                result
            );

            // HardFail should reject missing CRL URI
            let result =
                check_revocation(&dsc, &iaca_der, RevocationPolicy::HardFail, None, now).await;
            assert!(result.is_err(), "HardFail should reject missing CRL URI");
        }

        #[tokio::test]
        async fn check_revocation_soft_fail_tolerates_crl_fetch_failure() {
            struct FailingCrlFetcher;

            #[async_trait]
            impl CrlFetcher for FailingCrlFetcher {
                async fn fetch_crl(
                    &self,
                    _uri: &str,
                ) -> std::result::Result<Vec<u8>, reqwest::Error> {
                    // Trigger a genuine reqwest error by connecting to a refused port.
                    // This exercises the handle_crl_fetch_error code path with a real
                    // reqwest::Error rather than a synthetic one (reqwest::Error::new is
                    // pub(crate) and cannot be called from outside the crate).
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_millis(100))
                        .build()
                        .expect("client must build");
                    client.get("http://127.0.0.1:1").send().await?;
                    unreachable!("connection to refused port must fail")
                }
            }

            let test_uri = "https://example.com/crl.crl";
            let (iaca_der, dsc_der, _signing_key) = build_chain_with_crl_uri(test_uri);
            let (_, dsc) = X509Certificate::from_der(&dsc_der).expect("DSC must parse");
            let now = OffsetDateTime::now_utc();
            let fetcher = FailingCrlFetcher;

            // SoftFail should tolerate CRL fetch failure
            let result = check_revocation(
                &dsc,
                &iaca_der,
                RevocationPolicy::SoftFail,
                Some(&fetcher),
                now,
            )
            .await;
            assert!(
                result.is_ok(),
                "SoftFail should tolerate CRL fetch failure: {:?}",
                result
            );

            // HardFail should reject CRL fetch failure
            let result = check_revocation(
                &dsc,
                &iaca_der,
                RevocationPolicy::HardFail,
                Some(&fetcher),
                now,
            )
            .await;
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

        /// Mock CRL fetcher for testing with pre-generated CRL fixtures.
        struct MockCrlFetcher {
            crl_bytes: Vec<u8>,
        }

        #[async_trait]
        impl CrlFetcher for MockCrlFetcher {
            async fn fetch_crl(&self, _uri: &str) -> std::result::Result<Vec<u8>, reqwest::Error> {
                Ok(self.crl_bytes.clone())
            }
        }

        /// Test fixtures generated by openssl (see test_data/mdoc/crl/README.md)
        /// CA certificate (self-signed root, used as DSC issuer)
        const CA_DER: &[u8] = include_bytes!("../../../test_data/mdoc/crl/ca.der");
        /// DSC with serial 0x0102030405 (revoked in crl_revoked.crl)
        const DSC_REVOKED_DER: &[u8] =
            include_bytes!("../../../test_data/mdoc/crl/dsc_with_crl_dp.der");
        /// DSC with serial 0xDEADBEEF (not revoked in any CRL)
        const DSC_NONREVOKED_DER: &[u8] =
            include_bytes!("../../../test_data/mdoc/crl/dsc_nonrevoked.der");
        /// Empty CRL signed by CA (no revoked certificates)
        const CRL_EMPTY_DER: &[u8] = include_bytes!("../../../test_data/mdoc/crl/crl_empty.crl");
        /// CRL signed by CA with serial 0x0102030405 revoked
        const CRL_REVOKED_DER: &[u8] =
            include_bytes!("../../../test_data/mdoc/crl/crl_revoked.crl");
        /// CRL signed by a different CA (invalid signature)
        const CRL_INVALID_DER: &[u8] =
            include_bytes!("../../../test_data/mdoc/crl/crl_invalid.crl");

        #[tokio::test]
        async fn check_revocation_empty_crl_clears_nonrevoked_dsc() {
            let (_, dsc) = X509Certificate::from_der(DSC_NONREVOKED_DER).expect("DSC must parse");
            let mock_fetcher = MockCrlFetcher {
                crl_bytes: CRL_EMPTY_DER.to_vec(),
            };
            let now = OffsetDateTime::now_utc();
            let result = check_revocation(
                &dsc,
                CA_DER,
                RevocationPolicy::HardFail,
                Some(&mock_fetcher),
                now,
            )
            .await;
            assert!(
                result.is_ok(),
                "Empty CRL should not reject non-revoked DSC: {:?}",
                result
            );
        }

        #[tokio::test]
        async fn check_revocation_revoked_crl_clears_nonrevoked_dsc() {
            let (_, dsc) = X509Certificate::from_der(DSC_NONREVOKED_DER).expect("DSC must parse");
            let mock_fetcher = MockCrlFetcher {
                crl_bytes: CRL_REVOKED_DER.to_vec(),
            };
            let now = OffsetDateTime::now_utc();
            let result = check_revocation(
                &dsc,
                CA_DER,
                RevocationPolicy::HardFail,
                Some(&mock_fetcher),
                now,
            )
            .await;
            assert!(
                result.is_ok(),
                "CRL with revoked DSC should not revoke different DSC: {:?}",
                result
            );
        }

        #[tokio::test]
        async fn check_revocation_revoked_dsc_returns_error() {
            let (_, dsc) = X509Certificate::from_der(DSC_REVOKED_DER).expect("DSC must parse");
            let mock_fetcher = MockCrlFetcher {
                crl_bytes: CRL_REVOKED_DER.to_vec(),
            };
            let now = OffsetDateTime::now_utc();
            let result = check_revocation(
                &dsc,
                CA_DER,
                RevocationPolicy::HardFail,
                Some(&mock_fetcher),
                now,
            )
            .await;
            assert!(
                matches!(result, Err(MdocError::CertificateRevoked { .. })),
                "DSC revoked in CRL should return CertificateRevoked error: {:?}",
                result
            );
        }

        #[tokio::test]
        async fn check_revocation_invalid_crl_signature_rejected_hardfail() {
            let (_, dsc) = X509Certificate::from_der(DSC_NONREVOKED_DER).expect("DSC must parse");
            let mock_fetcher = MockCrlFetcher {
                crl_bytes: CRL_INVALID_DER.to_vec(),
            };
            let now = OffsetDateTime::now_utc();
            let result = check_revocation(
                &dsc,
                CA_DER,
                RevocationPolicy::HardFail,
                Some(&mock_fetcher),
                now,
            )
            .await;
            assert!(
                result.is_err(),
                "CRL from wrong issuer should be rejected under HardFail: {:?}",
                result
            );
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("issuer name does not match")
                    || err_msg.contains("signature verification failed"),
                "Error should indicate issuer mismatch or signature failure: {err_msg}"
            );
        }

        #[tokio::test]
        async fn check_revocation_invalid_crl_signature_tolerated_softfail() {
            let (_, dsc) = X509Certificate::from_der(DSC_NONREVOKED_DER).expect("DSC must parse");
            let mock_fetcher = MockCrlFetcher {
                crl_bytes: CRL_INVALID_DER.to_vec(),
            };
            let now = OffsetDateTime::now_utc();
            let result = check_revocation(
                &dsc,
                CA_DER,
                RevocationPolicy::SoftFail,
                Some(&mock_fetcher),
                now,
            )
            .await;
            assert!(
                result.is_ok(),
                "SoftFail should tolerate CRL signature verification failure: {:?}",
                result
            );
        }
        //
        // #[tokio::test]
        // async fn check_revocation_revoked_dsc() {
        //     // Test: CRL DOES list DSC serial -> CertificateRevoked error
        //     let (iaca_der, dsc_der, _signing_key) = build_chain_with_crl_uri("https://example.com/crl.crl");
        //     let (_, dsc) = X509Certificate::from_der(&dsc_der).expect("DSC must parse");
        //     let crl_bytes = include_bytes!("fixtures/revoked_crl.der").to_vec();
        //     let mock_fetcher = MockCrlFetcher { crl_bytes };
        //     let result = check_revocation(&dsc, &iaca_der, RevocationPolicy::HardFail, Some(&mock_fetcher)).await;
        //     assert!(matches!(result, Err(MdocError::CertificateRevoked { .. })));
        // }
    }
}
