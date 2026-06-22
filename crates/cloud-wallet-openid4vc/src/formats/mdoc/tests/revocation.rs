use crate::formats::mdoc::revocation::{is_blocked_ip, validate_crl_url};

#[test]
fn is_blocked_ip_rejects_loopback_ipv4() {
    assert!(is_blocked_ip(&"127.0.0.1".parse().unwrap()));
    assert!(is_blocked_ip(&"127.0.0.0".parse().unwrap()));
    assert!(is_blocked_ip(&"127.255.255.255".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_loopback_ipv6() {
    assert!(is_blocked_ip(&"::1".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_private_ipv4_10_range() {
    assert!(is_blocked_ip(&"10.0.0.1".parse().unwrap()));
    assert!(is_blocked_ip(&"10.255.255.255".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_private_ipv4_172_range() {
    assert!(is_blocked_ip(&"172.16.0.1".parse().unwrap()));
    assert!(is_blocked_ip(&"172.31.255.255".parse().unwrap()));
    // 172.15.x.x and 172.32.x.x are NOT private
    assert!(!is_blocked_ip(&"172.15.0.1".parse().unwrap()));
    assert!(!is_blocked_ip(&"172.32.0.1".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_private_ipv4_192_168_range() {
    assert!(is_blocked_ip(&"192.168.0.1".parse().unwrap()));
    assert!(is_blocked_ip(&"192.168.255.255".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_link_local_ipv4() {
    assert!(is_blocked_ip(&"169.254.0.1".parse().unwrap()));
    assert!(is_blocked_ip(&"169.254.255.255".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_cloud_metadata_endpoint() {
    // AWS/GCP/Azure metadata endpoint
    assert!(is_blocked_ip(&"169.254.169.254".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_private_ipv6() {
    assert!(is_blocked_ip(&"fc00::1".parse().unwrap()));
    assert!(is_blocked_ip(
        &"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
    ));
}

#[test]
fn is_blocked_ip_rejects_link_local_ipv6() {
    assert!(is_blocked_ip(&"fe80::1".parse().unwrap()));
    assert!(is_blocked_ip(
        &"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
    ));
}

#[test]
fn is_blocked_ip_rejects_documentation_ipv6() {
    assert!(is_blocked_ip(&"2001:db8::1".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_multicast_ipv4() {
    assert!(is_blocked_ip(&"224.0.0.1".parse().unwrap()));
    assert!(is_blocked_ip(&"239.255.255.255".parse().unwrap()));
}

#[test]
fn is_blocked_ip_rejects_unspecified_addresses() {
    assert!(is_blocked_ip(&"0.0.0.0".parse().unwrap()));
    assert!(is_blocked_ip(&"::".parse().unwrap()));
}

#[test]
fn is_blocked_ip_accepts_public_ipv4() {
    assert!(!is_blocked_ip(&"8.8.8.8".parse().unwrap())); // Google DNS
    assert!(!is_blocked_ip(&"1.1.1.1".parse().unwrap())); // Cloudflare DNS
    assert!(!is_blocked_ip(&"93.184.216.34".parse().unwrap())); // example.com
}

#[test]
fn is_blocked_ip_accepts_public_ipv6() {
    assert!(!is_blocked_ip(&"2001:4860:4860::8888".parse().unwrap())); // Google DNS
    assert!(!is_blocked_ip(&"2606:4700:4700::1111".parse().unwrap())); // Cloudflare DNS
}

#[tokio::test]
async fn validate_crl_url_rejects_localhost() {
    let err = validate_crl_url("https://127.0.0.1/crl.crl")
        .await
        .expect_err("localhost IP should be rejected");
    assert!(err.contains("blocked IP address"));
}

#[tokio::test]
async fn validate_crl_url_rejects_private_ip() {
    let err = validate_crl_url("https://192.168.1.1/crl.crl")
        .await
        .expect_err("private IP should be rejected");
    assert!(err.contains("blocked IP address"));
}

#[tokio::test]
async fn validate_crl_url_rejects_metadata_endpoint() {
    let err = validate_crl_url("https://169.254.169.254/latest/meta-data/crl")
        .await
        .expect_err("metadata IP should be rejected");
    assert!(err.contains("blocked IP address"));
}

#[tokio::test]
async fn validate_crl_url_rejects_link_local() {
    let err = validate_crl_url("https://169.254.1.1/crl.crl")
        .await
        .expect_err("link-local IP should be rejected");
    assert!(err.contains("blocked IP address"));
}

#[tokio::test]
async fn validate_crl_url_rejects_http_scheme() {
    let err = validate_crl_url("http://example.com/crl.crl")
        .await
        .expect_err("HTTP scheme should be rejected");
    assert!(err.contains("HTTPS"));
}

#[tokio::test]
async fn validate_crl_url_rejects_ipv6_loopback() {
    let err = validate_crl_url("https://[::1]/crl.crl")
        .await
        .expect_err(&format!(
            "IPv6 loopback should be rejected, got: {:?}",
            validate_crl_url("https://[::1]/crl.crl").await
        ));
    assert!(
        err.contains("blocked IP address"),
        "Expected 'blocked IP address' in error, got: {err}"
    );
}

#[tokio::test]
async fn validate_crl_url_accepts_public_url() {
    // This test validates URL format but doesn't actually make a network request
    // since validate_crl_url only validates the URL, it doesn't fetch
    let result = validate_crl_url("https://example.com/crl.crl").await;
    // This will fail DNS resolution in CI environments without network,
    // but the IP validation would pass once DNS resolves
    match result {
        Ok(()) => {}                                   // DNS resolved to public IPs
        Err(e) if e.contains("resolve hostname") => {} // DNS failed - acceptable
        Err(e) => panic!("Unexpected error: {e}"),
    }
}
