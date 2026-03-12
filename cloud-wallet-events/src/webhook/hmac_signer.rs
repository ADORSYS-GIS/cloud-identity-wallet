use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::HmacSignerError;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 signer for webhook authentication.
///
/// The secret is stored as a [`SecretSlice<u8>`] which guarantees:
/// - The raw bytes are **never printed or logged** (no `Debug`/`Display` impl).
/// - The memory is **zeroed on drop** via the `zeroize` crate.
/// - The secret is only accessible through the explicit `.expose_secret()` call,
///   making every use-site an intentional, auditable act.
pub struct HmacSigner {
    secret: SecretSlice<u8>,
}

impl HmacSigner {
    /// Create a new HMAC signer.
    ///
    /// Accepts anything that converts into `Vec<u8>` — `&str`, `String`,
    /// `Vec<u8>`, or `&[u8]`. The bytes are immediately wrapped in a
    /// `SecretSlice`, so the raw value is protected from the moment of
    /// construction.
    ///
    /// ```rust,ignore
    /// let signer = HmacSigner::new("my-secret");
    /// let signer = HmacSigner::new(b"my-secret".to_vec());
    /// ```
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: SecretSlice::from(secret.into()),
        }
    }

    /// Sign a payload with the current timestamp.
    ///
    /// Returns `(signature_hex, unix_timestamp_secs)`.
    pub fn sign(&self, payload: &str) -> Result<(String, u64), HmacSignerError> {
        let timestamp = self.current_timestamp()?;
        let signature = self.sign_with_timestamp(payload, timestamp)?;
        Ok((signature, timestamp))
    }

    /// Sign a payload with a specific Unix timestamp (seconds).
    ///
    /// # Signed message format
    ///
    /// The message fed to HMAC-SHA256 is:
    ///
    /// ```text
    /// t=<ISO 8601 timestamp>.<payload>
    /// ```
    ///
    /// The ISO 8601 representation is produced from `timestamp` via RFC 3339.
    /// Using the same `t=<iso8601>` prefix as the signature header value
    /// means the verifier can extract the timestamp string directly from the
    /// header and reconstruct the signed message without any re-conversion.
    ///
    /// # Example
    ///
    /// For `timestamp = 1707574200` and `payload = r#"{"event":"test"}"#`:
    ///
    /// ```text
    /// signed_message = "t=2024-02-10T14:30:00Z.{\"event\":\"test\"}"
    /// ```
    pub fn sign_with_timestamp(
        &self,
        payload: &str,
        timestamp: u64,
    ) -> Result<String, HmacSignerError> {
        let ts = unix_to_rfc3339(timestamp)?;
        let message = format!("t={ts}.{payload}");
        self.hmac_sha256(message.as_bytes())
    }

    /// Verify a signature against a payload and timestamp.
    ///
    /// Checks in order:
    /// 1. Timestamp freshness (replay attack prevention, bounded by `max_age_secs`).
    /// 2. Future timestamp (clock skew tolerance: 60 seconds).
    /// 3. Constant-time HMAC comparison.
    pub fn verify(
        &self,
        payload: &str,
        signature: &str,
        timestamp: u64,
        max_age_secs: u64,
    ) -> Result<(), HmacSignerError> {
        let current = self.current_timestamp()?;
        let age = current.saturating_sub(timestamp);

        if age > max_age_secs {
            return Err(HmacSignerError::TimestampTooOld {
                age,
                max: max_age_secs,
            });
        }

        if timestamp > current + 60 {
            return Err(HmacSignerError::TimestampInFuture(timestamp - current));
        }

        self.verify_constant_time(payload, signature, timestamp)
    }

    /// Constant-time signature verification.
    ///
    /// Reconstructs the signed message (same format as [`sign_with_timestamp`])
    /// and delegates to `mac.verify_slice()` from the `hmac` crate, which
    /// performs a constant-time comparison to prevent timing side-channel attacks.
    ///
    /// [`sign_with_timestamp`]: HmacSigner::sign_with_timestamp
    fn verify_constant_time(
        &self,
        payload: &str,
        signature: &str,
        timestamp: u64,
    ) -> Result<(), HmacSignerError> {
        let ts = unix_to_rfc3339(timestamp)?;
        let message = format!("t={ts}.{payload}");

        let mut mac = HmacSha256::new_from_slice(self.secret.expose_secret())
            .map_err(|e| HmacSignerError::InvalidKey(e.to_string()))?;

        mac.update(message.as_bytes());

        let signature_bytes = hex::decode(signature).map_err(|_| HmacSignerError::InvalidHex)?;

        mac.verify_slice(&signature_bytes)
            .map_err(|_| HmacSignerError::SignatureMismatch)
    }

    /// Compute HMAC-SHA256 over `message` and return the result as a lowercase hex string.
    ///
    /// # Signed message format
    ///
    /// Callers are responsible for constructing `message`. Within this crate,
    /// the message is always `t=<RFC 3339 timestamp>.<payload>` — see
    /// [`sign_with_timestamp`] for details.
    ///
    /// [`sign_with_timestamp`]: HmacSigner::sign_with_timestamp
    fn hmac_sha256(&self, message: &[u8]) -> Result<String, HmacSignerError> {
        let mut mac = HmacSha256::new_from_slice(self.secret.expose_secret())
            .map_err(|e| HmacSignerError::InvalidKey(e.to_string()))?;

        mac.update(message);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Return the current Unix timestamp in seconds.
    fn current_timestamp(&self) -> Result<u64, HmacSignerError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| HmacSignerError::ClockError(e.to_string()))
    }
}

/// Convert a Unix timestamp (seconds) to an RFC 3339 string.
///
/// Returns [`HmacSignerError::TimestampOutOfRange`] if `timestamp` cannot be
/// represented as an [`time::OffsetDateTime`] (i.e. it is outside the range
/// supported by the `time` crate, roughly ±9999 years from epoch). In
/// practice this never occurs with real-world timestamps.
fn unix_to_rfc3339(timestamp: u64) -> Result<String, HmacSignerError> {
    let dt = time::OffsetDateTime::from_unix_timestamp(timestamp as i64)
        .map_err(|e| HmacSignerError::TimestampOutOfRange(e.to_string()))?;

    dt.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| HmacSignerError::TimestampOutOfRange(e.to_string()))
}

/// Format a webhook signature header value.
///
/// Format: `t=<RFC 3339 timestamp>,sig=<hex_signature>`
///
/// The `t=` prefix in the header matches the prefix used when constructing the
/// signed message in [`HmacSigner::sign_with_timestamp`], so a verifier can
/// extract the timestamp string from the header and reconstruct the exact
/// signed message as `"<t=...part>.<payload>"` without any re-conversion.
///
/// The caller is responsible for choosing the header name (e.g.
/// `"X-Hub-Signature-256"`, `"X-Webhook-Signature"`). This function only
/// produces the header *value*.
pub fn format_signature_header(signature: &str, timestamp: u64) -> Result<String, HmacSignerError> {
    let ts = unix_to_rfc3339(timestamp)?;
    Ok(format!("t={ts},sig={signature}"))
}

/// Parse a webhook signature header value.
///
/// Expects the format `t=<timestamp>,sig=<hex_signature>`.
/// Returns `(timestamp_str, signature_hex)` on success.
pub fn parse_signature_header(header: &str) -> Result<(String, String), HmacSignerError> {
    let mut timestamp = None;
    let mut signature = None;

    for part in header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = Some(ts.to_string());
        } else if let Some(sig) = part.strip_prefix("sig=") {
            signature = Some(sig.to_string());
        }
    }

    match (timestamp, signature) {
        (Some(t), Some(s)) => Ok((t, s)),
        _ => Err(HmacSignerError::InvalidHeaderFormat(header.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn signer(secret: &str) -> HmacSigner {
        HmacSigner::new(secret)
    }

    #[test]
    fn test_new_accepts_various_input_types() {
        // &str
        let _signer = HmacSigner::new("string-secret");
        // Vec<u8>
        let _signer = HmacSigner::new(vec![0x00u8, 0xFF, 0xDE, 0xAD]);
        // &[u8] via to_vec()
        let _signer = HmacSigner::new(b"bytes-secret".to_vec());
    }

    #[test]
    fn test_sign_and_verify() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let payload = r#"{"event":"test","data":"value"}"#;
        let (signature, timestamp) = s.sign(payload)?;
        s.verify(payload, &signature, timestamp, 300)
    }

    #[test]
    fn test_verify_fails_with_wrong_signature() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let payload = r#"{"event":"test"}"#;
        let (_, timestamp) = s.sign(payload)?;
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = s.verify(payload, wrong, timestamp, 300);
        assert!(matches!(result, Err(HmacSignerError::SignatureMismatch)));
        Ok(())
    }

    #[test]
    fn test_verify_rejects_malformed_hex() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let (_, timestamp) = s.sign("payload")?;
        let result = s.verify("payload", "not-valid-hex!!", timestamp, 300);
        assert!(matches!(result, Err(HmacSignerError::InvalidHex)));
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_wrong_secret() -> Result<(), HmacSignerError> {
        let s1 = signer("secret1");
        let s2 = signer("secret2");
        let (signature, timestamp) = s1.sign(r#"{"event":"test"}"#)?;
        assert!(
            s2.verify(r#"{"event":"test"}"#, &signature, timestamp, 300)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_modified_payload() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let (signature, timestamp) = s.sign(r#"{"amount":100}"#)?;
        assert!(
            s.verify(r#"{"amount":999}"#, &signature, timestamp, 300)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_timestamp_too_old() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let old = s.current_timestamp()? - 3600;
        let sig = s.sign_with_timestamp("payload", old)?;
        let result = s.verify("payload", &sig, old, 300);
        assert!(matches!(
            result,
            Err(HmacSignerError::TimestampTooOld { .. })
        ));
        Ok(())
    }

    #[test]
    fn test_timestamp_in_future() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let future = s.current_timestamp()? + 3600;
        let sig = s.sign_with_timestamp("payload", future)?;
        let result = s.verify("payload", &sig, future, 300);
        assert!(matches!(result, Err(HmacSignerError::TimestampInFuture(_))));
        Ok(())
    }

    #[test]
    fn test_sign_is_deterministic() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let ts = 1707574200u64;
        assert_eq!(
            s.sign_with_timestamp("payload", ts)?,
            s.sign_with_timestamp("payload", ts)?
        );
        Ok(())
    }

    #[test]
    fn test_different_payloads_produce_different_signatures() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let ts = 1707574200u64;
        assert_ne!(
            s.sign_with_timestamp("p1", ts)?,
            s.sign_with_timestamp("p2", ts)?
        );
        Ok(())
    }

    #[test]
    fn test_different_timestamps_produce_different_signatures() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        assert_ne!(
            s.sign_with_timestamp("p", 1000)?,
            s.sign_with_timestamp("p", 2000)?
        );
        Ok(())
    }

    #[test]
    fn test_binary_secret_is_accepted() -> Result<(), HmacSignerError> {
        let secret = vec![0x00u8, 0xFF, 0x80, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
        let s = HmacSigner::new(secret);
        let (sig, ts) = s.sign("payload")?;
        s.verify("payload", &sig, ts, 300)
    }

    #[test]
    fn test_signature_is_64_char_hex() -> Result<(), HmacSignerError> {
        let (sig, _) = signer("test-secret").sign("test")?;
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_format_and_parse_header_roundtrip() -> Result<(), HmacSignerError> {
        let ts = 1707574200u64;
        let header = format_signature_header("abcdef123456", ts)?;
        assert!(header.starts_with("t="));
        assert!(header.contains(",sig=abcdef123456"));

        let (parsed_ts, parsed_sig) = parse_signature_header(&header)?;
        assert_eq!(parsed_sig, "abcdef123456");
        // The timestamp round-trips through RFC 3339
        assert!(parsed_ts.starts_with("2024-"));
        Ok(())
    }

    #[test]
    fn test_header_timestamp_matches_signed_message() -> Result<(), HmacSignerError> {
        // The timestamp string in the header must be identical to the one used
        // when constructing the signed message, so a verifier can re-sign without
        // converting between formats.
        let s = signer("test-secret");
        let payload = r#"{"event":"credential.stored"}"#;
        let ts = 1707574200u64;

        let sig = s.sign_with_timestamp(payload, ts)?;
        let header = format_signature_header(&sig, ts)?;

        // Extract t= part from header
        let (ts_str, sig_from_header) = parse_signature_header(&header)?;

        // Re-construct the signed message using the header's timestamp string directly
        let reconstructed_message = format!("t={ts_str}.{payload}");

        // Verify using the raw HMAC so we can check the exact message
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"test-secret").unwrap();
        mac.update(reconstructed_message.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        assert_eq!(sig_from_header, expected);
        Ok(())
    }

    #[test]
    fn test_parse_invalid_signature_header() {
        assert!(parse_signature_header("sha256=abc").is_err());
        assert!(parse_signature_header("garbage").is_err());
    }

    #[test]
    fn test_verify_with_custom_max_age() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let old = s.current_timestamp()? - 100;
        let sig = s.sign_with_timestamp("test", old)?;
        assert!(s.verify("test", &sig, old, 60).is_err());
        s.verify("test", &sig, old, 200)
    }

    #[test]
    fn test_clock_skew_tolerance() -> Result<(), HmacSignerError> {
        let s = signer("test-secret");
        let future = s.current_timestamp()? + 30;
        let sig = s.sign_with_timestamp("test", future)?;
        s.verify("test", &sig, future, 300)
    }
}
