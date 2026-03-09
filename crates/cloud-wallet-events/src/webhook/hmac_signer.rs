use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretSlice};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 signer for webhook authentication.
pub struct HmacSigner {
    secret: SecretSlice<u8>,
}

impl HmacSigner {
    pub fn new(secret: SecretSlice<u8>) -> Self {
        Self { secret }
    }

    /// Sign a payload with the current timestamp.
    pub fn sign(&self, payload: &str) -> Result<(String, u64), String> {
        let timestamp = self.current_timestamp().map_err(|e| e.to_string())?;
        let signature = self.sign_with_timestamp(payload, timestamp)?;
        Ok((signature, timestamp))
    }

    /// Sign a payload with a specific timestamp.
    pub fn sign_with_timestamp(&self, payload: &str, timestamp: u64) -> Result<String, String> {
        let message = format!("{timestamp}.{payload}");
        self.hmac_sha256(message.as_bytes())
    }

    /// Verify a signature.
    pub fn verify(
        &self,
        payload: &str,
        signature: &str,
        timestamp: u64,
        max_age_secs: u64,
    ) -> Result<(), String> {
        let current = self.current_timestamp().map_err(|e| e.to_string())?;
        let age = current.saturating_sub(timestamp);

        if age > max_age_secs {
            return Err(format!(
                "Timestamp too old: {age} seconds (max: {max_age_secs})"
            ));
        }

        if timestamp > current + 60 {
            return Err(format!(
                "Timestamp is in the future: {} seconds ahead",
                timestamp - current
            ));
        }

        self.verify_constant_time(payload, signature, timestamp)
    }

    /// Constant-time signature verification using `mac.verify_slice()`.
    fn verify_constant_time(
        &self,
        payload: &str,
        signature: &str,
        timestamp: u64,
    ) -> Result<(), String> {
        let message = format!("{timestamp}.{payload}");

        let mut mac = HmacSha256::new_from_slice(self.secret.expose_secret())
            .map_err(|e| format!("Failed to initialise HMAC: {e}"))?;

        mac.update(message.as_bytes());

        let signature_bytes =
            hex::decode(signature).map_err(|_| "Invalid signature: not valid hex".to_string())?;

        mac.verify_slice(&signature_bytes)
            .map_err(|_| "Invalid signature".to_string())
    }

    /// Compute HMAC-SHA256 and return the result as a lowercase hex string.
    fn hmac_sha256(&self, message: &[u8]) -> Result<String, String> {
        let mut mac = HmacSha256::new_from_slice(self.secret.expose_secret())
            .map_err(|e| format!("Failed to initialise HMAC: {e}"))?;

        mac.update(message);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Get the current Unix timestamp in seconds.
    fn current_timestamp(&self) -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| e.to_string())
    }
}

/// Format the `X-iGrant-Signature` header value.
pub fn format_signature_header(signature: &str, timestamp: u64) -> String {
    // Convert unix timestamp to ISO 8601 for the header
    let dt = time::OffsetDateTime::from_unix_timestamp(timestamp as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let ts = dt
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    format!("t={ts},sig={signature}")
}

/// Parse the `X-iGrant-Signature` header value.
pub fn parse_signature_header(header: &str) -> Result<(String, String), String> {
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
        _ => Err(format!(
            "Invalid X-iGrant-Signature header format: {header}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretSlice;

    fn signer(secret: &str) -> HmacSigner {
        HmacSigner::new(SecretSlice::from(secret.as_bytes().to_vec()))
    }

    #[test]
    fn test_new_accepts_secret_slice() {
        let _signer = HmacSigner::new(SecretSlice::from(b"string-secret".to_vec()));
        let _signer = HmacSigner::new(SecretSlice::from(vec![0x00u8, 0xFF, 0xDE, 0xAD]));
    }

    #[test]
    fn test_sign_and_verify() -> Result<(), String> {
        let s = signer("test-secret");
        let payload = r#"{"event":"test","data":"value"}"#;
        let (signature, timestamp) = s.sign(payload)?;
        s.verify(payload, &signature, timestamp, 300)
    }

    #[test]
    fn test_verify_fails_with_wrong_signature() -> Result<(), String> {
        let s = signer("test-secret");
        let payload = r#"{"event":"test"}"#;
        let (_, timestamp) = s.sign(payload)?;
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = s.verify(payload, wrong, timestamp, 300);
        assert_eq!(result, Err("Invalid signature".to_string()));
        Ok(())
    }

    #[test]
    fn test_verify_rejects_malformed_hex() -> Result<(), String> {
        let s = signer("test-secret");
        let (_, timestamp) = s.sign("payload")?;
        let result = s.verify("payload", "not-valid-hex!!", timestamp, 300);
        assert!(matches!(result, Err(e) if e.contains("not valid hex")));
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_wrong_secret() -> Result<(), String> {
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
    fn test_verify_fails_with_modified_payload() -> Result<(), String> {
        let s = signer("test-secret");
        let (signature, timestamp) = s.sign(r#"{"amount":100}"#)?;
        assert!(
            s.verify(r#"{"amount":999}"#, &signature, timestamp, 300)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn test_timestamp_too_old() -> Result<(), String> {
        let s = signer("test-secret");
        let old = s.current_timestamp()? - 3600;
        let sig = s.sign_with_timestamp("payload", old)?;
        let result = s.verify("payload", &sig, old, 300);
        assert!(matches!(result, Err(e) if e.contains("Timestamp too old")));
        Ok(())
    }

    #[test]
    fn test_timestamp_in_future() -> Result<(), String> {
        let s = signer("test-secret");
        let future = s.current_timestamp()? + 3600;
        let sig = s.sign_with_timestamp("payload", future)?;
        let result = s.verify("payload", &sig, future, 300);
        assert!(matches!(result, Err(e) if e.contains("future")));
        Ok(())
    }

    #[test]
    fn test_sign_is_deterministic() -> Result<(), String> {
        let s = signer("test-secret");
        let ts = 1707574200u64;
        assert_eq!(
            s.sign_with_timestamp("payload", ts)?,
            s.sign_with_timestamp("payload", ts)?
        );
        Ok(())
    }

    #[test]
    fn test_different_payloads_produce_different_signatures() -> Result<(), String> {
        let s = signer("test-secret");
        let ts = 1707574200u64;
        assert_ne!(
            s.sign_with_timestamp("p1", ts)?,
            s.sign_with_timestamp("p2", ts)?
        );
        Ok(())
    }

    #[test]
    fn test_different_timestamps_produce_different_signatures() -> Result<(), String> {
        let s = signer("test-secret");
        assert_ne!(
            s.sign_with_timestamp("p", 1000)?,
            s.sign_with_timestamp("p", 2000)?
        );
        Ok(())
    }

    #[test]
    fn test_binary_secret_is_accepted() -> Result<(), String> {
        let secret = vec![0x00u8, 0xFF, 0x80, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
        let s = HmacSigner::new(SecretSlice::from(secret));
        let (sig, ts) = s.sign("payload")?;
        s.verify("payload", &sig, ts, 300)
    }

    #[test]
    fn test_signature_is_64_char_hex() -> Result<(), String> {
        let (sig, _) = signer("test-secret").sign("test")?;
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_format_signature_header() {
        let header = format_signature_header("abcdef123456", 1707574200);
        assert!(header.starts_with("t="));
        assert!(header.contains(",sig=abcdef123456"));
    }

    #[test]
    fn test_parse_signature_header() -> Result<(), String> {
        let (ts, sig) = parse_signature_header("t=2025-04-10T07:19:10Z,sig=abcdef123456")?;
        assert_eq!(ts, "2025-04-10T07:19:10Z");
        assert_eq!(sig, "abcdef123456");
        Ok(())
    }

    #[test]
    fn test_parse_invalid_signature_header() {
        assert!(parse_signature_header("sha256=abc").is_err());
        assert!(parse_signature_header("garbage").is_err());
    }

    #[test]
    fn test_verify_with_custom_max_age() -> Result<(), String> {
        let s = signer("test-secret");
        let old = s.current_timestamp()? - 100;
        let sig = s.sign_with_timestamp("test", old)?;
        assert!(s.verify("test", &sig, old, 60).is_err());
        s.verify("test", &sig, old, 200)
    }

    #[test]
    fn test_clock_skew_tolerance() -> Result<(), String> {
        let s = signer("test-secret");
        let future = s.current_timestamp()? + 30;
        let sig = s.sign_with_timestamp("test", future)?;
        s.verify("test", &sig, future, 300)
    }
}
