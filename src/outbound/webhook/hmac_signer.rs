use sha2::Sha256;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

/// HMAC-SHA256 signer for webhook authentication
pub struct HmacSigner {
    secret: String,
}

impl HmacSigner {
    /// New HMAC signer with the given secret
    pub fn new(secret: String) -> Self {
        Self { secret }
    }

    /// Sign a payload with current timestamp
    pub fn sign(&self, payload: &str) -> Result<(String, u64), SystemTimeError> {
        let timestamp = self.current_timestamp()?;
        let signature = self.sign_with_timestamp(payload, timestamp);
        Ok((signature, timestamp))
    }

    /// Sign a payload with a specific timestamp
    pub fn sign_with_timestamp(&self, payload: &str, timestamp: u64) -> String {
        let message = format!("{timestamp}.{payload}");
        self.hmac_sha256(&message)
    }

    /// Verify a signature
    pub fn verify(
        &self,
        payload: &str,
        signature: &str,
        timestamp: u64,
        max_age_secs: u64,
    ) -> Result<(), String> {
        // Check timestamp freshness first (prevent replay attacks)
        let current = self.current_timestamp().map_err(|e| e.to_string())?;
        let age = current.saturating_sub(timestamp);

        if age > max_age_secs {
            return Err(format!(
                "Timestamp too old: {age} seconds (max: {max_age_secs})"
            ));
        }

        // Future timestamps are also suspicious
        if timestamp > current + 60 {
            // Allow 60 seconds clock skew
            return Err(format!(
                "Timestamp is in the future: {} seconds ahead",
                timestamp - current
            ));
        }

        // Verify signature
        let expected = self.sign_with_timestamp(payload, timestamp);
        if signature != expected {
            return Err("Invalid signature".to_string());
        }

        Ok(())
    }

    /// Compute HMAC-SHA256
    fn hmac_sha256(&self, message: &str) -> String {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = match HmacSha256::new_from_slice(self.secret.as_bytes()) {
            Ok(mac) => mac,
            Err(_) => unreachable!("HMAC key can be of any size, as per crate documentation"),
        };

        mac.update(message.as_bytes());

        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Get current Unix timestamp in seconds
    fn current_timestamp(&self) -> Result<u64, SystemTimeError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
    }
}

/// Helper function to format signature for HTTP header
pub fn format_signature_header(signature: &str) -> String {
    format!("sha256={}", signature)
}

/// Helper function to parse signature from HTTP header
pub fn parse_signature_header(header: &str) -> Result<String, String> {
    if let Some(sig) = header.strip_prefix("sha256=") {
        Ok(sig.to_string())
    } else {
        Err(format!("Invalid signature header format: {header}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() -> Result<(), String> {
        let signer = HmacSigner::new("test-secret".to_string());
        let payload = r#"{"event":"test","data":"value"}"#;

        let (signature, timestamp) = signer.sign(payload).map_err(|e| e.to_string())?;

        // Verification should succeed
        signer.verify(payload, &signature, timestamp, 300)?;
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_wrong_signature() -> Result<(), SystemTimeError> {
        let signer = HmacSigner::new("test-secret".to_string());
        let payload = r#"{"event":"test"}"#;

        let (_, timestamp) = signer.sign(payload)?;
        let wrong_signature = "0000000000000000000000000000000000000000000000000000000000000000";

        let result = signer.verify(payload, wrong_signature, timestamp, 300);
        assert_eq!(result, Err("Invalid signature".to_string()));
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_wrong_secret() -> Result<(), SystemTimeError> {
        let signer1 = HmacSigner::new("secret1".to_string());
        let signer2 = HmacSigner::new("secret2".to_string());
        let payload = r#"{"event":"test"}"#;

        let (signature, timestamp) = signer1.sign(payload)?;

        // Verification with different secret should fail
        let result = signer2.verify(payload, &signature, timestamp, 300);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_verify_fails_with_modified_payload() -> Result<(), SystemTimeError> {
        let signer = HmacSigner::new("test-secret".to_string());
        let original = r#"{"event":"test","amount":100}"#;
        let modified = r#"{"event":"test","amount":999}"#;

        let (signature, timestamp) = signer.sign(original)?;

        // Verification with modified payload should fail
        let result = signer.verify(modified, &signature, timestamp, 300);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_timestamp_too_old() -> Result<(), SystemTimeError> {
        let signer = HmacSigner::new("test-secret".to_string());
        let payload = r#"{"event":"test"}"#;

        // Create signature with old timestamp (1 hour ago)
        let old_timestamp = signer.current_timestamp()? - 3600;
        let signature = signer.sign_with_timestamp(payload, old_timestamp);

        // Verification should fail (max age = 5 minutes = 300 seconds)
        let result = signer.verify(payload, &signature, old_timestamp, 300);
        assert!(matches!(result, Err(e) if e.contains("Timestamp too old")));
        Ok(())
    }

    #[test]
    fn test_timestamp_in_future() -> Result<(), SystemTimeError> {
        let signer = HmacSigner::new("test-secret".to_string());
        let payload = r#"{"event":"test"}"#;

        // Create signature with future timestamp (1 hour from now)
        let future_timestamp = signer.current_timestamp()? + 3600;
        let signature = signer.sign_with_timestamp(payload, future_timestamp);

        let result = signer.verify(payload, &signature, future_timestamp, 300);
        assert!(matches!(result, Err(e) if e.contains("future")));
        Ok(())
    }

    #[test]
    fn test_sign_with_specific_timestamp() {
        let signer = HmacSigner::new("test-secret".to_string());
        let payload = "test-payload";
        let timestamp = 1707574200u64;

        let signature = signer.sign_with_timestamp(payload, timestamp);

        // Signature should be deterministic
        let signature2 = signer.sign_with_timestamp(payload, timestamp);
        assert_eq!(signature, signature2);
    }

    #[test]
    fn test_different_payloads_different_signatures() {
        let signer = HmacSigner::new("test-secret".to_string());
        let timestamp = 1707574200u64;

        let sig1 = signer.sign_with_timestamp("payload1", timestamp);
        let sig2 = signer.sign_with_timestamp("payload2", timestamp);

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_different_timestamps_different_signatures() {
        let signer = HmacSigner::new("test-secret".to_string());
        let payload = "test-payload";

        let sig1 = signer.sign_with_timestamp(payload, 1000);
        let sig2 = signer.sign_with_timestamp(payload, 2000);

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_format_signature_header() {
        let signature = "abcdef123456";
        let header = format_signature_header(signature);
        assert_eq!(header, "sha256=abcdef123456");
    }

    #[test]
    fn test_parse_signature_header() -> Result<(), String> {
        let header = "sha256=abcdef123456";
        let signature = parse_signature_header(header)?;
        assert_eq!(signature, "abcdef123456");
        Ok(())
    }

    #[test]
    fn test_parse_invalid_signature_header() {
        let invalid = "md5=abcdef123456";
        let result = parse_signature_header(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_is_hex_encoded() -> Result<(), SystemTimeError> {
        let signer = HmacSigner::new("test-secret".to_string());
        let (signature, _) = signer.sign("test")?;

        // Should be valid hex (64 characters for SHA256)
        assert_eq!(signature.len(), 64);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_verify_with_custom_max_age() -> Result<(), String> {
        let signer = HmacSigner::new("test-secret".to_string());
        let payload = "test";

        let old_timestamp = signer.current_timestamp().map_err(|e| e.to_string())? - 100;
        let signature = signer.sign_with_timestamp(payload, old_timestamp);

        // Should fail with 60 second max age
        let result = signer.verify(payload, &signature, old_timestamp, 60);
        assert!(result.is_err());

        // Should succeed with 200 second max age
        signer.verify(payload, &signature, old_timestamp, 200)?;
        Ok(())
    }

    #[test]
    fn test_clock_skew_tolerance() -> Result<(), String> {
        let signer = HmacSigner::new("test-secret".to_string());
        let payload = "test";

        // 30 seconds in the future (within 60 second tolerance)
        let future_timestamp = signer.current_timestamp().map_err(|e| e.to_string())? + 30;
        let signature = signer.sign_with_timestamp(payload, future_timestamp);

        // Should succeed (within clock skew tolerance)
        signer.verify(payload, &signature, future_timestamp, 300)?;
        Ok(())
    }
}
