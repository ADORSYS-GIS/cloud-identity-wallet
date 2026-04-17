use base64ct::{Base64UrlUnpadded, Encoding};
use cloud_wallet_crypto::rand;
use color_eyre::eyre::{Result, eyre};

pub fn generate_session_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes).map_err(|e| eyre!("Failed to generate random bytes: {e}"))?;
    Ok(format!("ses_{}", Base64UrlUnpadded::encode_string(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_id() {
        let id = generate_session_id().unwrap();
        assert!(id.starts_with("ses_"));
        // Prefix is 4 chars, 16 bytes base64url unpadded is 22 chars. Total 26 chars.
        assert_eq!(id.len(), 26);
    }

    #[test]
    fn test_generate_session_id_uniqueness() {
        let id1 = generate_session_id().unwrap();
        let id2 = generate_session_id().unwrap();
        assert_ne!(id1, id2);
    }
}
