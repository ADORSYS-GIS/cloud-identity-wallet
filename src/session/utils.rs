use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub fn generate_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    format!("ses_{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_id() {
        let id = generate_session_id();
        assert!(id.starts_with("ses_"));
        // Prefix is 4 chars, 16 bytes base64url unpadded is 22 chars. Total 26 chars.
        assert_eq!(id.len(), 26);
    }

    #[test]
    fn test_generate_session_id_uniqueness() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert_ne!(id1, id2);
    }
}
