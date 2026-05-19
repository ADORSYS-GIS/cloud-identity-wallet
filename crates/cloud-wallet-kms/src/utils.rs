use cloud_wallet_crypto::digest;

const MASTER_KEY_PREFIX: &str = "mk-";
const DATA_KEY_PREFIX: &str = "dek-";

/// Generate a unique, deterministic master key ID from hostname
#[inline]
pub(crate) fn generate_mk_id(hostname: &str) -> String {
    generate_id(MASTER_KEY_PREFIX, hostname)
}

/// Generate a unique, deterministic data key ID from hostname
#[inline]
pub(crate) fn generate_dek_id(hostname: &str) -> String {
    generate_id(DATA_KEY_PREFIX, hostname)
}

// Generate a unique, 16 characters long ID from prefix + hostname
fn generate_id(prefix: &str, hostname: &str) -> String {
    use base64ct::{Base64Unpadded, Encoding};

    let input = format!("{}{}", prefix, hostname);
    let hash = digest::HashAlg::Sha256.hash(input.as_bytes());
    Base64Unpadded::encode_string(&hash.as_ref()[..12])
}
