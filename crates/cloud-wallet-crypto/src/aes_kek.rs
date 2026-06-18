//! RFC 3394 AES Key Wrap (AES-KW) for JWE `A128KW` and `A256KW`.
//!
//! Wraps a CEK with a KEK (Key Encryption Key). The ciphertext is always
//! `plaintext.len() + 8` bytes. The plaintext must be a non-zero multiple
//! of 8 bytes and at least 16 bytes (AWS-LC constraint matching the spec).

use aws_lc_rs::key_wrap::{AES_128, AES_256, AesBlockCipher, AesKek, KeyWrap};

use crate::error::{ErrorKind, Result};
use crate::secret::Secret;
use crate::utils::error_msg;

/// AES Key Wrap algorithm — selects the KEK size.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// 128-bit KEK, corresponding to JWE `A128KW`.
    A128Kw,
    /// 256-bit KEK, corresponding to JWE `A256KW`.
    A256Kw,
}

impl KeyWrapAlgorithm {
    fn key_len(self) -> usize {
        match self {
            Self::A128Kw => 16,
            Self::A256Kw => 32,
        }
    }
}

impl From<KeyWrapAlgorithm> for &'static AesBlockCipher {
    fn from(alg: KeyWrapAlgorithm) -> Self {
        match alg {
            KeyWrapAlgorithm::A128Kw => &AES_128,
            KeyWrapAlgorithm::A256Kw => &AES_256,
        }
    }
}

/// AES key-encryption key for wrapping and unwrapping a CEK.
///
/// # Note on key schedule expansion
///
/// `aws_lc_rs::key_wrap::KeyWrap::wrap` and `::unwrap` take `self` by value
/// (the `AesKek` is consumed per call). We therefore store the raw key bytes
/// in `Secret` and recreate the `AesKek` on each `wrap`/`unwrap_key` call.
/// AES key expansion is O(key size) and extremely fast in practice (~μs on
/// modern hardware), so this is not a meaningful performance concern for the
/// wrap/unwrap use case.
///
/// # Example
///
/// ```rust
/// use cloud_wallet_crypto::aes_kek::{KeyEncryptionKey, KeyWrapAlgorithm};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let kek_bytes = [0u8; 16]; // 128-bit KEK for A128KW
/// let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &kek_bytes)?;
///
/// let cek = [0u8; 16];
/// let mut wrapped = vec![0u8; cek.len() + 8];
/// let ct = kek.wrap_key(&cek, &mut wrapped)?;
///
/// let kek2 = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &kek_bytes)?;
/// let mut plaintext = vec![0u8; ct.len() - 8];
/// let pt = kek2.unwrap_key(ct, &mut plaintext)?;
/// assert_eq!(pt, cek);
/// # Ok(())
/// # }
/// ```
pub struct KeyEncryptionKey {
    algorithm: KeyWrapAlgorithm,
    key: Secret,
}

impl std::fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEncryptionKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl KeyEncryptionKey {
    /// Construct a new KEK.
    ///
    /// # Errors
    /// [`ErrorKind::WrongLength`] if `key.len()` does not match the required
    /// size (16 for `A128Kw`, 32 for `A256Kw`).
    pub fn new(algorithm: KeyWrapAlgorithm, key: &[u8]) -> Result<Self> {
        if key.len() != algorithm.key_len() {
            return Err(error_msg(
                ErrorKind::WrongLength,
                format!(
                    "expected {}-byte KEK for {:?}, got {} bytes",
                    algorithm.key_len(),
                    algorithm,
                    key.len(),
                ),
            ));
        }
        Ok(Self {
            algorithm,
            key: Secret::new(key),
        })
    }

    fn make_aes_kek(&self) -> Result<AesKek> {
        AesKek::new(self.algorithm.into(), self.key.expose())
            .map_err(|_| error_msg(ErrorKind::KeyGeneration, "AES-KW key setup failed"))
    }

    /// Wrap `plaintext` (CEK) into `output`.
    ///
    /// `plaintext.len()` must be a multiple of 8 and at least 16 bytes.
    /// `output.len()` must be `>= plaintext.len() + 8`.
    ///
    /// Returns the filled sub-slice of `output`.
    ///
    /// # Errors
    /// - [`ErrorKind::WrongLength`] if the plaintext or output buffer size
    ///   constraints are not met.
    /// - [`ErrorKind::Encryption`] on cryptographic failure.
    pub fn wrap_key<'o>(&self, plaintext: &[u8], output: &'o mut [u8]) -> Result<&'o [u8]> {
        if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
            return Err(error_msg(
                ErrorKind::WrongLength,
                format!(
                    "AES-KW plaintext must be a multiple of 8 and at least 16 bytes, got {}",
                    plaintext.len()
                ),
            ));
        }
        let required = plaintext.len() + 8;
        if output.len() < required {
            return Err(error_msg(
                ErrorKind::WrongLength,
                format!(
                    "AES-KW output buffer must be at least {required} bytes, got {}",
                    output.len()
                ),
            ));
        }
        self.make_aes_kek()?
            .wrap(plaintext, output)
            .map(|s| &*s)
            .map_err(|_| error_msg(ErrorKind::Encryption, "AES key wrap failed"))
    }

    /// Unwrap `ciphertext` (wrapped CEK) into `output`.
    ///
    /// `ciphertext.len()` must be a multiple of 8 and at least 24 bytes
    /// (corresponding to a minimum 16-byte plaintext).
    /// `output.len()` must be `>= ciphertext.len() - 8`.
    ///
    /// Returns the filled sub-slice of `output`.
    ///
    /// # Errors
    /// - [`ErrorKind::WrongLength`] if the ciphertext or output buffer size
    ///   constraints are not met.
    /// - [`ErrorKind::Decryption`] on authentication failure, wrong size, etc.
    pub fn unwrap_key<'o>(&self, ciphertext: &[u8], output: &'o mut [u8]) -> Result<&'o [u8]> {
        if ciphertext.len() < 24 || !ciphertext.len().is_multiple_of(8) {
            return Err(error_msg(
                ErrorKind::WrongLength,
                format!(
                    "AES-KW ciphertext must be a multiple of 8 and at least 24 bytes, got {}",
                    ciphertext.len()
                ),
            ));
        }
        let required = ciphertext.len() - 8;
        if output.len() < required {
            return Err(error_msg(
                ErrorKind::WrongLength,
                format!(
                    "AES-KW output buffer must be at least {required} bytes, got {}",
                    output.len()
                ),
            ));
        }
        self.make_aes_kek()?
            .unwrap(ciphertext, output)
            .map(|s| &*s)
            .map_err(|_| error_msg(ErrorKind::Decryption, "AES key unwrap failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // RFC 3394 §2.2.1: 128-bit KEK, 128-bit key data
    const KEK_128: [u8; 16] = hex!("000102030405060708090A0B0C0D0E0F");
    const KEY_DATA: [u8; 16] = hex!("00112233445566778899AABBCCDDEEFF");
    const WRAPPED_A128KW: [u8; 24] = hex!("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

    // RFC 3394 §2.2.3: 256-bit KEK, 128-bit key data
    const KEK_256: [u8; 32] =
        hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const WRAPPED_A256KW: [u8; 24] = hex!("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");

    // RFC 3394 §2.2.6: 256-bit key data and expected ciphertext with the 256-bit KEK above.
    const KEY_DATA_256: [u8; 32] =
        hex!("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    const WRAPPED_A256KW_256: [u8; 40] =
        hex!("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");

    // Interoperability tests (RFC 3394 known-answer vectors)

    #[test]
    fn rfc3394_wrap_a128kw() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &KEK_128).unwrap();
        let mut out = [0u8; 24];
        let ct = kek.wrap_key(&KEY_DATA, &mut out).unwrap();
        assert_eq!(ct, &WRAPPED_A128KW);
    }

    #[test]
    fn rfc3394_unwrap_a128kw() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &KEK_128).unwrap();
        let mut out = [0u8; 16];
        let pt = kek.unwrap_key(&WRAPPED_A128KW, &mut out).unwrap();
        assert_eq!(pt, &KEY_DATA);
    }

    #[test]
    fn rfc3394_wrap_a256kw() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A256Kw, &KEK_256).unwrap();
        let mut out = [0u8; 24];
        let ct = kek.wrap_key(&KEY_DATA, &mut out).unwrap();
        assert_eq!(ct, &WRAPPED_A256KW);
    }

    #[test]
    fn rfc3394_unwrap_a256kw() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A256Kw, &KEK_256).unwrap();
        let mut out = [0u8; 16];
        let pt = kek.unwrap_key(&WRAPPED_A256KW, &mut out).unwrap();
        assert_eq!(pt, &KEY_DATA);
    }

    #[test]
    fn rfc3394_wrap_a256kw_256bit_key_data() {
        // RFC 3394 §2.2.6: 256-bit KEK wrapping 256-bit key data → known 40-byte ciphertext.
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A256Kw, &KEK_256).unwrap();
        let mut out = [0u8; 40];
        let ct = kek.wrap_key(&KEY_DATA_256, &mut out).unwrap();
        assert_eq!(ct, &WRAPPED_A256KW_256);
    }

    #[test]
    fn rfc3394_unwrap_a256kw_256bit_key_data() {
        // RFC 3394 §2.2.6: unwrap the known ciphertext back to the original key data.
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A256Kw, &KEK_256).unwrap();
        let mut out = [0u8; 32];
        let pt = kek.unwrap_key(&WRAPPED_A256KW_256, &mut out).unwrap();
        assert_eq!(pt, &KEY_DATA_256);
    }

    #[test]
    fn wrong_kek_length_rejected() {
        assert_eq!(
            KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &[0u8; 32])
                .unwrap_err()
                .kind(),
            ErrorKind::WrongLength,
        );
        assert_eq!(
            KeyEncryptionKey::new(KeyWrapAlgorithm::A256Kw, &[0u8; 16])
                .unwrap_err()
                .kind(),
            ErrorKind::WrongLength,
        );
    }

    #[test]
    fn plaintext_too_short_returns_wrong_length() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &KEK_128).unwrap();
        let mut out = [0u8; 16];
        // 8 bytes: multiple of 8 but below the 16-byte minimum
        assert_eq!(
            kek.wrap_key(&[0u8; 8], &mut out).unwrap_err().kind(),
            ErrorKind::WrongLength
        );
    }

    #[test]
    fn plaintext_not_multiple_of_8_returns_wrong_length() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &KEK_128).unwrap();
        let mut out = [0u8; 32];
        assert_eq!(
            kek.wrap_key(&[0u8; 17], &mut out).unwrap_err().kind(),
            ErrorKind::WrongLength
        );
    }

    #[test]
    fn wrap_output_too_small_returns_wrong_length() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &KEK_128).unwrap();
        let mut out = [0u8; 23]; // needs 24 for 16-byte input
        assert_eq!(
            kek.wrap_key(&KEY_DATA, &mut out).unwrap_err().kind(),
            ErrorKind::WrongLength
        );
    }

    #[test]
    fn ciphertext_too_short_returns_wrong_length() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &KEK_128).unwrap();
        let mut out = [0u8; 16];
        // 16 bytes: below the 24-byte minimum for unwrap input
        assert_eq!(
            kek.unwrap_key(&[0u8; 16], &mut out).unwrap_err().kind(),
            ErrorKind::WrongLength
        );
    }

    #[test]
    fn unwrap_output_too_small_returns_wrong_length() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &KEK_128).unwrap();
        let mut out = [0u8; 15]; // needs 16 for 24-byte ciphertext
        assert_eq!(
            kek.unwrap_key(&WRAPPED_A128KW, &mut out)
                .unwrap_err()
                .kind(),
            ErrorKind::WrongLength
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let kek = KeyEncryptionKey::new(KeyWrapAlgorithm::A128Kw, &KEK_128).unwrap();
        let mut tampered = WRAPPED_A128KW;
        tampered[0] ^= 0xff;
        let mut out = [0u8; 16];
        assert_eq!(
            kek.unwrap_key(&tampered, &mut out).unwrap_err().kind(),
            ErrorKind::Decryption
        );
    }
}
