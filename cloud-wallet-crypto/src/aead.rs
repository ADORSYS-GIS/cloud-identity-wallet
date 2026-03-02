//! Authenticated Encryption with Associated Data (AEAD)
//!
//! # Supported Algorithms
//!
//! - `AES-128-GCM`: AES-GCM encryption with 128 bit key
//! - `AES-256-GCM`: AES-GCM encryption with 256 bit key
//! - `ChaCha20-Poly1305`: ChaCha20-Poly1305 as described in [RFC7539]
//!
//! All supported algorithms use 96 bit nonces and 128 bit authentication tags.
//!
//! # Basic Encryption/Decryption
//!
//! ```rust
//! use cloud_wallet_crypto::aead::{Algorithm, Key};
//! use cloud_wallet_crypto::rand;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a key
//! let key = Key::generate(Algorithm::AesGcm256)?;
//!
//! let message = b"Secret message";
//! let mut nonce = [0u8; 12];
//! rand::fill_bytes(&mut nonce)?;
//! let aad = b"metadata";
//!
//! // Encrypt the plaintext message with the given nonce
//! // and additional authenticated data (aad)
//! let mut in_out = message.to_vec();
//! let tag = key.encrypt(&nonce, aad, &mut in_out)?;
//!
//! // Decrypt the ciphertext with the given nonce and aad
//! let mut plaintext = vec![0u8; in_out.len()];
//! key.decrypt_with_tag(&nonce, aad, &tag, &in_out, &mut plaintext)?;
//! assert_eq!(message, plaintext.as_slice());
//! # Ok(())
//! # }
//! ```
//!
//! # Encryption/Decryption with Appended Tag
//!
//! ```rust
//! # use cloud_wallet_crypto::aead::{Algorithm, Key};
//! # use cloud_wallet_crypto::rand;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = Key::generate(Algorithm::AesGcm256)?;
//! let mut nonce = [0u8; 12];
//! rand::fill_bytes(&mut nonce)?;
//!
//! // Buffer automatically grows to append tag to the ciphertext
//! let mut in_out = Vec::from(*b"Secret message");
//! key.encrypt_append_tag(&nonce, b"", &mut in_out)?;
//!
//! // Decrypt the ciphertext with the appended tag
//! let plaintext = key.decrypt(&nonce, b"", &mut in_out)?;
//! assert_eq!(plaintext, b"Secret message");
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! Nonces must be unique for each key. Nonce reuse completely breaks AEAD security.
//!
//! ## Safe Nonce Strategies
//!
//! 1. Random nonces:
//!    ```rust
//!    # use cloud_wallet_crypto::aead::{Algorithm, Key};
//!    # let key = Key::generate(Algorithm::AesGcm256)?;
//!    let mut nonce = [0u8; 12];
//!    cloud_wallet_crypto::rand::fill_bytes(&mut nonce)?;
//!    # Ok::<(), Box<dyn std::error::Error>>(())
//!    ```
//!
//! 2. Counter nonces (when state can be maintained):
//!    - Maintain a strictly increasing counter
//!    - Never allow counter rollover
//!    - Store counter state persistently
//!
//! 3. Derived nonces (for message-based protocols):
//!    - Derive from unique message IDs or timestamps
//!    - Ensure derivation produces unique values
//!
//! ## Additional Authenticated Data (AAD)
//!
//! AAD is authenticated but not encrypted and must match
//! exactly between encryption and decryption.
//!
//! [RFC7539]: https://datatracker.ietf.org/doc/html/rfc7539

use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use crate::utils::error_msg;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

/// All the supported algorithms use a 96-bit nonce.
pub const NONCE_LENGTH: usize = 12;
/// All the supported algorithms use a 128-bit authentication tag.
pub const TAG_LENGTH: usize = 16;

/// Maximum supported key length.
const MAX_KEY_LENGTH: usize = 32;

/// AEAD encryption algorithms.
///
/// All algorithms provide:
/// - Authenticated encryption (confidentiality + integrity)
/// - 96-bit nonces and 128-bit authentication tags
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Algorithm {
    /// AES-GCM with 128-bit key
    AesGcm128,

    /// AES-GCM with 256-bit key
    AesGcm256,

    /// ChaCha20-Poly1305 with 256-bit key.
    ///
    /// See [RFC7539](https://datatracker.ietf.org/doc/html/rfc7539)
    ChaCha20Poly1305,
}

impl Algorithm {
    /// Returns the key size in bytes for this algorithm.
    #[inline]
    pub fn key_len(&self) -> usize {
        match self {
            Algorithm::AesGcm128 => 16,
            Algorithm::AesGcm256 | Algorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Returns the nonce length in bytes.
    ///
    /// All the supported algorithms in this library use a 96 bit nonces.
    #[inline]
    pub const fn nonce_len(&self) -> usize {
        NONCE_LENGTH
    }

    /// Returns the authentication tag length in bytes.
    ///
    /// All the supported algorithms in this library use a 128 bit authentication tags.
    #[inline]
    pub const fn tag_len(&self) -> usize {
        TAG_LENGTH
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::AesGcm128 => write!(f, "AES-128-GCM"),
            Algorithm::AesGcm256 => write!(f, "AES-256-GCM"),
            Algorithm::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

/// An AEAD encryption key.
///
/// Keys can encrypt and decrypt data with authentication.
#[derive(Debug, Clone)]
pub struct Key {
    alg: Algorithm,
    inner: Secret,
}

impl Key {
    /// Creates a new key from raw key material.
    ///
    /// The key material length must exactly match the algorithm's key size:
    /// - `AES-128-GCM`: 16 bytes
    /// - `AES-256-GCM`: 32 bytes
    /// - `ChaCha20-Poly1305`: 32 bytes
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::aead::{Algorithm, Key};
    /// # use cloud_wallet_crypto::rand;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // From secure random bytes
    /// let mut key_bytes = [0u8; 32];
    /// rand::fill_bytes(&mut key_bytes)?;
    /// let key = Key::new(Algorithm::AesGcm256, key_bytes)?;
    ///
    /// // Wrong length will fail
    /// let wrong_key = Key::new(Algorithm::AesGcm256, [0u8; 16]);
    /// assert!(wrong_key.is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::WrongLength` if the key material length doesn't
    /// match the algorithm's required key size.
    pub fn new(alg: Algorithm, key: impl Into<Secret>) -> Result<Self> {
        let inner = key.into();
        if inner.len() != alg.key_len() {
            return Err(Error::message(
                ErrorKind::WrongLength,
                "Key length does not match algorithm",
            ));
        }
        Ok(Self { alg, inner })
    }

    /// Generates a new random key using cryptographically secure RNG.
    ///
    /// # Errors
    ///
    /// Returns an error if random number generation fails (rare).
    pub fn generate(alg: Algorithm) -> Result<Self> {
        let key_len = alg.key_len();
        let mut buff = [0u8; MAX_KEY_LENGTH];
        crate::rand::fill_bytes(&mut buff[..key_len])?;
        let inner = Secret::from(&buff[..key_len]);
        Ok(Self { alg, inner })
    }

    /// Encrypts the given message, returning the authentication tag.
    ///
    /// The input buffer is encrypted in-place (plaintext → ciphertext), and a
    /// 16-byte authentication tag is returned.
    ///
    /// `nonce` must be unique for each key.
    /// `aad` additional authenticated data is not encrypted, but authenticated and can be empty.
    /// `in_out` is the buffer containing plaintext and will be overwritten with ciphertext.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::aead::{Algorithm, Key};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key = Key::generate(Algorithm::AesGcm256)?;
    /// let mut nonce = [0u8; 12];
    /// cloud_wallet_crypto::rand::fill_bytes(&mut nonce)?;
    ///
    /// let mut data = *b"Secret message";
    /// let tag = key.encrypt(&nonce, b"", &mut data)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Encryption` if encryption fails.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: impl AsRef<[u8]>,
        in_out: &mut [u8],
    ) -> Result<[u8; TAG_LENGTH]> {
        // SAFETY: The inner key has always the correct length
        // We enforce this during the construction
        let key = UnboundKey::new(self.alg.into(), self.inner.expose()).unwrap();
        let sealing_key = LessSafeKey::new(key);
        let nonce = Nonce::assume_unique_for_key(*nonce);

        let tag = sealing_key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), in_out)
            .map_err(|_| error_msg(ErrorKind::Encryption, "Failed to seal plaintext"))?;

        let mut tag_array = [0u8; TAG_LENGTH];
        tag_array.copy_from_slice(tag.as_ref());
        Ok(tag_array)
    }

    /// Encrypts the given message and append the authentication tag to the ciphertext.
    ///
    /// This is a convenience method that automatically appends the 16-byte
    /// authentication tag to the produced ciphertext.
    ///
    /// `nonce` must be unique for each key.
    /// `aad` additional authenticated data is not encrypted, but authenticated and can be empty.
    /// `in_out` is the buffer containing plaintext and will be overwritten with ciphertext + tag.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::aead::{Algorithm, Key};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key = Key::generate(Algorithm::AesGcm256)?;
    /// let mut nonce = [0u8; 12];
    /// cloud_wallet_crypto::rand::fill_bytes(&mut nonce)?;
    ///
    /// // Encrypts the message and append the tag to the ciphertext
    /// let mut in_out = Vec::from(*b"Secret");
    /// key.encrypt_append_tag(&nonce, b"", &mut in_out)?;
    ///
    /// assert_eq!(in_out.len(), 6 + 16); // plaintext + tag
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Encryption` if encryption fails.
    pub fn encrypt_append_tag<T>(
        &self,
        nonce: &[u8; 12],
        aad: impl AsRef<[u8]>,
        in_out: &mut T,
    ) -> Result<()>
    where
        T: AsMut<[u8]> + for<'a> Extend<&'a u8>,
    {
        // SAFETY: The inner key has always the correct length
        // We enforce this in the constructor
        let key = UnboundKey::new(self.alg.into(), self.inner.expose()).unwrap();
        let sealing_key = LessSafeKey::new(key);
        let nonce = Nonce::assume_unique_for_key(*nonce);

        sealing_key
            .seal_in_place_append_tag(nonce, Aad::from(aad), in_out)
            .map_err(|_| error_msg(ErrorKind::Encryption, "Failed to seal plaintext"))?;
        Ok(())
    }

    /// Decrypts and verifies the given message.
    ///
    /// The `cipher_inout` buffer must contain both ciphertext and the authentication
    /// tag appended. After successful verification and decryption, returns a mutable
    /// slice to the plaintext without the tag.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::aead::{Algorithm, Key};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key = Key::generate(Algorithm::AesGcm256)?;
    /// let mut nonce = [0u8; 12];
    /// cloud_wallet_crypto::rand::fill_bytes(&mut nonce)?;
    ///
    /// // Encrypt
    /// let mut in_out = Vec::from(*b"Secret message");
    /// key.encrypt_append_tag(&nonce, b"", &mut in_out)?;
    ///
    /// // Decrypt (buffer contains ciphertext + tag)
    /// let plaintext = key.decrypt(&nonce, b"", &mut in_out)?;
    /// assert_eq!(plaintext, b"Secret message");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Decryption`] if:
    /// - Authentication tag verification fails
    /// - Nonce doesn't match the one used during encryption
    /// - AAD doesn't match the one used during encryption
    /// - Decryption fails for any other reason
    pub fn decrypt<'a>(
        &self,
        nonce: &[u8; 12],
        aad: impl AsRef<[u8]>,
        cipher_inout: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        // SAFETY: The inner key has always the correct length
        // We enforce this in the constructor
        let key = UnboundKey::new(self.alg.into(), self.inner.expose()).unwrap();
        let opening_key = LessSafeKey::new(key);
        let nonce = Nonce::assume_unique_for_key(*nonce);

        let ciphertext = opening_key
            .open_in_place(nonce, Aad::from(aad), cipher_inout)
            .map_err(|_| error_msg(ErrorKind::Decryption, "Failed to decrypt ciphertext"))?;
        Ok(ciphertext)
    }

    /// Decrypts and verifies the given ciphertext.
    ///
    /// This method is useful when the ciphertext and authentication tag are stored
    /// separately. The plaintext is written to the provided `plaintext` buffer.
    ///
    /// # Buffer Requirements
    ///
    /// The `plaintext` buffer must be at least as large as the `ciphertext`.
    /// After decryption, the first `ciphertext.len()` bytes of `plaintext`
    /// will contain the decrypted data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::aead::{Algorithm, Key};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key = Key::generate(Algorithm::ChaCha20Poly1305)?;
    /// let mut nonce = [0u8; 12];
    /// cloud_wallet_crypto::rand::fill_bytes(&mut nonce)?;
    ///
    /// // Encrypt the message. The tag will be returned
    /// let mut message = *b"Secret message";
    /// let tag = key.encrypt(&nonce, b"", &mut message)?;
    /// let ciphertext = message;
    ///
    /// // Decrypt with separate tag
    /// let mut plaintext = vec![0u8; ciphertext.len()];
    /// key.decrypt_with_tag(&nonce, b"", &tag, &ciphertext, &mut plaintext)?;
    /// assert_eq!(&*plaintext, b"Secret message");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Decryption`] if:
    /// - Authentication tag verification fails
    /// - Any of the parameters don't match encryption
    /// - The plaintext buffer is too small
    pub fn decrypt_with_tag(
        &self,
        nonce: &[u8; 12],
        aad: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        plaintext: &mut [u8],
    ) -> Result<()> {
        // SAFETY: The inner key has always the correct length
        // We enforce this in the constructor
        let key = UnboundKey::new(self.alg.into(), self.inner.expose()).unwrap();
        let opening_key = LessSafeKey::new(key);
        let nonce = Nonce::assume_unique_for_key(*nonce);

        opening_key
            .open_separate_gather(
                nonce,
                Aad::from(aad),
                ciphertext.as_ref(),
                tag.as_ref(),
                plaintext,
            )
            .map_err(|_| error_msg(ErrorKind::Decryption, "Failed to decrypt ciphertext"))?;
        Ok(())
    }

    /// Returns the algorithm used by this key.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.alg
    }
}

impl From<Algorithm> for &'static aws_lc_rs::aead::Algorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::AesGcm128 => &aws_lc_rs::aead::AES_128_GCM,
            Algorithm::AesGcm256 => &aws_lc_rs::aead::AES_256_GCM,
            Algorithm::ChaCha20Poly1305 => &aws_lc_rs::aead::CHACHA20_POLY1305,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand;

    #[test]
    fn test_key_len() {
        assert_eq!(Algorithm::AesGcm128.key_len(), 16);
        assert_eq!(Algorithm::AesGcm256.key_len(), 32);
        assert_eq!(Algorithm::ChaCha20Poly1305.key_len(), 32);
    }

    #[test]
    fn test_key_new() {
        let key_bytes = [0u8; 16];
        let key = Key::new(Algorithm::AesGcm128, key_bytes).unwrap();
        assert_eq!(key.algorithm(), Algorithm::AesGcm128);

        let key_bytes = [0u8; 32];
        let key = Key::new(Algorithm::AesGcm256, key_bytes).unwrap();
        assert_eq!(key.algorithm(), Algorithm::AesGcm256);

        let key_bytes = [0u8; 32];
        let key = Key::new(Algorithm::ChaCha20Poly1305, key_bytes).unwrap();
        assert_eq!(key.algorithm(), Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn test_key_new_wrong_length() {
        let key_bytes = [0u8; 32];
        let err = Key::new(Algorithm::AesGcm128, key_bytes).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrongLength);

        let key_bytes = [0u8; 16];
        let err = Key::new(Algorithm::AesGcm256, key_bytes).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrongLength);

        let key_bytes = [0u8; 16];
        let err = Key::new(Algorithm::ChaCha20Poly1305, key_bytes).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrongLength);
    }

    #[test]
    fn test_key_generate() {
        let key = Key::generate(Algorithm::AesGcm128).unwrap();
        assert_eq!(key.algorithm(), Algorithm::AesGcm128);
        assert_eq!(key.inner.len(), 16);

        let key = Key::generate(Algorithm::AesGcm256).unwrap();
        assert_eq!(key.algorithm(), Algorithm::AesGcm256);
        assert_eq!(key.inner.len(), 32);

        let key = Key::generate(Algorithm::ChaCha20Poly1305).unwrap();
        assert_eq!(key.algorithm(), Algorithm::ChaCha20Poly1305);
        assert_eq!(key.inner.len(), 32);
    }

    fn test_encrypt_decrypt_cycle(alg: Algorithm) {
        let key = Key::generate(alg).unwrap();
        let mut nonce = [0u8; 12];
        rand::fill_bytes(&mut nonce).unwrap();
        let aad = b"additional data";
        let message = b"secret message";

        // Test with encrypt_append_tag and decrypt
        let mut in_out = message.to_vec();
        key.encrypt_append_tag(&nonce, aad, &mut in_out).unwrap();
        let plaintext = key.decrypt(&nonce, aad, &mut in_out).unwrap();
        assert_eq!(plaintext, message);

        // Test with encrypt and decrypt_with_tag
        let mut in_out = message.to_vec();
        let tag = key.encrypt(&nonce, aad, &mut in_out).unwrap();
        let mut plaintext = vec![0u8; message.len()];
        key.decrypt_with_tag(&nonce, aad, tag, &in_out, &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, message);
    }

    #[test]
    fn test_encrypt_decrypt_cycles() {
        test_encrypt_decrypt_cycle(Algorithm::AesGcm128);
        test_encrypt_decrypt_cycle(Algorithm::AesGcm256);
        test_encrypt_decrypt_cycle(Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn test_decryption_failure() {
        let alg = Algorithm::AesGcm256;
        let key = Key::generate(alg).unwrap();
        let wrong_key = Key::generate(alg).unwrap();
        let mut nonce = [0u8; 12];
        rand::fill_bytes(&mut nonce).unwrap();
        let mut wrong_nonce = [0u8; 12];
        rand::fill_bytes(&mut wrong_nonce).unwrap();
        let aad = b"additional data";
        let wrong_aad = b"wrong additional data";
        let message = b"secret message";

        let mut in_out = message.to_vec();
        key.encrypt_append_tag(&nonce, aad, &mut in_out).unwrap();

        // Wrong key
        let mut ciphertext = in_out.clone();
        let err = wrong_key.decrypt(&nonce, aad, &mut ciphertext).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decryption);

        // Wrong nonce
        let mut ciphertext = in_out.clone();
        let err = key
            .decrypt(&wrong_nonce, aad, &mut ciphertext)
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decryption);

        // Wrong AAD
        let mut ciphertext = in_out.clone();
        let err = key.decrypt(&nonce, wrong_aad, &mut ciphertext).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decryption);

        // Corrupted ciphertext
        let mut ciphertext = in_out.clone();
        ciphertext[0] ^= 1;
        let err = key.decrypt(&nonce, aad, &mut ciphertext).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decryption);

        // Corrupted tag
        let mut ciphertext = in_out;
        let tag_start = ciphertext.len() - TAG_LENGTH;
        ciphertext[tag_start] ^= 1;
        let err = key.decrypt(&nonce, aad, &mut ciphertext).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Decryption);
    }

    #[test]
    fn test_chacha20_poly1305() {
        // from RFC7539
        let k = Key::new(Algorithm::ChaCha20Poly1305, [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ]).unwrap();
        let mut buffer = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        let tag = k.encrypt(&nonce, aad, &mut buffer[..]).unwrap();

        assert_eq!(
            buffer,
            [
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
                0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
                0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
                0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
                0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
                0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                0x61, 0x16
            ]
        );
        assert_eq!(
            tag,
            [
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
                0x06, 0x91
            ]
        );
    }
}
