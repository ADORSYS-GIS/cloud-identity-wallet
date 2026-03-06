//! SHA-2 and SHA-3 cryptographic hash functions.
//!
//! # Computing Digests
//!
//! There are two primary APIs for computing digests, each serving a different purpose:
//!
//! - One-shot hashing: The [`HashAlg::hash`] method is designed for cases where you have
//!   the entire input data available at once. It is a convenience method that handles
//!   initialization, updating, and finalization in a single step.
//!
//! - Incremental hashing: The [`Hasher`] struct is designed for cases where the input data
//!   is streamed or available in chunks. It allows to maintain the state of the hash
//!   computation and update it as new data arrives.
//!
//! # Examples
//!
//! ## One-shot hashing
//!
//! ```
//! use cloud_wallet_crypto::digest::HashAlg;
//! use hex_literal::hex;
//!
//! let data = b"hello, world";
//! let digest = HashAlg::Sha256.hash(data);
//!
//! assert_eq!(digest.as_ref(), hex!("09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b"));
//! ```
//!
//! ## Incremental hashing
//!
//! ```
//! use cloud_wallet_crypto::digest::{HashAlg, Hasher};
//! use hex_literal::hex;
//!
//! let mut hasher = Hasher::new(HashAlg::Sha256);
//! hasher.update(b"hello");
//! hasher.update(b", ");
//! hasher.update(b"world");
//! let digest = hasher.finalize();
//!
//! assert_eq!(digest.as_ref(), hex!("09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b"));
//! ```

use aws_lc_rs::digest::{self, Context as HashContext};

/// Maximum output length of any hash algorithm in this module.
pub const MAX_OUTPUT_LEN: usize = 64;

/// `SHA-2` and `SHA-3` hash algorithms,
/// as specified in [FIPS 180-4] and [FIPS 202] respectively.
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
/// [FIPS 202]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HashAlg {
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
    /// SHA3-256
    Sha3_256,
    /// SHA3-384
    Sha3_384,
    /// SHA3-512
    Sha3_512,
}

/// A hasher for a specific hash algorithm.
///
/// # Example
///
/// ```
/// use cloud_wallet_crypto::digest::{HashAlg, Hasher};
///
/// let mut hasher = Hasher::new(HashAlg::Sha256);
/// hasher.update(b"hello, world");
/// let hash = hasher.finalize();
/// ```
pub struct Hasher {
    algorithm: HashAlg,
    context: HashContext,
}

impl Hasher {
    /// Creates a new hasher for the specified hash algorithm.
    #[inline]
    pub fn new(algorithm: HashAlg) -> Self {
        Self {
            algorithm,
            context: HashContext::new(algorithm.into()),
        }
    }

    /// Feed data into the hasher.
    #[inline]
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.context.update(data.as_ref());
    }

    /// Finalizes the computation and returns the digest.
    #[inline]
    pub fn finalize(self) -> Digest {
        let digest = self.context.finish();
        Digest::new(self.algorithm, digest.as_ref())
    }

    /// Returns the hash algorithm used by this hasher.
    pub fn algorithm(&self) -> HashAlg {
        self.algorithm
    }
}

impl HashAlg {
    /// Hash the given data using this algorithm and returns its digest.
    ///
    /// # Examples
    ///
    /// ```
    /// use cloud_wallet_crypto::digest::HashAlg;
    /// use hex_literal::hex;
    ///
    /// let expected = hex!("09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b");
    /// let hash = HashAlg::Sha256.hash("hello, world");
    /// assert_eq!(hash.as_ref(), expected);
    /// ```
    pub fn hash(&self, data: impl AsRef<[u8]>) -> Digest {
        let algorithm: &digest::Algorithm = (*self).into();
        let digest = digest::digest(algorithm, data.as_ref());
        Digest::new(*self, digest.as_ref())
    }

    /// Get the size of the hash output produced by this algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use cloud_wallet_crypto::digest::HashAlg;
    ///
    /// assert_eq!(HashAlg::Sha256.digest_size(), 32);
    /// assert_eq!(HashAlg::Sha384.digest_size(), 48);
    /// assert_eq!(HashAlg::Sha512.digest_size(), 64);
    /// ```
    pub fn digest_size(self) -> usize {
        match self {
            HashAlg::Sha224 => 28,
            HashAlg::Sha256 | HashAlg::Sha3_256 => 32,
            HashAlg::Sha384 | HashAlg::Sha3_384 => 48,
            HashAlg::Sha512 | HashAlg::Sha3_512 => 64,
        }
    }
}

impl From<HashAlg> for &'static digest::Algorithm {
    fn from(alg: HashAlg) -> Self {
        match alg {
            HashAlg::Sha224 => &digest::SHA224,
            HashAlg::Sha256 => &digest::SHA256,
            HashAlg::Sha384 => &digest::SHA384,
            HashAlg::Sha512 => &digest::SHA512,
            HashAlg::Sha3_256 => &digest::SHA3_256,
            HashAlg::Sha3_384 => &digest::SHA3_384,
            HashAlg::Sha3_512 => &digest::SHA3_512,
        }
    }
}

impl std::fmt::Display for HashAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            HashAlg::Sha224 => "SHA-224",
            HashAlg::Sha256 => "SHA-256",
            HashAlg::Sha384 => "SHA-384",
            HashAlg::Sha512 => "SHA-512",
            HashAlg::Sha3_256 => "SHA3-256",
            HashAlg::Sha3_384 => "SHA3-384",
            HashAlg::Sha3_512 => "SHA3-512",
        };
        write!(f, "{name}")
    }
}

/// A digest value produced by the hash function.
///
/// To access the digest value as a byte slice, use [`Self::as_ref()`] or [`Self::as_mut()`].
#[derive(Clone, Copy)]
pub struct Digest {
    algorithm: HashAlg,
    value: [u8; MAX_OUTPUT_LEN],
}

impl Digest {
    fn new(algorithm: HashAlg, bytes: &[u8]) -> Self {
        let mut value = [0u8; MAX_OUTPUT_LEN];
        value[..algorithm.digest_size()].copy_from_slice(bytes);
        Self { algorithm, value }
    }

    /// Get the hash algorithm used to produce this digest.
    pub fn algorithm(&self) -> HashAlg {
        self.algorithm
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.value == other.value
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.algorithm.digest_size()]
    }
}

impl AsMut<[u8]> for Digest {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.value[..self.algorithm.digest_size()]
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: ", self.algorithm)?;
        for byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_sha256_vectors() {
        // Test vector from FIPS 180-4 or similar standard sources
        // "abc"
        let data = b"abc";
        let expected = hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(HashAlg::Sha256.hash(data).as_ref(), expected);

        // empty string
        let data = b"";
        let expected = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(HashAlg::Sha256.hash(data).as_ref(), expected);
    }

    #[test]
    fn test_incremental_hashing() {
        let part1 = b"The quick brown ";
        let part2 = b"fox jumps over ";
        let part3 = b"the lazy dog";
        let full = b"The quick brown fox jumps over the lazy dog";

        let algs = [
            HashAlg::Sha224,
            HashAlg::Sha256,
            HashAlg::Sha384,
            HashAlg::Sha512,
            HashAlg::Sha3_256,
            HashAlg::Sha3_384,
            HashAlg::Sha3_512,
        ];

        for alg in algs {
            let mut hasher = Hasher::new(alg);
            hasher.update(part1);
            hasher.update(part2);
            hasher.update(part3);
            let digest_incremental = hasher.finalize();

            let digest_oneshot = alg.hash(full);

            assert_eq!(digest_incremental, digest_oneshot);
        }
    }

    #[test]
    fn test_digest_sizes() {
        assert_eq!(HashAlg::Sha224.hash(b"").as_ref().len(), 28);
        assert_eq!(HashAlg::Sha256.hash(b"").as_ref().len(), 32);
        assert_eq!(HashAlg::Sha384.hash(b"").as_ref().len(), 48);
        assert_eq!(HashAlg::Sha512.hash(b"").as_ref().len(), 64);
        assert_eq!(HashAlg::Sha3_256.hash(b"").as_ref().len(), 32);
        assert_eq!(HashAlg::Sha3_384.hash(b"").as_ref().len(), 48);
        assert_eq!(HashAlg::Sha3_512.hash(b"").as_ref().len(), 64);
    }

    #[test]
    fn test_hasher_algorithm_getter() {
        let hasher = Hasher::new(HashAlg::Sha256);
        assert_eq!(hasher.algorithm(), HashAlg::Sha256);
    }

    #[test]
    fn test_display_impl() {
        assert_eq!(format!("{}", HashAlg::Sha256), "SHA-256");
        assert_eq!(format!("{}", HashAlg::Sha3_256), "SHA3-256");
    }
}
