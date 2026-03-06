//! A wrapper type for secret data that controls secret exposure and zeroizes secret data on drop.
//!
//! It provides various `From` implementations for different types of secret data
//! so `Secret` can be created easily from common types like `[T; N]`, `&[T]`, `Vec<T>`, etc.
//!
//! # Basic Usage
//!
//! ```
//! use cloud_wallet_crypto::secret::Secret;
//!
//! // Create a new secret
//! let secret = Secret::new(b"my-secret-data");
//! // or
//! let secret = Secret::from([1, 2, 3, 4, 5]);
//! // or
//! let secret = Secret::from(vec![1, 2, 3, 4, 5]);
//!
//! // The secret can be accessed using the `expose` or `expose_mut` method
//! let secret_data = secret.expose();
//! ```

#[cfg(feature = "jwk")]
use base64ct::{Base64UrlUnpadded, Encoding};
#[cfg(feature = "jwk")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure wrapper for sensitive bytes that zeroizes on drop.
/// It attempts to limit the exposure of the secret data as much as possible.
///
/// Use [`Secret::expose`] or [`Secret::expose_mut`] to access the inner secret data.
pub struct Secret<T: Zeroize = u8> {
    inner: Box<[T]>,
}

impl<T: Zeroize> Secret<T> {
    /// Create a new secret from the given raw data
    pub fn new(secret: impl Into<Vec<T>>) -> Self {
        Self {
            inner: secret.into().into_boxed_slice(),
        }
    }

    /// Expose the secret data as a slice.
    ///
    /// # Safety
    ///
    /// This method exposes the secret data.
    /// The caller must ensure that the secret data is not accessed after the secret is dropped.
    pub fn expose(&self) -> &[T] {
        &self.inner
    }

    /// Expose the secret data as a mutable slice.
    ///
    /// # Safety
    ///
    /// This method exposes the secret data.
    /// The caller must ensure that the secret data is not accessed after the secret is dropped.
    pub fn expose_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }

    /// Returns the length of the secret data
    pub fn len(&self) -> usize {
        self.expose().len()
    }

    /// Returns true if this secret has no data
    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }
}

impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(&format!("Secret<{}>", std::any::type_name::<T>()))
            .finish()
    }
}

impl<T: Zeroize> Zeroize for Secret<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: Zeroize + ConstantTimeEq> ConstantTimeEq for Secret<T> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.inner.as_ref().ct_eq(other.inner.as_ref())
    }
}

impl<T: Zeroize + ConstantTimeEq> Eq for Secret<T> {}
impl<T: Zeroize + ConstantTimeEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<T: Zeroize + Clone> From<&[T]> for Secret<T> {
    fn from(value: &[T]) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> From<Vec<T>> for Secret<T> {
    fn from(value: Vec<T>) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize, const N: usize> From<[T; N]> for Secret<T> {
    fn from(value: [T; N]) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> From<Box<[T]>> for Secret<T> {
    fn from(value: Box<[T]>) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize + Default> Default for Secret<T> {
    fn default() -> Self {
        Self {
            inner: Box::<[T]>::default(),
        }
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(feature = "jwk")]
impl Serialize for Secret<u8> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let encoded = Base64UrlUnpadded::encode_string(self.expose());
            serializer.serialize_str(&encoded)
        } else {
            Err(ser::Error::custom(
                "Binary serialization of secrets is not supported",
            ))
        }
    }
}

#[cfg(feature = "jwk")]
impl<'de> Deserialize<'de> for Secret<u8> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: String = Deserialize::deserialize(deserializer)?;
            let decoded = Base64UrlUnpadded::decode_vec(&s)
                .map_err(|e| de::Error::custom(format!("Invalid base64url data: {e}")))?;
            Ok(Secret::new(decoded))
        } else {
            Err(de::Error::custom(
                "Binary deserialization of secrets is not supported",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mut_exposure() {
        let mut secret = Secret::new(vec![1, 2, 3]);
        secret.expose_mut()[1] = 5;
        assert_eq!(secret.expose(), &[1, 5, 3]);
    }

    #[test]
    fn test_zeroize() {
        let mut secret = Secret::new(vec![1, 2, 3, 4, 5]);
        secret.zeroize();
        assert_eq!(secret.expose(), &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_debug_format() {
        let secret = Secret::<u8>::new(b"supersecret".to_vec());
        let debug_str = format!("{:?}", secret);
        assert!(!debug_str.contains("supersecret"));
        assert!(debug_str.contains("Secret<u8>"));
    }
}
