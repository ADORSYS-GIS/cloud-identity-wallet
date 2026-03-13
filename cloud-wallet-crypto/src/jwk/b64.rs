use std::marker::PhantomData;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// A serde wrapper for base64-encoded bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct B64<E = Base64UrlUnpadded> {
    buf: Box<[u8]>,
    cfg: PhantomData<E>,
}

impl<E> B64<E> {
    /// Create a new B64 from a byte buffer.
    pub fn new(buf: impl Into<Box<[u8]>>) -> Self {
        Self {
            buf: buf.into(),
            cfg: PhantomData,
        }
    }
}

impl<E> std::ops::Deref for B64<E> {
    type Target = Box<[u8]>;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl<E> std::ops::DerefMut for B64<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl<E> AsRef<[u8]> for B64<E> {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_ref()
    }
}

impl<E> AsMut<[u8]> for B64<E> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut()
    }
}

impl<E> From<&[u8]> for B64<E> {
    fn from(buf: &[u8]) -> Self {
        Self::new(buf)
    }
}

impl<E> From<Vec<u8>> for B64<E> {
    fn from(buf: Vec<u8>) -> Self {
        Self::new(buf)
    }
}

impl<E> From<Box<[u8]>> for B64<E> {
    fn from(buf: Box<[u8]>) -> Self {
        Self::new(buf)
    }
}

impl<const N: usize, E> From<[u8; N]> for B64<E> {
    fn from(buf: [u8; N]) -> Self {
        Self::new(buf)
    }
}

impl<E: Encoding> Serialize for B64<E> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let b64 = E::encode_string(self.buf.as_ref());
        b64.serialize(serializer)
    }
}

impl<'de, E: Encoding> Deserialize<'de> for B64<E> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let enc = String::deserialize(deserializer)?;
        let dec = E::decode_vec(&enc).map_err(|_| D::Error::custom("invalid base64"))?;

        Ok(Self {
            cfg: PhantomData,
            buf: dec.into_boxed_slice(),
        })
    }
}

impl<E> Default for B64<E> {
    fn default() -> Self {
        Self {
            buf: Box::new([]),
            cfg: PhantomData,
        }
    }
}
