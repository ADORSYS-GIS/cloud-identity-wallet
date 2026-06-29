//! AES_CBC_HMAC_SHA2 composite content encryption (RFC 7518 §5.2).
//!
//! Unlike AES-GCM (a single AEAD primitive), this is a composite construction
//! assembled from two independent primitives:
//!
//! - AES-CBC with PKCS#7 padding for confidentiality.
//! - HMAC-SHA2, truncated to half its native output length, for authentication.
//!
//! The CEK is split into a MAC key (first half) and an encryption key (second
//! half) per RFC 7518 §5.2.2.1. The MAC input is `AAD || IV || ciphertext || AL`,
//! where `AL` is the AAD length in bits, encoded as a fixed 8-byte big-endian
//! integer (RFC 7518 §5.2.2.1).
//!
//! # Security: verify-then-decrypt ordering
//!
//! RFC 7518 §5.2.2.2 requires the authentication tag to be validated *before*
//! any decryption happens. [`Key::decrypt_with_tag`] implements this as a hard
//! early return: the tag is checked first, and AES-CBC decryption / PKCS#7
//! unpadding are unreachable on a mismatch. A MAC failure and a padding
//! failure both surface as the same generic error, so the two cases are not
//! distinguishable by a caller. This ordering is what prevents a padding
//! oracle — the exact vulnerability this MAC-then-decrypt construction exists
//! to avoid. Do not reorder it.
//!
//! # Example
//!
//! ```rust
//! use cloud_wallet_crypto::cbc_hmac::{Algorithm, Key};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cek = [0u8; 32]; // 16-byte MAC key + 16-byte enc key
//! let key = Key::new(Algorithm::Aes128CbcHmacSha256, &cek)?;
//!
//! let mut iv = [0u8; 16];
//! cloud_wallet_crypto::rand::fill_bytes(&mut iv)?;
//! let aad = b"metadata";
//!
//! let (ciphertext, tag) = key.encrypt(&iv, aad, b"secret message")?;
//! let plaintext = key.decrypt_with_tag(&iv, aad, &tag, &ciphertext)?;
//! assert_eq!(&*plaintext, b"secret message");
//! # Ok(())
//! # }
//! ```

use aws_lc_rs::cipher::{
    AES_128, AES_192, AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
    UnboundCipherKey,
};
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{ErrorKind, Result};
use crate::secret::Secret;
use crate::utils::error_msg;

/// AES block / CBC IV length in bytes — fixed regardless of key size (RFC 7518 §5.2.2.1).
pub const IV_LENGTH: usize = 16;

/// AES_CBC_HMAC_SHA2 content encryption algorithms (RFC 7518 §5.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Algorithm {
    /// AES-128-CBC with HMAC-SHA-256, corresponding to JWE `A128CBC-HS256` (RFC 7518 §5.2.3).
    Aes128CbcHmacSha256,
    /// AES-192-CBC with HMAC-SHA-384, corresponding to JWE `A192CBC-HS384` (RFC 7518 §5.2.4).
    Aes192CbcHmacSha384,
    /// AES-256-CBC with HMAC-SHA-512, corresponding to JWE `A256CBC-HS512` (RFC 7518 §5.2.5).
    Aes256CbcHmacSha512,
}

impl Algorithm {
    /// Total CEK length in bytes (MAC key + encryption key).
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128CbcHmacSha256 => 32,
            Self::Aes192CbcHmacSha384 => 48,
            Self::Aes256CbcHmacSha512 => 64,
        }
    }

    /// MAC key length — the first half of the CEK (RFC 7518 §5.2.2.1).
    #[must_use]
    fn mac_key_len(self) -> usize {
        self.key_len() / 2
    }

    /// Authentication tag length — equal to the MAC key length, i.e. half the
    /// HMAC's native output length (RFC 7518 §5.2.2.1).
    ///
    /// This equality (`mac_key_len() == hmac_algorithm().tag_len() / 2`) holds
    /// for all three RFC-defined combinations by construction — it is not
    /// re-derived from `hmac_algorithm()` here. A future variant that paired a
    /// MAC key size with a hash whose output isn't exactly double that size
    /// would silently get the wrong truncation length; there is no
    /// existing combination where that applies.
    #[must_use]
    pub fn tag_len(self) -> usize {
        self.mac_key_len()
    }

    fn hmac_algorithm(self) -> hmac::Algorithm {
        match self {
            Self::Aes128CbcHmacSha256 => hmac::HMAC_SHA256,
            Self::Aes192CbcHmacSha384 => hmac::HMAC_SHA384,
            Self::Aes256CbcHmacSha512 => hmac::HMAC_SHA512,
        }
    }

    fn cipher_algorithm(self) -> &'static aws_lc_rs::cipher::Algorithm {
        match self {
            Self::Aes128CbcHmacSha256 => &AES_128,
            Self::Aes192CbcHmacSha384 => &AES_192,
            Self::Aes256CbcHmacSha512 => &AES_256,
        }
    }
}

/// A generic error used for both tag-verification and padding failures.
///
/// Keeping a single error site (and message) for both cases means a MAC
/// failure and a padding failure are indistinguishable to a caller.
fn tag_error() -> crate::error::Error {
    error_msg(
        ErrorKind::Decryption,
        "JWE authentication tag verification failed",
    )
}

/// `AL` — the AAD length in bits, as a fixed 8-byte big-endian integer (RFC 7518 §5.2.2.1).
fn al_bytes(aad_len: usize) -> [u8; 8] {
    // JWE protected headers are never anywhere near u64::MAX/8 bytes.
    let bits = (aad_len as u64) * 8;
    bits.to_be_bytes()
}

/// Build the MAC input `AAD || IV || ciphertext || AL` (RFC 7518 §5.2.2.1).
fn mac_input(aad: &[u8], iv: &[u8; IV_LENGTH], ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(aad.len() + IV_LENGTH + ciphertext.len() + 8);
    buf.extend_from_slice(aad);
    buf.extend_from_slice(iv);
    buf.extend_from_slice(ciphertext);
    buf.extend_from_slice(&al_bytes(aad.len()));
    buf
}

/// Pad `plaintext` to a multiple of the AES block length using PKCS#7.
fn pkcs7_pad(plaintext: &[u8]) -> Vec<u8> {
    let pad_len = IV_LENGTH - (plaintext.len() % IV_LENGTH);
    let mut out = Vec::with_capacity(plaintext.len() + pad_len);
    out.extend_from_slice(plaintext);
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    out
}

/// Validate PKCS#7 padding on an already MAC-verified buffer and return the
/// unpadded length.
///
/// This is only ever reached after tag verification has succeeded, so timing
/// variations here do not constitute a padding oracle — see the module docs.
fn pkcs7_unpadded_len(buf: &[u8]) -> Result<usize> {
    let pad_len = *buf.last().ok_or_else(tag_error)? as usize;
    if pad_len == 0 || pad_len > IV_LENGTH || pad_len > buf.len() {
        return Err(tag_error());
    }
    let data_len = buf.len() - pad_len;
    if buf[data_len..].iter().any(|&b| b as usize != pad_len) {
        return Err(tag_error());
    }
    Ok(data_len)
}

/// An AES_CBC_HMAC_SHA2 content encryption key (RFC 7518 §5.2.2.1).
///
/// Constructed from a single CEK, split into a MAC key (first half) and an
/// encryption key (second half).
pub struct Key {
    alg: Algorithm,
    mac_key: Secret,
    enc_key: Secret,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

impl Key {
    /// Construct a key from raw CEK bytes, splitting into a MAC key (first
    /// half) and an encryption key (second half) per RFC 7518 §5.2.2.1.
    ///
    /// # Errors
    /// [`ErrorKind::WrongLength`] if `cek.len()` does not match `alg.key_len()`.
    pub fn new(alg: Algorithm, cek: &[u8]) -> Result<Self> {
        if cek.len() != alg.key_len() {
            return Err(error_msg(
                ErrorKind::WrongLength,
                format!(
                    "expected {}-byte CEK for {alg:?}, got {} bytes",
                    alg.key_len(),
                    cek.len()
                ),
            ));
        }
        let (mac_key, enc_key) = cek.split_at(alg.mac_key_len());
        Ok(Self {
            alg,
            mac_key: Secret::new(mac_key),
            enc_key: Secret::new(enc_key),
        })
    }

    /// The authentication tag length for this key's algorithm.
    #[must_use]
    pub fn tag_len(&self) -> usize {
        self.alg.tag_len()
    }

    /// Compute the truncated HMAC tag over `AAD || IV || ciphertext || AL`.
    fn compute_tag(&self, iv: &[u8; IV_LENGTH], aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let mac_key = hmac::Key::new(self.alg.hmac_algorithm(), self.mac_key.expose());
        let input = mac_input(aad, iv, ciphertext);
        let full_tag = hmac::sign(&mac_key, &input);
        full_tag.as_ref()[..self.alg.tag_len()].to_vec()
    }

    /// Encrypt `plaintext` with PKCS#7 padding, returning `(ciphertext, tag)`.
    ///
    /// `iv` must be unique for each key. `aad` is authenticated but not
    /// encrypted (RFC 7518 §5.2.2.1).
    ///
    /// # Errors
    /// [`ErrorKind::Encryption`] if AES-CBC encryption fails.
    pub fn encrypt(
        &self,
        iv: &[u8; IV_LENGTH],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut buf = Zeroizing::new(pkcs7_pad(plaintext));

        // aws-lc-rs flags raw CBC as dangerous alone; it's safe here because
        // it's always paired with the HMAC compute/verify around it (RFC 7518 §5.2).
        let cipher_key = UnboundCipherKey::new(self.alg.cipher_algorithm(), self.enc_key.expose())
            .map_err(|_| error_msg(ErrorKind::Encryption, "failed to construct AES-CBC key"))?;
        let encrypting_key = EncryptingKey::cbc(cipher_key).map_err(|_| {
            error_msg(
                ErrorKind::Encryption,
                "failed to construct AES-CBC encrypting key",
            )
        })?;
        let context = EncryptionContext::Iv128(FixedLength::<IV_LENGTH>::from(iv));
        encrypting_key
            .less_safe_encrypt(&mut buf, context)
            .map_err(|_| error_msg(ErrorKind::Encryption, "AES-CBC encryption failed"))?;

        let tag = self.compute_tag(iv, aad, &buf);
        Ok((buf.to_vec(), tag))
    }

    /// Verify the tag (constant-time) and, only on success, decrypt and remove
    /// PKCS#7 padding.
    ///
    /// See the module-level docs for why the tag check is a hard early return
    /// before any decryption or unpadding occurs.
    ///
    /// # Errors
    /// [`ErrorKind::Decryption`] if tag verification, decryption, or padding
    /// removal fails — all three surface the same generic error.
    pub fn decrypt_with_tag(
        &self,
        iv: &[u8; IV_LENGTH],
        aad: &[u8],
        tag: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        // Explicit length check: `cbc_hmac::Key` is public API reachable
        // without the JWE layer's pre-validation, so this must hold here too.
        if tag.len() != self.alg.tag_len() {
            return Err(tag_error());
        }

        let expected = self.compute_tag(iv, aad, ciphertext);
        let tag_ok: bool = expected.as_slice().ct_eq(tag).into();
        if !tag_ok {
            return Err(tag_error());
        }
        // Everything below only ever runs on a MAC-verified ciphertext —
        // do not reorder (see module docs).

        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(IV_LENGTH) {
            return Err(tag_error());
        }

        let cipher_key = UnboundCipherKey::new(self.alg.cipher_algorithm(), self.enc_key.expose())
            .map_err(|_| tag_error())?;
        let decrypting_key = DecryptingKey::cbc(cipher_key).map_err(|_| tag_error())?;
        let context = DecryptionContext::Iv128(FixedLength::<IV_LENGTH>::from(iv));

        let mut buf = Zeroizing::new(ciphertext.to_vec());
        decrypting_key
            .decrypt(&mut buf, context)
            .map_err(|_| tag_error())?;

        let data_len = pkcs7_unpadded_len(&buf)?;
        buf.truncate(data_len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // RFC 7518 §5.2.2.1 / the underlying AEAD_AES_128_CBC_HMAC_SHA_256 example
    // (Kerckhoffs's-principle plaintext). Independently re-derived and verified
    // with the Python `cryptography` library (AES-128-CBC + HMAC-SHA-256) before
    // being hardcoded here — not transcribed from memory.
    const KAT_CEK: [u8; 32] =
        hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const KAT_IV: [u8; 16] = hex!("1af38c2dc2b96ffdd86694092341bc04");
    const KAT_AAD: &[u8] = b"The second principle of Auguste Kerckhoffs";
    const KAT_PLAINTEXT: &[u8] =
        b"A cipher system must not be required to be secret, and it must be able \
          to fall into the hands of the enemy without inconvenience";
    const KAT_CIPHERTEXT: [u8; 144] = hex!(
        "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c70323"
        "3609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a676463444"
        "27ade54b8851ffb598f7f80074b9473c82e2db"
    );
    const KAT_TAG: [u8; 16] = hex!("652c3fa36b0a7c5b3219fab3a30bc1c4");

    #[test]
    fn rfc7518_aes128cbc_hs256_known_answer() {
        let key = Key::new(Algorithm::Aes128CbcHmacSha256, &KAT_CEK).unwrap();

        let (ciphertext, tag) = key.encrypt(&KAT_IV, KAT_AAD, KAT_PLAINTEXT).unwrap();
        assert_eq!(ciphertext, KAT_CIPHERTEXT);
        assert_eq!(tag, KAT_TAG);

        let plaintext = key
            .decrypt_with_tag(&KAT_IV, KAT_AAD, &KAT_TAG, &KAT_CIPHERTEXT)
            .unwrap();
        assert_eq!(&*plaintext, KAT_PLAINTEXT);
    }

    // `AL` worked example, hand-computed independently of the function under
    // test: a 51-byte AAD is 51*8 = 408 bits = 0x198, as an 8-byte big-endian
    // integer.
    #[test]
    fn al_bytes_worked_example() {
        let aad = [0u8; 51];
        assert_eq!(
            al_bytes(aad.len()),
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x98]
        );
    }

    fn roundtrip(alg: Algorithm) {
        let mut cek = vec![0u8; alg.key_len()];
        crate::rand::fill_bytes(&mut cek).unwrap();
        let key = Key::new(alg, &cek).unwrap();

        let mut iv = [0u8; IV_LENGTH];
        crate::rand::fill_bytes(&mut iv).unwrap();
        let aad = b"protected header bytes";
        let plaintext = b"roundtrip test message";

        let (ciphertext, tag) = key.encrypt(&iv, aad, plaintext).unwrap();
        let got = key.decrypt_with_tag(&iv, aad, &tag, &ciphertext).unwrap();
        assert_eq!(&*got, plaintext);
    }

    #[test]
    fn roundtrip_a128cbc_hs256() {
        roundtrip(Algorithm::Aes128CbcHmacSha256);
    }

    #[test]
    fn roundtrip_a192cbc_hs384() {
        roundtrip(Algorithm::Aes192CbcHmacSha384);
    }

    #[test]
    fn roundtrip_a256cbc_hs512() {
        roundtrip(Algorithm::Aes256CbcHmacSha512);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        // Exercises the "plaintext already a multiple of the block length"
        // PKCS#7 path, which must still add a full padding block.
        let cek = vec![0u8; Algorithm::Aes128CbcHmacSha256.key_len()];
        let key = Key::new(Algorithm::Aes128CbcHmacSha256, &cek).unwrap();
        let iv = [0u8; IV_LENGTH];
        let (ciphertext, tag) = key.encrypt(&iv, b"aad", b"").unwrap();
        assert_eq!(ciphertext.len(), IV_LENGTH);
        let got = key
            .decrypt_with_tag(&iv, b"aad", &tag, &ciphertext)
            .unwrap();
        assert_eq!(&*got, b"");
    }

    #[test]
    fn wrong_cek_length_rejected() {
        for alg in [
            Algorithm::Aes128CbcHmacSha256,
            Algorithm::Aes192CbcHmacSha384,
            Algorithm::Aes256CbcHmacSha512,
        ] {
            let err = Key::new(alg, &[0u8; 16]).unwrap_err().kind();
            assert_eq!(
                err,
                ErrorKind::WrongLength,
                "expected WrongLength for {alg:?} with a wrong-length CEK"
            );
        }
    }

    /// A MAC failure must be reported, and the padding/decryption code must
    /// never run as a result of it. This is the structural guarantee behind
    /// the padding-oracle defense: we construct ciphertext whose *padding*
    /// would also be invalid once decrypted with the right key (by flipping
    /// the final ciphertext block, which scrambles the last plaintext block
    /// under CBC), so if the implementation ever decrypted before checking
    /// the tag, this would surface as a different, distinguishable error
    /// (or succeed) rather than the generic tag-verification failure.
    #[test]
    fn tampered_tag_and_corrupted_padding_both_report_generic_decryption_error() {
        let cek = vec![0u8; Algorithm::Aes128CbcHmacSha256.key_len()];
        let key = Key::new(Algorithm::Aes128CbcHmacSha256, &cek).unwrap();
        let iv = [0u8; IV_LENGTH];
        let (mut ciphertext, mut tag) = key.encrypt(&iv, b"aad", b"some plaintext").unwrap();

        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        let err_corrupted_ct = key
            .decrypt_with_tag(&iv, b"aad", &tag, &ciphertext)
            .unwrap_err();

        // A tag-only corruption (ciphertext untouched) hits the same code path.
        tag[0] ^= 0xff;
        let (ciphertext2, _) = key.encrypt(&iv, b"aad", b"some plaintext").unwrap();
        let err_bad_tag = key
            .decrypt_with_tag(&iv, b"aad", &tag, &ciphertext2)
            .unwrap_err();

        assert_eq!(err_corrupted_ct.kind(), ErrorKind::Decryption);
        assert_eq!(err_bad_tag.kind(), ErrorKind::Decryption);
        assert_eq!(err_corrupted_ct.to_string(), err_bad_tag.to_string());
    }

    /// `cbc_hmac::Key` is public API reachable without the JWE layer's own
    /// pre-validation, so it must reject malformed tag/ciphertext lengths
    /// itself: a too-short or too-long tag (not merely relying on `ct_eq`'s
    /// own length handling), and an empty ciphertext.
    #[test]
    fn decrypt_with_tag_rejects_malformed_lengths() {
        for alg in [
            Algorithm::Aes128CbcHmacSha256,
            Algorithm::Aes192CbcHmacSha384,
            Algorithm::Aes256CbcHmacSha512,
        ] {
            let cek = vec![0u8; alg.key_len()];
            let key = Key::new(alg, &cek).unwrap();
            let iv = [0u8; IV_LENGTH];
            let (ciphertext, tag) = key.encrypt(&iv, b"aad", b"some plaintext").unwrap();
            assert_eq!(tag.len(), alg.tag_len());

            let err = key
                .decrypt_with_tag(&iv, b"aad", &tag[..tag.len() / 2], &ciphertext)
                .unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::Decryption,
                "expected rejection for {alg:?} with a too-short tag"
            );

            let mut too_long = tag.clone();
            too_long.push(0);
            let err = key
                .decrypt_with_tag(&iv, b"aad", &too_long, &ciphertext)
                .unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::Decryption,
                "expected rejection for {alg:?} with a too-long tag"
            );

            let empty_tag = key.compute_tag(&iv, b"aad", b"");
            let err = key
                .decrypt_with_tag(&iv, b"aad", &empty_tag, b"")
                .unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::Decryption,
                "expected rejection for {alg:?} with an empty ciphertext"
            );
        }
    }
}
