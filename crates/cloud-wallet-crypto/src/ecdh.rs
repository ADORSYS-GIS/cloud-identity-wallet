//! Ephemeral ECDH key agreement for X25519, P-256, P-384, and P-521.
//!
//! All private keys are ephemeral: generated fresh per operation and consumed
//! on [`EphemeralEcdhKey::agree`]. RFC 7518 §4.6 mandates this
//! for ECDH-ES, so no reuse is exposed. Feed [`SharedSecret`] bytes into
//! [`crate::kdf::concat_kdf`] to derive key material using the NIST
//! ConcatKDF.

use aws_lc_rs::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
#[cfg(feature = "jwe")]
use aws_lc_rs::agreement::{PrivateKey, agree};
use aws_lc_rs::rand::SystemRandom;

use crate::error::{ErrorKind, Result};
use crate::secret::Secret;
use crate::utils::{error_msg, key_gen_error, parse_error};

/// Supported ECDH curves.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcdhCurve {
    /// NIST P-256 (prime256v1 / secp256r1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
    /// NIST P-521 (secp521r1).
    P521,
    /// X25519 Diffie-Hellman (RFC 7748).
    X25519,
}

impl From<EcdhCurve> for &'static agreement::Algorithm {
    fn from(curve: EcdhCurve) -> Self {
        match curve {
            EcdhCurve::P256 => &agreement::ECDH_P256,
            EcdhCurve::P384 => &agreement::ECDH_P384,
            EcdhCurve::P521 => &agreement::ECDH_P521,
            EcdhCurve::X25519 => &agreement::X25519,
        }
    }
}

impl EcdhCurve {
    /// Expected byte length of the serialised public key for this curve.
    ///
    /// NIST curves: 1 (uncompressed tag `04`) + 2 × coordinate size.
    /// X25519: 32-byte raw scalar.
    ///
    /// Use this to size the output buffer passed to
    /// [`EphemeralEcdhKey::public_key_bytes`].
    pub fn public_key_len(self) -> usize {
        match self {
            EcdhCurve::P256 => 65,  // 1 + 32 + 32
            EcdhCurve::P384 => 97,  // 1 + 48 + 48
            EcdhCurve::P521 => 133, // 1 + 66 + 66
            EcdhCurve::X25519 => 32,
        }
    }
}

// Fixed-size heap-free storage for a public key, one array variant per curve.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicKeyBytes {
    P256([u8; 65]),
    P384([u8; 97]),
    P521([u8; 133]),
    X25519([u8; 32]),
}

impl PublicKeyBytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::P256(b) => b,
            Self::P384(b) => b,
            Self::P521(b) => b,
            Self::X25519(b) => b,
        }
    }

    fn curve(&self) -> EcdhCurve {
        match self {
            Self::P256(_) => EcdhCurve::P256,
            Self::P384(_) => EcdhCurve::P384,
            Self::P521(_) => EcdhCurve::P521,
            Self::X25519(_) => EcdhCurve::X25519,
        }
    }
}

/// An ephemeral ECDH private key, consumed on agreement.
///
/// RFC 7518 §4.6 requires a fresh ephemeral key per JWE operation; this type
/// enforces that by taking ownership in [`EphemeralEcdhKey::agree`].
pub struct EphemeralEcdhKey {
    inner: EphemeralPrivateKey,
    curve: EcdhCurve,
}

impl std::fmt::Debug for EphemeralEcdhKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralEcdhKey")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

impl EphemeralEcdhKey {
    /// Generate a fresh ephemeral key pair for the given curve.
    ///
    /// # Errors
    /// [`ErrorKind::KeyGeneration`] on RNG or key-generation failure.
    pub fn generate(curve: EcdhCurve) -> Result<Self> {
        let rng = SystemRandom::new();
        let inner = EphemeralPrivateKey::generate(curve.into(), &rng)
            .map_err(|_| key_gen_error("ephemeral ECDH"))?;
        Ok(Self { inner, curve })
    }

    /// The curve this key was generated for.
    #[must_use]
    pub fn curve(&self) -> EcdhCurve {
        self.curve
    }

    /// Serialise the public key into `output` for inclusion in the JWE `epk` header.
    ///
    /// `output.len()` must be `>= self.curve().public_key_len()`.
    /// Encoding: SEC1 uncompressed point (`04 || x || y`) for P-256/384/521;
    /// raw 32-byte little-endian scalar for X25519.
    ///
    /// Returns the filled sub-slice of `output`.
    ///
    /// # Errors
    /// - [`ErrorKind::WrongLength`] if `output` is too small.
    /// - [`ErrorKind::KeyGeneration`] on internal failure.
    pub fn public_key_bytes<'o>(&self, output: &'o mut [u8]) -> Result<&'o [u8]> {
        let key = self
            .inner
            .compute_public_key()
            .map_err(|_| key_gen_error("ECDH public key"))?;
        let bytes = key.as_ref();
        if output.len() < bytes.len() {
            return Err(error_msg(
                ErrorKind::WrongLength,
                format!(
                    "output buffer must be at least {} bytes for {:?} public key, got {}",
                    bytes.len(),
                    self.curve,
                    output.len()
                ),
            ));
        }
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(&output[..bytes.len()])
    }

    /// Perform ECDH key agreement and return the shared secret, consuming the
    /// ephemeral key.
    ///
    /// # Errors
    /// - [`ErrorKind::KeyParsing`] if `peer.curve()` does not match `self.curve()`, or if
    ///   the agreement computation fails (low-order point, point not on curve, etc.).
    pub fn agree(self, peer: &EcdhPublicKey) -> Result<SharedSecret> {
        if self.curve != peer.curve() {
            return Err(error_msg(
                ErrorKind::KeyParsing,
                format!(
                    "curve mismatch: self is {:?} but peer key is {:?}",
                    self.curve,
                    peer.curve()
                ),
            ));
        }
        let peer_key = UnparsedPublicKey::new(self.curve.into(), peer.as_bytes());
        let curve = self.curve;
        agree_ephemeral(
            self.inner,
            peer_key,
            error_msg(
                ErrorKind::KeyParsing,
                "ECDH agreement failed: peer key is invalid or a low-order point",
            ),
            move |key_material| {
                Ok(SharedSecret {
                    secret: Secret::new(key_material),
                    curve,
                })
            },
        )
    }
}

/// Peer public key for ECDH.
///
/// For P-256/384/521: uncompressed SEC1 point (`04 || x || y`).
/// For X25519: raw 32-byte little-endian scalar.
///
/// Stored in a fixed-size array determined by the curve; no heap allocation.
/// Byte length and uncompressed-point tag are validated at construction.
/// Curve mismatch with the private key is caught in
/// [`EphemeralEcdhKey::agree`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EcdhPublicKey {
    bytes: PublicKeyBytes,
}

impl std::fmt::Debug for EcdhPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhPublicKey")
            .field("curve", &self.bytes.curve())
            .finish_non_exhaustive()
    }
}

impl EcdhPublicKey {
    /// Construct from raw public key bytes for the given curve.
    ///
    /// Validates:
    /// - Exact byte length for the curve (65 / 97 / 133 / 32 bytes).
    /// - Uncompressed-point tag `0x04` for NIST curves.
    ///
    /// Point-on-curve validation is deferred to
    /// [`EphemeralEcdhKey::agree`].
    ///
    /// # Errors
    /// [`ErrorKind::KeyParsing`] if the length or tag is wrong.
    pub fn from_bytes(curve: EcdhCurve, bytes: &[u8]) -> Result<Self> {
        let expected = curve.public_key_len();
        if bytes.len() != expected {
            return Err(error_msg(
                ErrorKind::KeyParsing,
                format!(
                    "{:?} public key must be {expected} bytes, got {}",
                    curve,
                    bytes.len()
                ),
            ));
        }
        if curve != EcdhCurve::X25519 && bytes[0] != 0x04 {
            return Err(parse_error(
                "NIST curve public key must use uncompressed SEC1 encoding (0x04 prefix)",
            ));
        }
        // len validated above — try_into is infallible for each branch.
        let inner = match curve {
            EcdhCurve::P256 => {
                PublicKeyBytes::P256(bytes.try_into().expect("length validated above"))
            }
            EcdhCurve::P384 => {
                PublicKeyBytes::P384(bytes.try_into().expect("length validated above"))
            }
            EcdhCurve::P521 => {
                PublicKeyBytes::P521(bytes.try_into().expect("length validated above"))
            }
            EcdhCurve::X25519 => {
                PublicKeyBytes::X25519(bytes.try_into().expect("length validated above"))
            }
        };
        Ok(Self { bytes: inner })
    }

    /// The curve this key belongs to.
    #[must_use]
    pub fn curve(&self) -> EcdhCurve {
        self.bytes.curve()
    }

    /// Raw public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Raw shared secret produced by ECDH.
///
/// Do **not** use as an encryption key directly. Derive key material via
/// [`crate::kdf::concat_kdf`] (NIST ConcatKDF).
pub struct SharedSecret {
    secret: Secret,
    curve: EcdhCurve,
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

impl SharedSecret {
    /// Exposes the raw shared secret bytes for use with ConcatKDF.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.secret.expose()
    }

    /// The curve the shared secret was derived from.
    ///
    /// Useful for selecting the correct KDF hash (e.g. SHA-256 for P-256/X25519,
    /// SHA-384 for P-384, SHA-512 for P-521) without tracking the curve
    /// separately alongside the secret.
    #[must_use]
    pub fn curve(&self) -> EcdhCurve {
        self.curve
    }
}

#[cfg(feature = "jwe")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwe")))]
/// A static (long-term) ECDH private key for use as the recipient key in ECDH-ES JWE decryption.
///
/// Unlike [`EphemeralEcdhKey`], this key is not consumed on use and can be reused across
/// multiple decryption operations. It corresponds to the "Static" half of the
/// Ephemeral-Static ECDH-ES key agreement defined in RFC 7518 §4.6.
///
/// # Validation
///
/// Scalar range validation occurs at construction time for all constructors.
/// For NIST curves, `from_pkcs8_der` and `from_private_key_bytes` both reject scalars that
/// are zero or not in the valid field range via aws-lc-rs's internal checks.
/// For X25519, any 32-byte value is a syntactically valid private key; the X25519 function
/// applies the required clamping internally at agreement time.
///
/// # Thread Safety
///
/// `StaticEcdhKey` is `Send + Sync` — it can be shared across threads via
/// `Arc<StaticEcdhKey>`. The inner key material is read-only after construction;
/// no interior mutability is involved.
pub struct StaticEcdhKey {
    inner: PrivateKey,
    curve: EcdhCurve,
}

#[cfg(feature = "jwe")]
impl std::fmt::Debug for StaticEcdhKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticEcdhKey")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "jwe")]
impl StaticEcdhKey {
    /// Generate a fresh static key pair for the given curve.
    ///
    /// Intended primarily for testing. In production, load a persisted key via
    /// [`from_pkcs8_der`] or [`from_private_key_bytes`].
    ///
    /// [`from_pkcs8_der`]: StaticEcdhKey::from_pkcs8_der
    /// [`from_private_key_bytes`]: StaticEcdhKey::from_private_key_bytes
    ///
    /// # Errors
    /// [`ErrorKind::KeyGeneration`] on failure.
    pub fn generate(curve: EcdhCurve) -> Result<Self> {
        let inner = PrivateKey::generate(curve.into()).map_err(|_| key_gen_error("static ECDH"))?;
        Ok(Self { inner, curve })
    }

    /// Load a static private key from a DER-encoded PKCS#8 `PrivateKeyInfo` structure.
    ///
    /// Supported for P-256, P-384, and P-521. **X25519 is not supported** by this
    /// constructor because the underlying aws-lc-rs DER parser does not handle
    /// X25519 PKCS#8; use [`from_private_key_bytes`] with the raw 32-byte seed instead.
    ///
    /// Scalar range validation occurs at construction time.
    ///
    /// [`from_private_key_bytes`]: StaticEcdhKey::from_private_key_bytes
    ///
    /// # Errors
    /// - [`ErrorKind::UnsupportedAlgorithm`] if `curve` is [`EcdhCurve::X25519`].
    /// - [`ErrorKind::KeyParsing`] if the DER is malformed or the scalar is invalid.
    pub fn from_pkcs8_der(curve: EcdhCurve, bytes: &[u8]) -> Result<Self> {
        if curve == EcdhCurve::X25519 {
            return Err(error_msg(
                ErrorKind::UnsupportedAlgorithm,
                "X25519 PKCS#8 DER loading is not supported; \
                 use from_private_key_bytes with the raw 32-byte seed",
            ));
        }
        let inner = PrivateKey::from_private_key_der(curve.into(), bytes)
            .map_err(|_| parse_error("invalid ECDH private key DER (PKCS#8 PrivateKeyInfo)"))?;
        Ok(Self { inner, curve })
    }

    /// Load a static private key from a raw big-endian private scalar.
    ///
    /// Supported for all curves:
    /// - P-256: 32 bytes
    /// - P-384: 48 bytes
    /// - P-521: 66 bytes
    /// - X25519: 32 bytes (the seed/scalar; clamping is applied internally at agreement time)
    ///
    /// Scalar length and range validation occur at construction time.
    ///
    /// # Errors
    /// [`ErrorKind::KeyParsing`] if the length is wrong or the scalar is invalid for
    /// the curve.
    pub fn from_private_key_bytes(curve: EcdhCurve, bytes: &[u8]) -> Result<Self> {
        let inner = PrivateKey::from_private_key(curve.into(), bytes)
            .map_err(|_| parse_error("invalid ECDH private key scalar bytes"))?;
        Ok(Self { inner, curve })
    }

    /// The curve this key was generated for.
    #[must_use]
    pub fn curve(&self) -> EcdhCurve {
        self.curve
    }

    /// Serialise the public key into `output`.
    ///
    /// `output.len()` must be `>= self.curve().public_key_len()`.
    /// Encoding matches [`EphemeralEcdhKey::public_key_bytes`]: SEC1 uncompressed
    /// (`04 || x || y`) for NIST curves, raw 32-byte little-endian scalar for X25519.
    ///
    /// # Errors
    /// - [`ErrorKind::WrongLength`] if `output` is too small.
    /// - [`ErrorKind::KeyGeneration`] on internal failure.
    pub fn public_key_bytes<'o>(&self, output: &'o mut [u8]) -> Result<&'o [u8]> {
        let key = self
            .inner
            .compute_public_key()
            .map_err(|_| key_gen_error("static ECDH public key"))?;
        let bytes = key.as_ref();
        if output.len() < bytes.len() {
            return Err(error_msg(
                ErrorKind::WrongLength,
                format!(
                    "output buffer must be at least {} bytes for {:?} public key, got {}",
                    bytes.len(),
                    self.curve,
                    output.len()
                ),
            ));
        }
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(&output[..bytes.len()])
    }

    /// Perform ECDH key agreement with a peer's public key and return the shared secret.
    ///
    /// Unlike [`EphemeralEcdhKey::agree`], this method borrows `self` and
    /// can be called multiple times on the same key.
    ///
    /// The result must be fed into [`crate::kdf::concat_kdf`] before use as key material.
    ///
    /// This method is intentionally `pub(crate)` to enforce that the raw ECDH output is
    /// always processed through ConcatKDF (RFC 7518 §4.6.2) before use. Use
    /// [`fn@crate::jwe::decrypt`] with [`crate::jwe::JweDecryptKey::Ecdh`] to decrypt a JWE
    /// token using this key.
    ///
    /// # Errors
    /// [`ErrorKind::KeyParsing`] if the curves do not match or agreement fails
    /// (low-order point, point not on curve, etc.).
    pub(crate) fn agree_with(&self, peer: &EcdhPublicKey) -> Result<SharedSecret> {
        if self.curve != peer.curve() {
            return Err(error_msg(
                ErrorKind::KeyParsing,
                format!(
                    "curve mismatch: static key is {:?} but peer key is {:?}",
                    self.curve,
                    peer.curve()
                ),
            ));
        }
        let peer_key = UnparsedPublicKey::new(self.curve.into(), peer.as_bytes());
        let curve = self.curve;
        agree(
            &self.inner,
            peer_key,
            error_msg(
                ErrorKind::KeyParsing,
                "ECDH agreement failed: peer key is invalid or a low-order point",
            ),
            move |key_material| {
                Ok(SharedSecret {
                    secret: Secret::new(key_material),
                    curve,
                })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::agreement::{self as lc, PrivateKey, UnparsedPublicKey, agree};
    use hex_literal::hex;

    // Round-trip tests
    // Verify that an ephemeral Alice and a static Bob agree on the same secret.

    fn round_trip(curve: EcdhCurve) {
        let bob = PrivateKey::generate(curve.into()).unwrap();
        let bob_pub = bob.compute_public_key().unwrap();

        let alice = EphemeralEcdhKey::generate(curve).unwrap();
        let mut alice_pub_buf = vec![0u8; curve.public_key_len()];
        let alice_pub_bytes = alice.public_key_bytes(&mut alice_pub_buf).unwrap();

        let alice_shared = alice
            .agree(&EcdhPublicKey::from_bytes(curve, bob_pub.as_ref()).unwrap())
            .unwrap();

        let alice_pub_unparsed = UnparsedPublicKey::new(curve.into(), alice_pub_bytes);
        let bob_shared = agree(&bob, alice_pub_unparsed, (), |b| {
            Ok::<Vec<u8>, ()>(b.to_vec())
        })
        .unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_slice());
        assert!(!alice_shared.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn round_trip_p256() {
        round_trip(EcdhCurve::P256);
    }

    #[test]
    fn round_trip_p384() {
        round_trip(EcdhCurve::P384);
    }

    #[test]
    fn round_trip_p521() {
        round_trip(EcdhCurve::P521);
    }

    #[test]
    fn round_trip_x25519() {
        round_trip(EcdhCurve::X25519);
    }

    // - NIST / Wycheproof known-answer tests
    // Vectors sourced from the aws-lc-rs test suite (agreement_tests.rs),
    // which in turn uses NIST CAVP vectors for P-256/384/521 and RFC 7748 §6.1 for X25519.
    fn known_answer(
        curve: EcdhCurve,
        lc_alg: &'static lc::Algorithm,
        d: &[u8],
        peer_pub: &[u8],
        expected_z: &[u8],
    ) {
        // algorithm constant and EcdhPublicKey parsing are correct.
        let peer = EcdhPublicKey::from_bytes(curve, peer_pub).unwrap();
        let priv_key = PrivateKey::from_private_key(lc_alg, d).unwrap();
        let lc_peer = UnparsedPublicKey::new(lc_alg, peer.as_bytes());
        let z = agree(&priv_key, lc_peer, (), |b| Ok::<Vec<u8>, ()>(b.to_vec())).unwrap();
        assert_eq!(z.as_slice(), expected_z);

        // Exercise EphemeralEcdhKey::agree end-to-end via commutativity.
        //
        // EphemeralPrivateKey has no `from_private_key` constructor (by design), so
        // the NIST scalar `d` above cannot be loaded through our wrapper. This is not
        // a second CAVP test — it verifies that our ephemeral wrapper routes to the
        // same algorithm constant validated in Part 1, using a fresh random key pair.
        let bob_static = PrivateKey::generate(lc_alg).unwrap();
        let bob_pub_bytes = bob_static.compute_public_key().unwrap();

        let alice = EphemeralEcdhKey::generate(curve).unwrap();
        let mut alice_pub_buf = vec![0u8; curve.public_key_len()];
        let alice_pub_bytes = alice.public_key_bytes(&mut alice_pub_buf).unwrap();

        let bob_peer = EcdhPublicKey::from_bytes(curve, bob_pub_bytes.as_ref()).unwrap();
        let alice_z = alice.agree(&bob_peer).unwrap(); // ← exercises EphemeralEcdhKey::agree
        assert_eq!(alice_z.curve(), curve);

        let alice_pub_unparsed = UnparsedPublicKey::new(lc_alg, alice_pub_bytes);
        let bob_z = agree(&bob_static, alice_pub_unparsed, (), |b| {
            Ok::<Vec<u8>, ()>(b.to_vec())
        })
        .unwrap();

        assert_eq!(alice_z.as_bytes(), bob_z.as_slice());
        assert!(!alice_z.as_bytes().iter().all(|&b| b == 0));
    }

    // Source: aws-lc-rs agreement_tests.rs (NIST CAVP P-256)
    #[test]
    fn nist_cavp_p256() {
        #[rustfmt::skip]
        known_answer(
            EcdhCurve::P256,
            &lc::ECDH_P256,
            &hex!("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433"),
            &hex!("04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF6356FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"),
            &hex!("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE"),
        );
    }

    // Source: aws-lc-rs agreement_tests.rs (NIST CAVP P-384)
    #[test]
    fn nist_cavp_p384() {
        #[rustfmt::skip]
        known_answer(
            EcdhCurve::P384,
            &lc::ECDH_P384,
            &hex!("099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194"),
            &hex!("04E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C"),
            &hex!("11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746"),
        );
    }

    // Source: aws-lc-rs agreement_tests.rs (NIST CAVP P-521)
    #[test]
    fn nist_cavp_p521() {
        #[rustfmt::skip]
        known_answer(
            EcdhCurve::P521,
            &lc::ECDH_P521,
            &hex!("00df14b1f1432a7b0fb053965fd8643afee26b2451ecb6a8a53a655d5fbe16e4c64ce8647225eb11e7fdcb23627471dffc5c2523bd2ae89957cba3a57a23933e5a78"),
            &hex!("0401a32099b02c0bd85371f60b0dd20890e6c7af048c8179890fda308b359dbbc2b7a832bb8c6526c4af99a7ea3f0b3cb96ae1eb7684132795c478ad6f962e4a6f446d017627357b39e9d7632a1370b3e93c1afb5c851b910eb4ead0c9d387df67cde85003e0e427552f1cd09059aad0262e235cce5fba8cedc4fdc1463da76dcd4b6d1a46"),
            &hex!("01aaf24e5d47e4080c18c55ea35581cd8da30f1a079565045d2008d51b12d0abb4411cda7a0785b15d149ed301a3697062f42da237aa7f07e0af3fd00eb1800d9c41"),
        );
    }

    // Source: RFC 7748 §6.1 / aws-lc-rs agreement_tests.rs (Wycheproof X25519)
    #[test]
    fn rfc7748_x25519() {
        known_answer(
            EcdhCurve::X25519,
            &lc::X25519,
            &hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            &hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            &hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        );
    }

    #[test]
    fn wrong_length_rejected() {
        // One byte too short for P-256 (expects 65).
        let err = EcdhPublicKey::from_bytes(EcdhCurve::P256, &[0u8; 64]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KeyParsing);

        // One byte too long for X25519 (expects 32).
        let err = EcdhPublicKey::from_bytes(EcdhCurve::X25519, &[0u8; 33]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KeyParsing);
    }

    #[test]
    fn compressed_point_rejected() {
        // 65-byte buffer but tag is 0x02 (compressed), not 0x04.
        let mut bytes = [0u8; 65];
        bytes[0] = 0x02;
        let err = EcdhPublicKey::from_bytes(EcdhCurve::P256, &bytes).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KeyParsing);
    }

    #[test]
    fn x25519_low_order_point_rejected() {
        // All-zeros is a low-order point for X25519; aws-lc-rs rejects these internally.
        // Pins that rejection returns KeyParsing so a kind-change would be caught.
        let low_order_point = [0u8; 32];
        let peer = EcdhPublicKey::from_bytes(EcdhCurve::X25519, &low_order_point).unwrap();
        let alice = EphemeralEcdhKey::generate(EcdhCurve::X25519).unwrap();
        assert_eq!(
            alice.agree(&peer).unwrap_err().kind(),
            ErrorKind::KeyParsing
        );
    }

    #[test]
    fn curve_mismatch_rejected() {
        // P-256 public key offered to a P-384 ephemeral key.
        let p256_priv = PrivateKey::generate(&lc::ECDH_P256).unwrap();
        let p256_pub = p256_priv.compute_public_key().unwrap();
        let peer = EcdhPublicKey::from_bytes(EcdhCurve::P256, p256_pub.as_ref()).unwrap();

        let alice = EphemeralEcdhKey::generate(EcdhCurve::P384).unwrap();
        let err = alice.agree(&peer).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KeyParsing);
    }

    #[test]
    fn shared_secret_exposes_curve() {
        let bob = PrivateKey::generate(EcdhCurve::P256.into()).unwrap();
        let bob_pub = bob.compute_public_key().unwrap();
        let alice = EphemeralEcdhKey::generate(EcdhCurve::P256).unwrap();
        let secret = alice
            .agree(&EcdhPublicKey::from_bytes(EcdhCurve::P256, bob_pub.as_ref()).unwrap())
            .unwrap();
        assert_eq!(secret.curve(), EcdhCurve::P256);
    }

    #[test]
    fn debug_hides_key_material() {
        let key = EphemeralEcdhKey::generate(EcdhCurve::P256).unwrap();
        // Capture the public key bytes BEFORE consuming the key via Debug format.
        // pub_bytes borrows from pub_buf (not from key), so key remains usable.
        let mut pub_buf = vec![0u8; EcdhCurve::P256.public_key_len()];
        let pub_bytes = key.public_key_bytes(&mut pub_buf).unwrap();
        let dbg = format!("{key:?}");

        assert!(dbg.contains("EphemeralEcdhKey"));

        // Verify that the raw key bytes do not appear hex-encoded in the output.
        // Sample 8 bytes from the middle of the 65-byte public key to keep the
        // false-positive probability astronomically low (~2^-64).
        let hex_sample: String = pub_bytes[10..18]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(
            !dbg.to_lowercase().contains(&hex_sample),
            "Debug output must not contain raw key bytes"
        );
    }

    #[test]
    fn public_key_equality() {
        // Parsing the same bytes twice must yield equal keys.
        let ephemeral = EphemeralEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut buf = vec![0u8; EcdhCurve::P256.public_key_len()];
        let bytes = ephemeral.public_key_bytes(&mut buf).unwrap().to_vec();

        let key_a = EcdhPublicKey::from_bytes(EcdhCurve::P256, &bytes).unwrap();
        let key_b = EcdhPublicKey::from_bytes(EcdhCurve::P256, &bytes).unwrap();
        assert_eq!(key_a, key_b);

        // A freshly generated key must not equal the first (negligible collision probability).
        let other = EphemeralEcdhKey::generate(EcdhCurve::P256).unwrap();
        let mut other_buf = vec![0u8; EcdhCurve::P256.public_key_len()];
        let other_bytes = other.public_key_bytes(&mut other_buf).unwrap().to_vec();
        let key_c = EcdhPublicKey::from_bytes(EcdhCurve::P256, &other_bytes).unwrap();
        assert_ne!(key_a, key_c);

        // Different curves use different PublicKeyBytes variants and must never compare equal,
        // even when the raw bytes happen to share a common prefix.
        let x_bytes = [0x42u8; 32];
        let x_key = EcdhPublicKey::from_bytes(EcdhCurve::X25519, &x_bytes).unwrap();
        let p_key = EcdhPublicKey::from_bytes(EcdhCurve::P256, &bytes).unwrap();
        assert_ne!(x_key, p_key);
    }

    #[cfg(feature = "jwe")]
    mod static_key_tests {
        use super::*;
        use aws_lc_rs::agreement::{self as lc, PrivateKey};

        #[test]
        fn static_round_trip_all_curves() {
            for curve in [
                EcdhCurve::P256,
                EcdhCurve::P384,
                EcdhCurve::P521,
                EcdhCurve::X25519,
            ] {
                let static_key = StaticEcdhKey::generate(curve).unwrap();

                let mut static_pub_buf = vec![0u8; curve.public_key_len()];
                let static_pub_bytes = static_key.public_key_bytes(&mut static_pub_buf).unwrap();
                let static_pub = EcdhPublicKey::from_bytes(curve, static_pub_bytes).unwrap();

                let ephemeral = EphemeralEcdhKey::generate(curve).unwrap();
                let mut ephem_pub_buf = vec![0u8; curve.public_key_len()];
                let ephem_pub_bytes = ephemeral.public_key_bytes(&mut ephem_pub_buf).unwrap();
                let ephem_pub = EcdhPublicKey::from_bytes(curve, ephem_pub_bytes).unwrap();

                let sender_secret = ephemeral.agree(&static_pub).unwrap();
                let recipient_secret = static_key.agree_with(&ephem_pub).unwrap();

                assert_eq!(
                    sender_secret.as_bytes(),
                    recipient_secret.as_bytes(),
                    "curve {curve:?}"
                );
                assert!(
                    !recipient_secret.as_bytes().iter().all(|&b| b == 0),
                    "curve {curve:?}"
                );
                assert_eq!(recipient_secret.curve(), curve, "curve {curve:?}");
            }
        }

        #[test]
        fn static_from_pkcs8_der_p256() {
            // Load a P-256 key from PKCS#8 DER and confirm agree_with produces the
            // same shared secret as the matching ephemeral direction (commutativity).
            let key_der = include_bytes!("../test_data/secp256r1.pkcs8.der");
            let static_key = StaticEcdhKey::from_pkcs8_der(EcdhCurve::P256, key_der).unwrap();
            assert_eq!(static_key.curve(), EcdhCurve::P256);

            let mut static_pub_buf = vec![0u8; EcdhCurve::P256.public_key_len()];
            let static_pub_bytes = static_key.public_key_bytes(&mut static_pub_buf).unwrap();
            let static_pub = EcdhPublicKey::from_bytes(EcdhCurve::P256, static_pub_bytes).unwrap();

            let ephemeral = EphemeralEcdhKey::generate(EcdhCurve::P256).unwrap();
            let mut ephem_pub_buf = vec![0u8; EcdhCurve::P256.public_key_len()];
            let ephem_pub_bytes = ephemeral.public_key_bytes(&mut ephem_pub_buf).unwrap();
            let ephem_pub = EcdhPublicKey::from_bytes(EcdhCurve::P256, ephem_pub_bytes).unwrap();
            let sender_secret = ephemeral.agree(&static_pub).unwrap();
            let recipient_secret = static_key.agree_with(&ephem_pub).unwrap();

            assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
            assert!(!recipient_secret.as_bytes().iter().all(|&b| b == 0));
        }

        #[test]
        fn static_from_pkcs8_der_x25519_rejected() {
            let dummy = [0u8; 32];
            let err = StaticEcdhKey::from_pkcs8_der(EcdhCurve::X25519, &dummy).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
        }

        #[test]
        fn static_from_private_key_bytes_x25519() {
            let mut seed = [0u8; 32];
            crate::rand::fill_bytes(&mut seed).unwrap();
            let key = StaticEcdhKey::from_private_key_bytes(EcdhCurve::X25519, &seed).unwrap();
            assert_eq!(key.curve(), EcdhCurve::X25519);
        }

        #[test]
        fn static_wrong_length_rejected() {
            // One byte short for P-256 scalar (needs 32).
            let err =
                StaticEcdhKey::from_private_key_bytes(EcdhCurve::P256, &[0u8; 31]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::KeyParsing);
        }

        #[test]
        fn static_curve_mismatch_rejected() {
            let static_key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();
            let p384_priv = PrivateKey::generate(&lc::ECDH_P384).unwrap();
            let p384_pub_raw = p384_priv.compute_public_key().unwrap();
            let peer = EcdhPublicKey::from_bytes(EcdhCurve::P384, p384_pub_raw.as_ref()).unwrap();
            let err = static_key.agree_with(&peer).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::KeyParsing);
        }

        #[test]
        fn static_debug_hides_key_material() {
            let key = StaticEcdhKey::generate(EcdhCurve::P256).unwrap();

            let mut pub_buf = vec![0u8; EcdhCurve::P256.public_key_len()];
            let pub_bytes = key.public_key_bytes(&mut pub_buf).unwrap();

            let dbg = format!("{key:?}");
            assert!(dbg.contains("StaticEcdhKey"));
            assert!(!dbg.contains("inner"));

            // Sample 8 bytes from the middle of the 65-byte public key; the
            // probability of a false positive is ~2^-64.
            let hex_sample: String = pub_bytes[10..18]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert!(
                !dbg.to_lowercase().contains(&hex_sample),
                "Debug output must not contain raw key bytes"
            );
        }

        // Compile-time proof of the thread-safety doc claim on StaticEcdhKey.
        // If aws-lc-rs ever removes Send/Sync from PrivateKey, this will fail to compile.
        #[test]
        fn static_key_is_send_sync() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<StaticEcdhKey>();
        }
    }
}
