//! JWE protected header types.
//!
//! Defines the algorithm enums and [`JweHeader`] struct that represent the
//! JOSE protected header for JSON Web Encryption (RFC 7516).

use crate::aead;
use crate::aes_kek::KeyWrapAlgorithm;
use crate::error::{ErrorKind, Result};
use crate::jwk::B64;
use crate::rsa::oaep::OaepAlgorithm;
use crate::utils::error_msg;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// JWE key management algorithms supported by this crate (RFC 7518 §4).
///
/// Deserialization fails on any algorithm not listed here, providing fail-fast
/// rejection of unsupported algorithms before any cryptographic work begins.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgAlgorithm {
    /// RSAES OAEP using SHA-256 and MGF1-SHA-256 (RFC 7518 §4.3).
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,

    /// RSAES OAEP using SHA-384 and MGF1-SHA-384 (RFC 8230).
    #[serde(rename = "RSA-OAEP-384")]
    RsaOaep384,

    /// RSAES OAEP using SHA-512 and MGF1-SHA-512 (RFC 8230).
    #[serde(rename = "RSA-OAEP-512")]
    RsaOaep512,

    /// ECDH-ES direct key agreement (RFC 7518 §4.6).
    ///
    /// The derived key is used directly as the content encryption key (CEK).
    /// The `enc` algorithm ID is used as the ConcatKDF `algorithmID` field.
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES with AES-128 Key Wrap (RFC 7518 §4.6).
    ///
    /// ECDH-ES derives a 128-bit KEK which wraps a separately generated CEK.
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128Kw,

    /// ECDH-ES with AES-256 Key Wrap (RFC 7518 §4.6).
    ///
    /// ECDH-ES derives a 256-bit KEK which wraps a separately generated CEK.
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,
}

impl AlgAlgorithm {
    /// Returns `true` if this is an RSA-OAEP key management algorithm.
    #[must_use]
    pub(crate) fn is_rsa(self) -> bool {
        matches!(self, Self::RsaOaep256 | Self::RsaOaep384 | Self::RsaOaep512)
    }

    /// Returns `true` if this is an ECDH-ES key management algorithm.
    #[must_use]
    pub(crate) fn is_ecdh(self) -> bool {
        matches!(self, Self::EcdhEs | Self::EcdhEsA128Kw | Self::EcdhEsA256Kw)
    }

    /// Maps an RSA-OAEP variant to its OAEP hash algorithm; `None` for ECDH variants.
    #[must_use]
    pub(crate) fn to_oaep_algorithm(self) -> Option<OaepAlgorithm> {
        match self {
            Self::RsaOaep256 => Some(OaepAlgorithm::Sha256),
            Self::RsaOaep384 => Some(OaepAlgorithm::Sha384),
            Self::RsaOaep512 => Some(OaepAlgorithm::Sha512),
            _ => None,
        }
    }

    /// ConcatKDF `algorithmID` for KW variants (RFC 7518 §4.6.2); `None` for non-KW variants.
    #[must_use]
    pub(crate) fn kdf_alg_id(self) -> Option<&'static [u8]> {
        match self {
            Self::EcdhEsA128Kw => Some(b"ECDH-ES+A128KW"),
            Self::EcdhEsA256Kw => Some(b"ECDH-ES+A256KW"),
            _ => None,
        }
    }

    /// KEK length in bytes for KW variants; `None` for non-KW variants.
    #[must_use]
    pub(crate) fn kek_len(self) -> Option<usize> {
        match self {
            Self::EcdhEsA128Kw => Some(16),
            Self::EcdhEsA256Kw => Some(32),
            _ => None,
        }
    }

    /// AES Key Wrap algorithm for KW variants; `None` for non-KW variants.
    #[must_use]
    pub(crate) fn kw_algorithm(self) -> Option<KeyWrapAlgorithm> {
        match self {
            Self::EcdhEsA128Kw => Some(KeyWrapAlgorithm::A128Kw),
            Self::EcdhEsA256Kw => Some(KeyWrapAlgorithm::A256Kw),
            _ => None,
        }
    }
}

/// JWE content encryption algorithms supported by this crate (RFC 7518 §5).
///
/// Deserialization fails on any algorithm not listed here.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncAlgorithm {
    /// AES-GCM with 128-bit key (RFC 7518 §5.3).
    #[serde(rename = "A128GCM")]
    A128Gcm,

    /// AES-GCM with 256-bit key (RFC 7518 §5.3).
    #[serde(rename = "A256GCM")]
    A256Gcm,
}

impl EncAlgorithm {
    /// Key length in bytes required for this content encryption algorithm.
    #[must_use]
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A256Gcm => 32,
        }
    }

    /// Maps to the underlying AEAD algorithm for [`crate::aead::Key`].
    #[must_use]
    pub(crate) fn aead_algorithm(self) -> aead::Algorithm {
        match self {
            Self::A128Gcm => aead::Algorithm::AesGcm128,
            Self::A256Gcm => aead::Algorithm::AesGcm256,
        }
    }

    /// ASCII algorithm identifier used as `algorithmID` in ConcatKDF (RFC 7518 §4.6.2).
    ///
    /// For ECDH-ES direct mode the `enc` value is used; for +KW modes the
    /// `alg` value is used instead (handled in the encrypt/decrypt paths).
    #[must_use]
    pub(crate) fn alg_id(self) -> &'static [u8] {
        match self {
            Self::A128Gcm => b"A128GCM",
            Self::A256Gcm => b"A256GCM",
        }
    }
}

/// Registered JWE/JWA header parameter names (RFC 7516 §4, RFC 7518 §4).
///
/// Per RFC 7516 §4.1.13 these MUST NOT appear in the `crit` array; doing so is
/// a protocol error and this implementation rejects such tokens.
const REGISTERED_HEADER_PARAMS: &[&str] = &[
    "alg", "enc", "epk", "apu", "apv", "kid", "typ", "cty", "crit",
];

/// Extension header parameters understood by this implementation.
///
/// A `crit` entry that is neither a registered parameter nor listed here causes
/// [`JweHeader::validate`] to return [`ErrorKind::UnsupportedAlgorithm`].
/// Currently empty — no proprietary extensions are defined by this crate.
const UNDERSTOOD_EXTENSION_PARAMS: &[&str] = &[];

/// JWE protected header (RFC 7516 §4).
///
/// All fields except `alg` and `enc` are optional. The `epk`, `apu`, and `apv`
/// fields are used only for ECDH-ES key agreement algorithms.
///
/// During encryption the `epk` field is populated by [`fn@crate::jwe::encrypt`]
/// after the ephemeral key is generated; callers should leave it `None` when
/// constructing a header for encryption.
///
/// Use [`JweHeader::new`] to construct a header; struct literal syntax is not
/// available to code outside this crate because this type is `#[non_exhaustive]`.
#[non_exhaustive]
#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JweHeader {
    /// Key management algorithm.
    pub alg: AlgAlgorithm,

    /// Content encryption algorithm.
    pub enc: EncAlgorithm,

    /// Ephemeral public key (ECDH-ES variants only).
    ///
    /// Set automatically by [`fn@crate::jwe::encrypt`]; populated from the token
    /// during decryption. Stored as a JWK without private key material.
    #[serde(default)]
    pub epk: Option<crate::jwk::Jwk>,

    /// Agreement PartyUInfo — base64url-decoded bytes on the wire (RFC 7518 §4.6.1.2).
    ///
    /// Used in the ConcatKDF derivation for ECDH-ES variants only. **Ignored for
    /// RSA-OAEP variants** (RFC 7518 §4.3 does not define `apu`/`apv` semantics);
    /// if set, the bytes are still serialised into the header and bound to the
    /// AES-GCM AAD, but they do not influence key derivation.
    #[serde(default)]
    pub apu: Option<B64>,

    /// Agreement PartyVInfo — base64url-decoded bytes on the wire (RFC 7518 §4.6.1.3).
    ///
    /// Used in the ConcatKDF derivation for ECDH-ES variants only. **Ignored for
    /// RSA-OAEP variants** — see `apu` for details.
    #[serde(default)]
    pub apv: Option<B64>,

    /// Key identifier.
    #[serde(default)]
    pub kid: Option<String>,

    /// Media type of the JWE.
    #[serde(default)]
    pub typ: Option<String>,

    /// Content type of the plaintext.
    #[serde(default)]
    pub cty: Option<String>,

    /// Critical header parameters (RFC 7516 §4.1.13).
    ///
    /// If present, each listed parameter must be understood by the recipient.
    /// Validation is enforced by [`JweHeader::validate`].
    #[serde(default)]
    pub crit: Option<Vec<String>>,
}

impl JweHeader {
    /// Construct a header with the given key-management and content-encryption algorithms,
    /// with all optional fields set to `None`.
    ///
    /// The `epk` field is always `None` here; [`fn@crate::jwe::encrypt`] populates it
    /// automatically for ECDH-ES variants.
    pub fn new(alg: AlgAlgorithm, enc: EncAlgorithm) -> Self {
        Self {
            alg,
            enc,
            epk: None,
            apu: None,
            apv: None,
            kid: None,
            typ: None,
            cty: None,
            crit: None,
        }
    }

    /// Validate the header against RFC 7516 §4.1.13 `crit` rules.
    ///
    /// Three conditions are enforced:
    /// 1. **B-2** — The `crit` array, if present, must not be empty.
    /// 2. **B-3** — Each entry must not be a registered JOSE header parameter
    ///    (`alg`, `enc`, `epk`, etc.); listing them in `crit` is explicitly
    ///    forbidden by RFC 7516 §4.1.13.
    /// 3. Each entry must be understood by this implementation (currently no
    ///    proprietary extensions are defined, so any extension param is rejected).
    ///
    /// Called by both [`fn@crate::jwe::encrypt`] and [`fn@crate::jwe::decrypt`] so that
    /// neither side can produce or accept non-conformant tokens.
    ///
    /// # Errors
    /// [`ErrorKind::UnsupportedAlgorithm`] if any of the three conditions above
    /// is violated.
    pub fn validate(&self) -> Result<()> {
        if let Some(crit) = &self.crit {
            // B-2: RFC 7516 §4.1.13 — "The value of the crit member MUST NOT be
            // an empty list."
            if crit.is_empty() {
                return Err(error_msg(
                    ErrorKind::UnsupportedAlgorithm,
                    "crit array MUST NOT be empty (RFC 7516 §4.1.13)",
                ));
            }
            for param in crit {
                // B-3: RFC 7516 §4.1.13 — registered header parameters MUST NOT
                // appear in crit; they are defined by the spec, not extensions.
                if REGISTERED_HEADER_PARAMS.contains(&param.as_str()) {
                    return Err(error_msg(
                        ErrorKind::UnsupportedAlgorithm,
                        format!(
                            "crit MUST NOT list registered JOSE header parameter \
                             \"{param}\" (RFC 7516 §4.1.13)"
                        ),
                    ));
                }
                if !UNDERSTOOD_EXTENSION_PARAMS.contains(&param.as_str()) {
                    return Err(error_msg(
                        ErrorKind::UnsupportedAlgorithm,
                        format!(
                            "critical header parameter \"{param}\" is not understood \
                             (RFC 7516 §4.1.13)"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}
