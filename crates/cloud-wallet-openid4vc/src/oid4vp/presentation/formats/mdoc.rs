//! ISO mdoc (ISO 18013-5) presentation format as defined in [OpenID4VP Appendix B.2].
//!
//! Implements the Wallet-side logic for building mdoc presentations:
//!
//! 1. **Session Transcript** — constructs the `SessionTranscript` with the
//!    `OID4VPHandover` structure per Appendix B.2.6.
//! 2. **Device Signature** — constructs and signs a COSE_Sign1 `DeviceSignature`
//!    over the `DeviceAuthentication` payload (§9.1.2.4).
//! 3. **Presentation assembly** — produces the final base64url-encoded CBOR
//!    `DeviceResponse` (§8.3.2.1.2).
//!
//! # Example
//!
//! ```ignore
//! use cloud_wallet_openid4vc::oid4vp::presentation::mdoc::MdocPresentation;
//!
//! let mdoc_presentation = MdocPresentation::builder(doc_type, session_transcript)
//!     .algorithm(iana::Algorithm::ES256)
//!     .add_device_claim(namespace, claim_name, value)
//!     .issuer_signed(issuer_signed_value)
//!     .signer(|tbs| { /* sign DeviceAuthentication bytes */ })
//!     .build();
//!
//! let presentation = mdoc_presentation.create_presentation()?;
//! ```
//!
//! [OpenID4VP Appendix B.2]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2

use std::borrow::Cow;
use std::collections::BTreeMap;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::ser::into_writer;
use ciborium::value::Value;
use coset::{AsCborValue, CoseSign1Builder, HeaderBuilder, iana};
use thiserror::Error;

use crate::core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer};
use crate::oid4vp::authorization::Presentation;
use crate::oid4vp::dcql::ClaimsQuery;
use crate::oid4vp::presentation::PresentationFactory;
use crate::oid4vp::presentation::error::ProofError;
use cloud_wallet_crypto::digest::HashAlg;

/// Function type for signing `DeviceAuthentication` bytes.
///
/// Receives the COSE `Sig_Structure` bytes (per RFC 9052 §4.4) and must return
/// the raw EC signature bytes (e.g., for ES256: the 64-byte r‖s encoding).
/// The signer must use the device private key corresponding to the key in
/// `IssuerSigned`.
pub type DeviceSigner = Box<dyn Fn(&[u8]) -> Result<Vec<u8>, ProofError> + Send + Sync>;

/// Errors produced while building ISO mdoc OpenID4VP presentation artifacts.
#[derive(Debug, Error)]
pub enum MdocVpError {
    /// The claims path does not have the mdoc-specific `[namespace, claim_name]` shape.
    #[error("mdoc claims path must contain exactly two string elements")]
    InvalidClaimsPath,
    /// A claims path element was not a string.
    #[error("mdoc claims path element {index} must be a string")]
    InvalidClaimsPathElement { index: usize },
    /// A required string field was empty.
    #[error("{field} must not be empty")]
    EmptyField { field: &'static str },
    /// CBOR serialisation failed.
    #[error("failed to serialise CBOR value")]
    CborEncode(#[source] ciborium::ser::Error<std::io::Error>),
    /// COSE signing or structure error.
    #[error("COSE error: {0}")]
    CoseSign(#[from] coset::CoseError),
    /// Signing failed.
    #[error("failed to sign DeviceSignature: {0}")]
    Signing(String),
}

impl From<MdocVpError> for ProofError {
    fn from(value: MdocVpError) -> Self {
        Self::Format(Box::new(value))
    }
}

/// mdoc-specific interpretation of a DCQL claims query.
///
/// This normalises a claims path into the `namespace` + `claim_name` pair used
/// by ISO mdoc presentation logic.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MdocClaimsQuery {
    /// ISO namespace string.
    pub namespace: String,
    /// Data element identifier.
    pub claim_name: String,
}

impl TryFrom<ClaimsQuery> for MdocClaimsQuery {
    type Error = MdocVpError;

    fn try_from(query: ClaimsQuery) -> Result<Self, Self::Error> {
        let (namespace, claim_name) = claim_path_to_namespace_and_element(&query.path)?;
        Ok(Self {
            namespace,
            claim_name,
        })
    }
}

/// Converts a DCQL claim path into the mdoc namespace/data-element pair.
pub fn claim_path_to_namespace_and_element(
    path: &ClaimPathPointer,
) -> Result<(String, String), MdocVpError> {
    let elements = path.elements();
    if elements.len() != 2 {
        return Err(MdocVpError::InvalidClaimsPath);
    }

    let namespace = match &elements[0] {
        ClaimPathElement::String(value) => value.clone(),
        _ => return Err(MdocVpError::InvalidClaimsPathElement { index: 0 }),
    };
    let claim_name = match &elements[1] {
        ClaimPathElement::String(value) => value.clone(),
        _ => return Err(MdocVpError::InvalidClaimsPathElement { index: 1 }),
    };

    if namespace.trim().is_empty() {
        return Err(MdocVpError::EmptyField { field: "namespace" });
    }
    if claim_name.trim().is_empty() {
        return Err(MdocVpError::EmptyField {
            field: "claim_name",
        });
    }

    Ok((namespace, claim_name))
}

/// OpenID4VP handover structure per Appendix B.2.6.
///
/// CDDL: `OID4VPHandover = [ "OpenID4VP", clientIdHash: bstr, responseUriHash: bstr, nonce: tstr ]`
///
/// `clientIdHash`  = SHA-256(clientId)
/// `responseUriHash` = SHA-256(responseUri)
///
/// The hash fields are kept private to guarantee they are exactly 32-byte
/// SHA-256 digests, preventing callers from constructing a spec-invalid
/// handover with wrong-length byte strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenID4VPHandover {
    client_id_hash: [u8; 32],
    response_uri_hash: [u8; 32],
    nonce: String,
}

impl OpenID4VPHandover {
    /// Creates the handover from the verifier request parameters,
    /// hashing `client_id` and `response_uri` with SHA-256.
    ///
    /// Returns an error if `client_id`, `response_uri`, or `nonce` is empty,
    /// since empty inputs would produce SHA-256 hashes of empty strings —
    /// structurally valid but semantically meaningless.
    pub fn new(
        client_id: &str,
        response_uri: &str,
        nonce: String,
    ) -> Result<Self, MdocVpError> {
        if client_id.trim().is_empty() {
            return Err(MdocVpError::EmptyField { field: "client_id" });
        }
        if response_uri.trim().is_empty() {
            return Err(MdocVpError::EmptyField {
                field: "response_uri",
            });
        }
        if nonce.trim().is_empty() {
            return Err(MdocVpError::EmptyField { field: "nonce" });
        }
        let client_id_hash: [u8; 32] = HashAlg::Sha256
            .hash(client_id.as_bytes())
            .as_ref()
            .try_into()
            .expect("SHA-256 produces 32 bytes");
        let response_uri_hash: [u8; 32] = HashAlg::Sha256
            .hash(response_uri.as_bytes())
            .as_ref()
            .try_into()
            .expect("SHA-256 produces 32 bytes");
        Ok(Self {
            client_id_hash,
            response_uri_hash,
            nonce,
        })
    }

    /// Returns the SHA-256 digest of `client_id`.
    pub fn client_id_hash(&self) -> &[u8; 32] {
        &self.client_id_hash
    }

    /// Returns the SHA-256 digest of `response_uri`.
    pub fn response_uri_hash(&self) -> &[u8; 32] {
        &self.response_uri_hash
    }

    /// Returns the nonce value.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Serialises the structure to a CBOR value.
    ///
    /// Produces `["OpenID4VP", clientIdHash, responseUriHash, nonce]`.
    pub fn to_cbor_value(&self) -> Value {
        Value::Array(vec![
            Value::Text("OpenID4VP".to_string()),
            Value::Bytes(self.client_id_hash.to_vec()),
            Value::Bytes(self.response_uri_hash.to_vec()),
            Value::Text(self.nonce.clone()),
        ])
    }

    /// Serialises the structure to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, MdocVpError> {
        let mut buf = Vec::new();
        into_writer(&self.to_cbor_value(), &mut buf)
            .map_err(MdocVpError::CborEncode)?;
        Ok(buf)
    }
}

/// OpenID4VP session transcript structure.
///
/// CDDL: `SessionTranscript = [ null, null, OID4VPHandover ]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTranscript {
    pub handover: OpenID4VPHandover,
}

impl SessionTranscript {
    /// Creates the redirect-based session transcript required for OID4VP.
    pub fn new(handover: OpenID4VPHandover) -> Self {
        Self { handover }
    }

    /// Serialises the structure to a CBOR value.
    pub fn to_cbor_value(&self) -> Value {
        Value::Array(vec![
            Value::Null,
            Value::Null,
            self.handover.to_cbor_value(),
        ])
    }
}

/// ISO mdoc presentation for building verifiable presentations.
///
/// Orchestrates `DeviceAuthentication` construction, COSE_Sign1 signature
/// generation, and final `DeviceResponse` assembly as specified in
/// [ISO 18013-5 §9.1.2.4] and [OpenID4VP Appendix B.2].
///
/// Use [`MdocPresentationBuilder`] (via [`MdocPresentation::builder`]) for
/// ergonomic construction.
///
/// [ISO 18013-5 §9.1.2.4]: https://www.iso.org/standard/69084.html
/// [OpenID4VP Appendix B.2]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2
pub struct MdocPresentation {
    doc_type: String,
    device_namespaces: BTreeMap<String, BTreeMap<String, Value>>,
    session_transcript: SessionTranscript,
    algorithm: iana::Algorithm,
    issuer_signed: Value,
    signer: DeviceSigner,
}

impl MdocPresentation {
    /// Returns a builder for constructing an `MdocPresentation`.
    pub fn builder(
        doc_type: impl Into<String>,
        session_transcript: SessionTranscript,
    ) -> MdocPresentationBuilder {
        MdocPresentationBuilder {
            doc_type: doc_type.into(),
            device_namespaces: BTreeMap::new(),
            session_transcript,
            algorithm: iana::Algorithm::ES256,
            issuer_signed: None,
            signer: None,
        }
    }
}

/// Constructs `DeviceAuthenticationBytes` per ISO 18013-5 §9.1.2.4.
///
/// Returns the bytes of `#6.24(bstr .cbor DeviceAuthentication)`, which is the
/// payload that gets signed via COSE_Sign1 with detached content.
fn build_device_authentication_bytes(
    doc_type: &str,
    session_transcript: &SessionTranscript,
    device_ns_tagged: Value,
) -> Result<Vec<u8>, MdocVpError> {
    let device_authentication = Value::Array(vec![
        Value::Text("DeviceAuthentication".to_string()),
        session_transcript.to_cbor_value(),
        Value::Text(doc_type.to_string()),
        device_ns_tagged,
    ]);
    let device_auth_bytes = value_to_bytes(&device_authentication)?;
    let device_auth_tagged = Value::Tag(24, Box::new(Value::Bytes(device_auth_bytes)));
    value_to_bytes(&device_auth_tagged)
}

/// Signs `DeviceAuthenticationBytes` with a detached COSE_Sign1 per
/// ISO 18013-5 §9.1.2.4.
///
/// The payload is nil (detached); the actual data is carried in
/// `Sig_Structure.payload`. External AAD is empty per spec.
fn sign_device_authentication(
    device_auth_bytes: &[u8],
    algorithm: iana::Algorithm,
    signer: &DeviceSigner,
) -> Result<coset::CoseSign1, MdocVpError> {
    let protected = HeaderBuilder::new().algorithm(algorithm).build();
    Ok(CoseSign1Builder::new()
        .protected(protected)
        .try_create_detached_signature(device_auth_bytes, &[], |tbs| {
            signer(tbs).map_err(|e| MdocVpError::Signing(e.to_string()))
        })?
        .build())
}

/// Assembles a `DeviceResponse` map per ISO 18013-5 §8.3.2.1.2.
fn build_device_response(
    doc_type: &str,
    issuer_signed: Value,
    device_ns_tagged: Value,
    sign1: coset::CoseSign1,
) -> Result<Value, MdocVpError> {
    let device_signed = Value::Map(vec![
        (Value::Text("nameSpaces".to_string()), device_ns_tagged),
        (
            Value::Text("deviceAuth".to_string()),
            Value::Map(vec![(
                Value::Text("deviceSignature".to_string()),
                sign1.to_cbor_value().map_err(MdocVpError::from)?,
            )]),
        ),
    ]);

    let document = Value::Map(vec![
        (
            Value::Text("docType".to_string()),
            Value::Text(doc_type.to_string()),
        ),
        (Value::Text("issuerSigned".to_string()), issuer_signed),
        (Value::Text("deviceSigned".to_string()), device_signed),
    ]);

    Ok(Value::Map(vec![
        (
            Value::Text("version".to_string()),
            Value::Text("1.0".to_string()),
        ),
        (
            Value::Text("documents".to_string()),
            Value::Array(vec![document]),
        ),
        (Value::Text("status".to_string()), Value::Integer(0.into())),
    ]))
}

impl PresentationFactory for MdocPresentation {
    fn create_presentation(self) -> Result<Presentation, ProofError> {
        let Self {
            doc_type,
            device_namespaces,
            session_transcript,
            algorithm,
            issuer_signed,
            signer,
        } = self;

        if doc_type.trim().is_empty() {
            return Err(ProofError::InvalidInput(Cow::Borrowed(
                "doc_type must not be empty",
            )));
        }

        let device_ns_value = Value::Map(
            device_namespaces
                .into_iter()
                .map(|(ns, claims)| {
                    let claim_entries: Vec<(Value, Value)> = claims
                        .into_iter()
                        .map(|(k, v)| (Value::Text(k), v))
                        .collect();
                    (Value::Text(ns), Value::Map(claim_entries))
                })
                .collect(),
        );
        let device_ns_bytes = value_to_bytes(&device_ns_value)?;
        let device_ns_tagged = Value::Tag(24, Box::new(Value::Bytes(device_ns_bytes.clone())));

        let device_auth_bytes =
            build_device_authentication_bytes(&doc_type, &session_transcript, device_ns_tagged)?;

        let sign1 = sign_device_authentication(&device_auth_bytes, algorithm, &signer)?;

        let device_ns_tagged_for_signed = Value::Tag(24, Box::new(Value::Bytes(device_ns_bytes)));
        let device_response =
            build_device_response(&doc_type, issuer_signed, device_ns_tagged_for_signed, sign1)?;

        let bytes = value_to_bytes(&device_response)?;
        let encoded = Base64UrlUnpadded::encode_string(&bytes);

        Ok(Presentation::String(encoded))
    }
}

impl std::fmt::Debug for MdocPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdocPresentation")
            .field("doc_type", &self.doc_type)
            .field("algorithm", &self.algorithm)
            .field(
                "device_namespaces",
                &format!(
                    "{} namespace(s) redacted",
                    self.device_namespaces.len()
                ),
            )
            .finish_non_exhaustive()
    }
}

/// Builder for [`MdocPresentation`].
pub struct MdocPresentationBuilder {
    doc_type: String,
    device_namespaces: BTreeMap<String, BTreeMap<String, Value>>,
    session_transcript: SessionTranscript,
    algorithm: iana::Algorithm,
    issuer_signed: Option<Value>,
    signer: Option<DeviceSigner>,
}

impl MdocPresentationBuilder {
    /// Sets the COSE signing algorithm used for `DeviceSignature`.
    pub fn algorithm(mut self, algorithm: iana::Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Adds one device-asserted data element to `deviceSigned.nameSpaces`.
    ///
    /// For most mdoc presentations `deviceSigned.nameSpaces` is empty or
    /// minimal; the credential data comes from
    /// [`MdocPresentationBuilder::issuer_signed`].
    ///
    /// The name `add_device_claim` makes it clear that these values populate
    /// the device-asserted namespace, not the issuer-signed attributes.
    ///
    /// The `value` parameter accepts a CBOR [`Value`] to preserve native mdoc
    /// types (e.g., full-date tags, bstr) that have no JSON equivalent.
    pub fn add_device_claim(
        mut self,
        namespace: impl Into<String>,
        claim_name: impl Into<String>,
        value: Value,
    ) -> Self {
        self.device_namespaces
            .entry(namespace.into())
            .or_default()
            .insert(claim_name.into(), value);
        self
    }

    /// Adds a set of device-asserted claims for one namespace.
    pub fn add_device_namespace(
        mut self,
        namespace: impl Into<String>,
        claims: BTreeMap<String, Value>,
    ) -> Self {
        self.device_namespaces.insert(namespace.into(), claims);
        self
    }

    /// Sets the `issuerSigned` CBOR value for this document.
    ///
    /// Per ISO 18013-5 the `issuerSigned` map contains `"nameSpaces"` and
    /// `"issuerAuth"`. The caller is responsible for constructing the CBOR
    /// value, including the issuer's COSE_Sign1 under `"issuerAuth"`.
    pub fn issuer_signed(mut self, value: Value) -> Self {
        self.issuer_signed = Some(value);
        self
    }

    /// Sets the signing function that produces the COSE_Sign1 signature.
    ///
    /// The function receives the COSE `Sig_Structure` bytes (per RFC 9052 §4.4)
    /// and must return the raw EC signature bytes (e.g., for ES256: the 64-byte
    /// r‖s encoding). The signer must use the device private key corresponding
    /// to the key in `IssuerSigned`.
    pub fn signer<F>(mut self, f: F) -> Self
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, ProofError> + Send + Sync + 'static,
    {
        self.signer = Some(Box::new(f));
        self
    }

    /// Builds the [`MdocPresentation`].
    ///
    /// # Errors
    ///
    /// Returns an error if `issuer_signed` has not been set via
    /// [`MdocPresentationBuilder::issuer_signed`].
    pub fn build(self) -> Result<MdocPresentation, ProofError> {
        let issuer_signed = self
            .issuer_signed
            .ok_or_else(|| ProofError::MissingRequiredField(Cow::Borrowed("issuer_signed")))?;
        let signer = self
            .signer
            .ok_or_else(|| ProofError::MissingRequiredField(Cow::Borrowed("signer")))?;
        Ok(MdocPresentation {
            doc_type: self.doc_type,
            device_namespaces: self.device_namespaces,
            session_transcript: self.session_transcript,
            algorithm: self.algorithm,
            issuer_signed,
            signer,
        })
    }
}

fn value_to_bytes(value: &Value) -> Result<Vec<u8>, MdocVpError> {
    let mut buf = Vec::new();
    into_writer(value, &mut buf).map_err(MdocVpError::CborEncode)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{CborSerializable, CoseSign1};

    fn sample_handover() -> OpenID4VPHandover {
        OpenID4VPHandover::new(
            "wallet.example",
            "https://verifier.example/cb",
            "nonce-123".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn maps_claim_path_pointer_to_namespace_and_element() {
        let query = ClaimsQuery {
            path: ClaimPathPointer::new(vec![
                ClaimPathElement::from("org.iso.18013.5.1"),
                ClaimPathElement::from("family_name"),
            ]),
            id: Some("family_name".to_string()),
            values: None,
        };

        let mapped: MdocClaimsQuery = query.try_into().unwrap();
        assert_eq!(mapped.namespace, "org.iso.18013.5.1");
        assert_eq!(mapped.claim_name, "family_name");
    }

    #[test]
    fn builds_openid4vp_handover_per_spec() {
        let handover = OpenID4VPHandover::new(
            "wallet.example",
            "https://verifier.example/cb",
            "nonce-123".to_string(),
        )
        .unwrap();

        let expected_client_id_hash = HashAlg::Sha256.hash(b"wallet.example").as_ref().to_vec();
        let expected_response_uri_hash = HashAlg::Sha256
            .hash(b"https://verifier.example/cb")
            .as_ref()
            .to_vec();

        assert_eq!(
            handover.client_id_hash().as_slice(),
            expected_client_id_hash.as_slice()
        );
        assert_eq!(
            handover.response_uri_hash().as_slice(),
            expected_response_uri_hash.as_slice()
        );
        assert_eq!(handover.nonce(), "nonce-123");

        let value = handover.to_cbor_value();
        match value {
            Value::Array(items) => {
                assert_eq!(items.len(), 4);
                assert_eq!(items[0], Value::Text("OpenID4VP".to_string()));
                assert_eq!(items[1], Value::Bytes(expected_client_id_hash));
                assert_eq!(items[2], Value::Bytes(expected_response_uri_hash));
                assert_eq!(items[3], Value::Text("nonce-123".to_string()));
            }
            other => panic!("unexpected handover value: {other:?}"),
        }
    }

    #[test]
    fn builds_session_transcript_structure() {
        let handover = sample_handover();
        let transcript = SessionTranscript::new(handover);

        match transcript.to_cbor_value() {
            Value::Array(items) => {
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], Value::Null);
                assert_eq!(items[1], Value::Null);
                assert!(matches!(items[2], Value::Array(_)));
                if let Value::Array(handover_items) = &items[2] {
                    assert_eq!(handover_items.len(), 4);
                    assert_eq!(handover_items[0], Value::Text("OpenID4VP".to_string()));
                }
            }
            other => panic!("unexpected session transcript value: {other:?}"),
        }
    }

    #[test]
    fn device_authentication_bytes_is_tag24_wrapped() {
        let transcript = SessionTranscript::new(sample_handover());
        let device_ns_tagged = Value::Tag(24, Box::new(Value::Bytes(vec![0xa1])));

        let bytes = build_device_authentication_bytes(
            "org.iso.18013.5.1.mDL",
            &transcript,
            device_ns_tagged,
        )
        .unwrap();

        let decoded: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert!(
            matches!(decoded, Value::Tag(24, _)),
            "DeviceAuthenticationBytes must be #6.24(bstr)"
        );

        if let Value::Tag(24, inner) = decoded {
            let inner_bytes = match *inner {
                Value::Bytes(b) => b,
                other => panic!("Tag-24 inner must be bstr, got {other:?}"),
            };
            let inner_value: Value = ciborium::de::from_reader(inner_bytes.as_slice()).unwrap();
            if let Value::Array(items) = inner_value {
                assert_eq!(items.len(), 4);
                assert_eq!(items[0], Value::Text("DeviceAuthentication".to_string()));
                assert!(
                    matches!(items[1], Value::Array(_)),
                    "second element must be SessionTranscript"
                );
                assert_eq!(items[2], Value::Text("org.iso.18013.5.1.mDL".to_string()));
                assert!(
                    matches!(items[3], Value::Tag(24, _)),
                    "fourth element must be DeviceNameSpacesBytes"
                );
            } else {
                panic!("DeviceAuthentication must be an array");
            }
        }
    }

    #[test]
    fn creates_mdoc_presentation_with_detached_signature() {
        let transcript = SessionTranscript::new(sample_handover());
        let issuer_signed = Value::Map(vec![
            (Value::Text("nameSpaces".to_string()), Value::Map(vec![])),
            (Value::Text("issuerAuth".to_string()), Value::Null),
        ]);

        let presentation = MdocPresentation::builder("org.iso.18013.5.1.mDL", transcript)
            .algorithm(iana::Algorithm::ES256)
            .add_device_claim(
                "org.iso.18013.5.1",
                "family_name",
                Value::Text("Doe".to_string()),
            )
            .add_device_claim(
                "org.iso.18013.5.1",
                "given_name",
                Value::Text("Jane".to_string()),
            )
            .issuer_signed(issuer_signed)
            .signer(|tbs| Ok(vec![0xAA; tbs.len().min(64)]))
            .build()
            .unwrap()
            .create_presentation()
            .unwrap();

        let Presentation::String(encoded) = presentation else {
            panic!("expected string presentation");
        };

        let bytes = Base64UrlUnpadded::decode_vec(&encoded).unwrap();
        let decoded: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();

        let Value::Map(top) = decoded else {
            panic!("device response must be a map");
        };
        assert_eq!(
            top.iter()
                .find(|(k, _)| *k == Value::Text("version".to_string()))
                .expect("version entry")
                .1,
            Value::Text("1.0".to_string())
        );

        assert_eq!(
            top.iter()
                .find(|(k, _)| *k == Value::Text("status".to_string()))
                .expect("status entry")
                .1,
            Value::Integer(0.into())
        );

        let documents = top
            .iter()
            .find(|(k, _)| *k == Value::Text("documents".to_string()))
            .expect("documents entry")
            .1
            .clone();
        let Value::Array(documents) = documents else {
            panic!("documents must be an array");
        };
        assert_eq!(documents.len(), 1);

        let Value::Map(document) = &documents[0] else {
            panic!("document must be a map");
        };
        assert!(document.iter().any(|(k, v)| {
            *k == Value::Text("docType".to_string())
                && *v == Value::Text("org.iso.18013.5.1.mDL".to_string())
        }));

        let issuer_signed = document
            .iter()
            .find(|(k, _)| *k == Value::Text("issuerSigned".to_string()))
            .expect("issuerSigned entry")
            .1
            .clone();
        assert!(matches!(issuer_signed, Value::Map(_)));

        let device_signed = document
            .iter()
            .find(|(k, _)| *k == Value::Text("deviceSigned".to_string()))
            .expect("deviceSigned entry")
            .1
            .clone();
        let Value::Map(device_signed) = device_signed else {
            panic!("deviceSigned must be a map");
        };
        assert!(
            device_signed
                .iter()
                .any(|(k, _)| *k == Value::Text("nameSpaces".to_string()))
        );
        let device_auth = device_signed
            .iter()
            .find(|(k, _)| *k == Value::Text("deviceAuth".to_string()))
            .expect("deviceAuth entry")
            .1
            .clone();
        let Value::Map(device_auth) = device_auth else {
            panic!("deviceAuth must be a map");
        };
        let signature_value = device_auth
            .iter()
            .find(|(k, _)| *k == Value::Text("deviceSignature".to_string()))
            .expect("deviceSignature entry")
            .1
            .clone();

        let mut signature_bytes = Vec::new();
        into_writer(&signature_value, &mut signature_bytes).unwrap();
        let sign1 = CoseSign1::from_slice(&signature_bytes).unwrap();
        assert!(matches!(
            sign1.protected.header.alg,
            Some(coset::RegisteredLabelWithPrivate::Assigned(
                iana::Algorithm::ES256
            ))
        ));

        assert!(
            sign1.payload.is_none(),
            "COSE_Sign1 payload must be nil (detached) per ISO 18013-5 §9.1.2.4"
        );
    }

    #[test]
    fn rejects_build_without_issuer_signed() {
        let transcript = SessionTranscript::new(sample_handover());
        let result = MdocPresentation::builder("org.iso.18013.5.1.mDL", transcript)
            .add_device_claim(
                "org.iso.18013.5.1",
                "family_name",
                Value::Text("Doe".to_string()),
            )
            .signer(|tbs| Ok(vec![0xAA; tbs.len().min(64)]))
            .build();
        assert!(result.is_err());
        match result.unwrap_err() {
            ProofError::MissingRequiredField(field) => {
                assert_eq!(field, "issuer_signed");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn rejects_build_without_signer() {
        let transcript = SessionTranscript::new(sample_handover());
        let issuer_signed = Value::Map(vec![
            (Value::Text("nameSpaces".to_string()), Value::Map(vec![])),
            (Value::Text("issuerAuth".to_string()), Value::Null),
        ]);
        let result = MdocPresentation::builder("org.iso.18013.5.1.mDL", transcript)
            .issuer_signed(issuer_signed)
            .build();
        assert!(result.is_err());
        match result.unwrap_err() {
            ProofError::MissingRequiredField(field) => {
                assert_eq!(field, "signer");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn rejects_empty_doc_type_in_create_presentation() {
        let transcript = SessionTranscript::new(sample_handover());
        let issuer_signed = Value::Map(vec![
            (Value::Text("nameSpaces".to_string()), Value::Map(vec![])),
            (Value::Text("issuerAuth".to_string()), Value::Null),
        ]);
        let err = MdocPresentation::builder("", transcript)
            .issuer_signed(issuer_signed)
            .signer(|tbs| Ok(vec![0xAA; tbs.len().min(64)]))
            .build()
            .unwrap()
            .create_presentation()
            .unwrap_err();
        assert!(
            matches!(err, ProofError::InvalidInput(ref input) if input.contains("doc_type")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_empty_client_id_in_handover() {
        let err = OpenID4VPHandover::new("", "https://verifier.example/cb", "nonce".to_string())
            .unwrap_err();
        assert!(
            matches!(err, MdocVpError::EmptyField { field } if field == "client_id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_empty_response_uri_in_handover() {
        let err = OpenID4VPHandover::new("wallet.example", "", "nonce".to_string()).unwrap_err();
        assert!(
            matches!(err, MdocVpError::EmptyField { field } if field == "response_uri"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_empty_nonce_in_handover() {
        let err =
            OpenID4VPHandover::new("wallet.example", "https://verifier.example/cb", "".to_string())
                .unwrap_err();
        assert!(
            matches!(err, MdocVpError::EmptyField { field } if field == "nonce"),
            "unexpected error: {err}"
        );
    }
}
