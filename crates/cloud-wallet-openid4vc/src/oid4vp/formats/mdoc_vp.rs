use std::collections::BTreeMap;
use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use ciborium::ser::into_writer;
use ciborium::value::Value;
use coset::{AsCborValue, CoseSign1Builder, HeaderBuilder, iana};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::skip_serializing_none;
use thiserror::Error;

use crate::core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer};
use crate::oid4vp::dcql::ClaimsQuery;
use cloud_wallet_crypto::digest::HashAlg;

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
    #[error("failed to serialise CBOR value: {0}")]
    CborEncode(String),
    /// Signing failed.
    #[error("failed to sign DeviceSignature: {0}")]
    Signing(String),
}

type Result<T> = std::result::Result<T, MdocVpError>;

/// mdoc-specific interpretation of a DCQL claims query.
///
/// This normalises a claims path into the `namespace` + `claim_name` pair used
/// by ISO mdoc presentation logic.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdocClaimsQuery {
    /// ISO namespace string.
    pub namespace: String,
    /// Data element identifier.
    pub claim_name: String,
    /// Optional mdoc retention hint.
    pub intent_to_retain: Option<bool>,
}

impl MdocClaimsQuery {
    /// Creates an mdoc claims query from a generic DCQL [`ClaimsQuery`].
    pub fn try_from_claims_query(
        query: &ClaimsQuery,
        intent_to_retain: Option<bool>,
    ) -> Result<Self> {
        let (namespace, claim_name) = claim_path_to_namespace_and_element(&query.path)?;
        Ok(Self {
            namespace,
            claim_name,
            intent_to_retain,
        })
    }
}

/// Converts a DCQL claim path into the mdoc namespace/data-element pair.
pub fn claim_path_to_namespace_and_element(path: &ClaimPathPointer) -> Result<(String, String)> {
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

/// OpenID4VP mdoc handover info structure.
///
/// The spec hashes the CBOR-encoded bytes of this structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenID4VPHandoverInfo {
    pub client_id: String,
    pub nonce: String,
    pub jwk_thumbprint: Option<Vec<u8>>,
    pub response_uri: String,
}

impl OpenID4VPHandoverInfo {
    /// Serialises the handover info structure to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        into_writer(&self.to_cbor_value(), &mut buf)
            .map_err(|e| MdocVpError::CborEncode(e.to_string()))?;
        Ok(buf)
    }

    /// Returns the CBOR value for this structure.
    pub fn to_cbor_value(&self) -> Value {
        Value::Array(vec![
            Value::Text(self.client_id.clone()),
            Value::Text(self.nonce.clone()),
            match &self.jwk_thumbprint {
                Some(bytes) => Value::Bytes(bytes.clone()),
                None => Value::Null,
            },
            Value::Text(self.response_uri.clone()),
        ])
    }
}

/// OpenID4VP handover structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenID4VPHandover {
    pub info_hash: Vec<u8>,
}

impl OpenID4VPHandover {
    /// Builds the handover structure by hashing the CBOR-encoded handover info.
    pub fn from_info(info: &OpenID4VPHandoverInfo) -> Result<Self> {
        let info_bytes = info.to_cbor_bytes()?;
        let info_hash = HashAlg::Sha256.hash(info_bytes).as_ref().to_vec();
        Ok(Self { info_hash })
    }

    /// Serialises the structure to a CBOR value.
    pub fn to_cbor_value(&self) -> Value {
        Value::Array(vec![
            Value::Text("OpenID4VPHandover".to_string()),
            Value::Bytes(self.info_hash.clone()),
        ])
    }

    /// Serialises the structure to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        into_writer(&self.to_cbor_value(), &mut buf)
            .map_err(|e| MdocVpError::CborEncode(e.to_string()))?;
        Ok(buf)
    }
}

/// OpenID4VP session transcript structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTranscript {
    pub handover: OpenID4VPHandover,
}

impl SessionTranscript {
    /// Creates the redirect-based session transcript required by this issue.
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

    /// Serialises the structure to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        into_writer(&self.to_cbor_value(), &mut buf)
            .map_err(|e| MdocVpError::CborEncode(e.to_string()))?;
        Ok(buf)
    }
}

/// Builder for an mdoc `DeviceResponse`.
#[derive(Debug, Clone)]
pub struct MdocDeviceResponseBuilder {
    doc_type: String,
    namespaces: BTreeMap<String, BTreeMap<String, JsonValue>>,
    session_transcript: SessionTranscript,
    algorithm: iana::Algorithm,
}

impl MdocDeviceResponseBuilder {
    /// Creates a new builder for a single mdoc document type.
    pub fn new(doc_type: impl Into<String>, session_transcript: SessionTranscript) -> Self {
        Self {
            doc_type: doc_type.into(),
            namespaces: BTreeMap::new(),
            session_transcript,
            algorithm: iana::Algorithm::ES256,
        }
    }

    /// Sets the COSE signing algorithm used for `DeviceSignature`.
    pub fn algorithm(mut self, algorithm: iana::Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Adds one data element to the response.
    pub fn add_claim(
        mut self,
        namespace: impl Into<String>,
        claim_name: impl Into<String>,
        value: impl Into<JsonValue>,
    ) -> Self {
        self.namespaces
            .entry(namespace.into())
            .or_default()
            .insert(claim_name.into(), value.into());
        self
    }

    /// Adds a set of claims for one namespace.
    pub fn add_namespace(
        mut self,
        namespace: impl Into<String>,
        claims: BTreeMap<String, JsonValue>,
    ) -> Self {
        self.namespaces.insert(namespace.into(), claims);
        self
    }

    /// Builds the CBOR `DeviceResponse` and encodes the `DeviceSignature`.
    pub fn build<F, E>(self, signer: F) -> Result<MdocDeviceResponse>
    where
        F: FnOnce(&[u8]) -> std::result::Result<Vec<u8>, E>,
        E: fmt::Display,
    {
        if self.doc_type.trim().is_empty() {
            return Err(MdocVpError::EmptyField { field: "doc_type" });
        }
        if self.namespaces.is_empty() {
            return Err(MdocVpError::EmptyField {
                field: "namespaces",
            });
        }

        let namespace_value = json_to_cbor_value(&JsonValue::Object(
            self.namespaces
                .into_iter()
                .map(|(ns, claims)| {
                    let claims = serde_json::Map::from_iter(claims);
                    (ns, JsonValue::Object(claims))
                })
                .collect(),
        ))?;

        let device_auth_payload = Value::Array(vec![
            Value::Text("DeviceAuthentication".to_string()),
            Value::Text(self.doc_type.clone()),
            namespace_value.clone(),
        ]);
        let device_auth_payload_bytes = value_to_bytes(&device_auth_payload)?;
        let aad = self.session_transcript.to_cbor_bytes()?;

        let protected = HeaderBuilder::new().algorithm(self.algorithm).build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(device_auth_payload_bytes)
            .try_create_signature(&aad, |tbs| {
                signer(tbs).map_err(|e| MdocVpError::Signing(e.to_string()))
            })?
            .build();

        let device_response = Value::Map(vec![
            (
                Value::Text("version".to_string()),
                Value::Text("1.0".to_string()),
            ),
            (
                Value::Text("documents".to_string()),
                Value::Array(vec![Value::Map(vec![
                    (
                        Value::Text("docType".to_string()),
                        Value::Text(self.doc_type),
                    ),
                    (
                        Value::Text("deviceSigned".to_string()),
                        Value::Map(vec![
                            (Value::Text("nameSpaces".to_string()), namespace_value),
                            (
                                Value::Text("deviceAuth".to_string()),
                                Value::Map(vec![(
                                    Value::Text("deviceSignature".to_string()),
                                    sign1.to_cbor_value().map_err(|e: coset::CoseError| {
                                        MdocVpError::CborEncode(e.to_string())
                                    })?,
                                )]),
                            ),
                        ]),
                    ),
                ])]),
            ),
        ]);

        Ok(MdocDeviceResponse {
            value: device_response,
        })
    }
}

/// A CBOR `DeviceResponse` value with helper encoding methods.
#[derive(Debug, Clone, PartialEq)]
pub struct MdocDeviceResponse {
    value: Value,
}

impl MdocDeviceResponse {
    /// Returns the underlying CBOR value.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// Serialises the response to CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        value_to_bytes(&self.value)
    }

    /// Serialises the response to unpadded base64url.
    pub fn to_base64url(&self) -> Result<String> {
        let bytes = self.to_cbor_bytes()?;
        Ok(Base64UrlUnpadded::encode_string(&bytes))
    }
}

fn json_to_cbor_value(value: &JsonValue) -> Result<Value> {
    let mut buf = Vec::new();
    into_writer(value, &mut buf).map_err(|e| MdocVpError::CborEncode(e.to_string()))?;
    let decoded: Value = ciborium::de::from_reader(buf.as_slice())
        .map_err(|e| MdocVpError::CborEncode(e.to_string()))?;
    Ok(decoded)
}

fn value_to_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    into_writer(value, &mut buf).map_err(|e| MdocVpError::CborEncode(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Base64UrlUnpadded;
    use cloud_wallet_crypto::digest::HashAlg;
    use coset::{CborSerializable, CoseSign1};
    use serde_json::json;

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

        let mapped = MdocClaimsQuery::try_from_claims_query(&query, Some(true)).unwrap();
        assert_eq!(mapped.namespace, "org.iso.18013.5.1");
        assert_eq!(mapped.claim_name, "family_name");
        assert_eq!(mapped.intent_to_retain, Some(true));
    }

    #[test]
    fn builds_openid4vp_handover_from_hashed_handover_info() {
        let info = OpenID4VPHandoverInfo {
            client_id: "wallet.example".to_string(),
            nonce: "nonce-123".to_string(),
            jwk_thumbprint: None,
            response_uri: "https://verifier.example/cb".to_string(),
        };

        let handover = OpenID4VPHandover::from_info(&info).unwrap();
        let info_bytes = info.to_cbor_bytes().unwrap();
        let expected_hash = HashAlg::Sha256.hash(info_bytes);
        assert_eq!(handover.info_hash, expected_hash.as_ref());

        let value = handover.to_cbor_value();
        match value {
            Value::Array(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], Value::Text("OpenID4VPHandover".to_string()));
                assert_eq!(items[1], Value::Bytes(expected_hash.as_ref().to_vec()));
            }
            other => panic!("unexpected handover value: {other:?}"),
        }
    }

    #[test]
    fn builds_session_transcript_structure() {
        let info = OpenID4VPHandoverInfo {
            client_id: "wallet.example".to_string(),
            nonce: "nonce-123".to_string(),
            jwk_thumbprint: None,
            response_uri: "https://verifier.example/cb".to_string(),
        };
        let transcript = SessionTranscript::new(OpenID4VPHandover::from_info(&info).unwrap());

        match transcript.to_cbor_value() {
            Value::Array(items) => {
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], Value::Null);
                assert_eq!(items[1], Value::Null);
                assert!(matches!(items[2], Value::Array(_)));
            }
            other => panic!("unexpected session transcript value: {other:?}"),
        }
    }

    #[test]
    fn builds_device_response_and_encodes_as_base64url() {
        let info = OpenID4VPHandoverInfo {
            client_id: "wallet.example".to_string(),
            nonce: "nonce-123".to_string(),
            jwk_thumbprint: None,
            response_uri: "https://verifier.example/cb".to_string(),
        };
        let transcript = SessionTranscript::new(OpenID4VPHandover::from_info(&info).unwrap());

        let response = MdocDeviceResponseBuilder::new("org.iso.18013.5.1.mDL", transcript)
            .algorithm(iana::Algorithm::ES256)
            .add_claim("org.iso.18013.5.1", "family_name", json!("Doe"))
            .add_claim("org.iso.18013.5.1", "given_name", json!("Jane"))
            .build(|tbs| Ok::<Vec<u8>, std::convert::Infallible>(vec![0xAA; tbs.len().min(64)]))
            .unwrap();

        let bytes = response.to_cbor_bytes().unwrap();
        let encoded = response.to_base64url().unwrap();
        assert_eq!(encoded, Base64UrlUnpadded::encode_string(&bytes));

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

        let payload = sign1.payload.expect("embedded payload");
        let payload_value: Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
        let Value::Array(items) = payload_value else {
            panic!("device auth payload must be an array");
        };
        assert_eq!(items[0], Value::Text("DeviceAuthentication".to_string()));
    }
}
