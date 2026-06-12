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

/// OpenID4VP handover structure per Appendix B.2.6.
///
/// CDDL: `OID4VPHandover = [ "OpenID4VP", clientIdHash: bstr, responseUriHash: bstr, nonce: tstr ]`
///
/// `clientIdHash`  = SHA-256(clientId)
/// `responseUriHash` = SHA-256(responseUri)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenID4VPHandover {
    pub client_id_hash: Vec<u8>,
    pub response_uri_hash: Vec<u8>,
    pub nonce: String,
}

impl OpenID4VPHandover {
    /// Creates the handover from the verifier request parameters,
    /// hashing `client_id` and `response_uri` with SHA-256.
    pub fn new(client_id: &str, response_uri: &str, nonce: String) -> Self {
        let client_id_hash = HashAlg::Sha256
            .hash(client_id.as_bytes())
            .as_ref()
            .to_vec();
        let response_uri_hash = HashAlg::Sha256
            .hash(response_uri.as_bytes())
            .as_ref()
            .to_vec();
        Self {
            client_id_hash,
            response_uri_hash,
            nonce,
        }
    }

    /// Serialises the structure to a CBOR value.
    ///
    /// Produces `["OpenID4VP", clientIdHash, responseUriHash, nonce]`.
    pub fn to_cbor_value(&self) -> Value {
        Value::Array(vec![
            Value::Text("OpenID4VP".to_string()),
            Value::Bytes(self.client_id_hash.clone()),
            Value::Bytes(self.response_uri_hash.clone()),
            Value::Text(self.nonce.clone()),
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

/// Builder for an mdoc `DeviceResponse`.

/// Builder for an mdoc `DeviceResponse`.
///
/// Per ISO 18013-5 and OpenID4VP Appendix B.2, the `DeviceResponse` must
/// include both `deviceSigned` and `issuerSigned`.
#[derive(Debug, Clone)]
pub struct MdocDeviceResponseBuilder {
    doc_type: String,
    device_namespaces: BTreeMap<String, BTreeMap<String, JsonValue>>,
    session_transcript: SessionTranscript,
    algorithm: iana::Algorithm,
    issuer_signed: Option<Value>,
}

impl MdocDeviceResponseBuilder {
    /// Creates a new builder for a single mdoc document type.
    pub fn new(doc_type: impl Into<String>, session_transcript: SessionTranscript) -> Self {
        Self {
            doc_type: doc_type.into(),
            device_namespaces: BTreeMap::new(),
            session_transcript,
            algorithm: iana::Algorithm::ES256,
            issuer_signed: None,
        }
    }

    /// Sets the COSE signing algorithm used for `DeviceSignature`.
    pub fn algorithm(mut self, algorithm: iana::Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Adds one device-asserted data element to the response.
    ///
    /// These populate `deviceSigned.nameSpaces`. For most mdoc presentations
    /// this is empty or minimal; the credential data comes from
    /// [`MdocDeviceResponseBuilder::issuer_signed`].
    pub fn add_claim(
        mut self,
        namespace: impl Into<String>,
        claim_name: impl Into<String>,
        value: impl Into<JsonValue>,
    ) -> Self {
        self.device_namespaces
            .entry(namespace.into())
            .or_default()
            .insert(claim_name.into(), value.into());
        self
    }

    /// Adds a set of device-asserted claims for one namespace.
    pub fn add_namespace(
        mut self,
        namespace: impl Into<String>,
        claims: BTreeMap<String, JsonValue>,
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

    /// Builds the CBOR `DeviceResponse` and encodes the `DeviceSignature`.
    ///
    /// Per ISO 18013-5 §9.1.2.4, the `DeviceAuthentication` payload is:
    /// ```cddl
    /// DeviceAuthentication = [
    ///     "DeviceAuthentication",
    ///     SessionTranscript,
    ///     DocType,
    ///     DeviceNameSpacesBytes   ; #6.24(bstr .cbor DeviceNameSpaces)
    /// ]
    /// ```
    ///
    /// The COSE_Sign1 `external_aad` is the empty byte string `h''`.
    pub fn build<F, E>(self, signer: F) -> Result<MdocDeviceResponse>
    where
        F: FnOnce(&[u8]) -> std::result::Result<Vec<u8>, E>,
        E: fmt::Display,
    {
        if self.doc_type.trim().is_empty() {
            return Err(MdocVpError::EmptyField { field: "doc_type" });
        }
        let issuer_signed = self.issuer_signed.ok_or_else(|| MdocVpError::EmptyField {
            field: "issuer_signed",
        })?;

        let device_ns_value = json_to_cbor_value(&JsonValue::Object(
            self.device_namespaces
                .into_iter()
                .map(|(ns, claims)| {
                    let claims = serde_json::Map::from_iter(claims);
                    (ns, JsonValue::Object(claims))
                })
                .collect(),
        ))?;

        let device_ns_bytes = value_to_bytes(&device_ns_value)?;
        let device_ns_tagged = Value::Tag(24, Box::new(Value::Bytes(device_ns_bytes.clone())));

        let device_auth_payload = Value::Array(vec![
            Value::Text("DeviceAuthentication".to_string()),
            self.session_transcript.to_cbor_value(),
            Value::Text(self.doc_type.clone()),
            device_ns_tagged,
        ]);
        let device_auth_payload_bytes = value_to_bytes(&device_auth_payload)?;

        let protected = HeaderBuilder::new().algorithm(self.algorithm).build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(device_auth_payload_bytes)
            .try_create_signature(&[], |tbs| {
                signer(tbs).map_err(|e| MdocVpError::Signing(e.to_string()))
            })?
            .build();

        let mut document_entries = vec![
            (
                Value::Text("docType".to_string()),
                Value::Text(self.doc_type),
            ),
        ];

        document_entries.push((
            Value::Text("issuerSigned".to_string()),
            issuer_signed,
        ));

        let device_ns_bytes_for_signed = Value::Tag(24, Box::new(Value::Bytes(device_ns_bytes)));

        let device_signed = Value::Map(vec![
            (Value::Text("nameSpaces".to_string()), device_ns_bytes_for_signed),
            (
                Value::Text("deviceAuth".to_string()),
                Value::Map(vec![(
                    Value::Text("deviceSignature".to_string()),
                    sign1.to_cbor_value().map_err(|e: coset::CoseError| {
                        MdocVpError::CborEncode(e.to_string())
                    })?,
                )]),
            ),
        ]);
        document_entries.push((
            Value::Text("deviceSigned".to_string()),
            device_signed,
        ));

        let device_response = Value::Map(vec![
            (
                Value::Text("version".to_string()),
                Value::Text("1.0".to_string()),
            ),
            (
                Value::Text("documents".to_string()),
                Value::Array(vec![Value::Map(document_entries)]),
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
    use coset::{CborSerializable, CoseSign1};
    use serde_json::json;

    fn sample_handover() -> OpenID4VPHandover {
        OpenID4VPHandover::new(
            "wallet.example",
            "https://verifier.example/cb",
            "nonce-123".to_string(),
        )
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

        let mapped = MdocClaimsQuery::try_from_claims_query(&query, Some(true)).unwrap();
        assert_eq!(mapped.namespace, "org.iso.18013.5.1");
        assert_eq!(mapped.claim_name, "family_name");
        assert_eq!(mapped.intent_to_retain, Some(true));
    }

    #[test]
    fn builds_openid4vp_handover_per_spec() {
        let handover = OpenID4VPHandover::new(
            "wallet.example",
            "https://verifier.example/cb",
            "nonce-123".to_string(),
        );

        let expected_client_id_hash =
            HashAlg::Sha256.hash(b"wallet.example").as_ref().to_vec();
        let expected_response_uri_hash = HashAlg::Sha256
            .hash(b"https://verifier.example/cb")
            .as_ref()
            .to_vec();

        assert_eq!(handover.client_id_hash, expected_client_id_hash);
        assert_eq!(handover.response_uri_hash, expected_response_uri_hash);
        assert_eq!(handover.nonce, "nonce-123");

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
    fn builds_device_response_and_encodes_as_base64url() {
        let transcript = SessionTranscript::new(sample_handover());

        let issuer_signed = Value::Map(vec![
            (Value::Text("nameSpaces".to_string()), Value::Map(vec![])),
            (
                Value::Text("issuerAuth".to_string()),
                Value::Null,
            ),
        ]);

        let response = MdocDeviceResponseBuilder::new("org.iso.18013.5.1.mDL", transcript)
            .algorithm(iana::Algorithm::ES256)
            .add_claim("org.iso.18013.5.1", "family_name", json!("Doe"))
            .add_claim("org.iso.18013.5.1", "given_name", json!("Jane"))
            .issuer_signed(issuer_signed)
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

        let payload = sign1.payload.expect("embedded payload");
        let payload_value: Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
        let Value::Array(items) = payload_value else {
            panic!("device auth payload must be an array");
        };
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], Value::Text("DeviceAuthentication".to_string()));
        assert!(matches!(items[1], Value::Array(_)));
        assert_eq!(items[2], Value::Text("org.iso.18013.5.1.mDL".to_string()));
        assert!(matches!(items[3], Value::Tag(24, _)));
    }

    #[test]
    fn rejects_build_without_issuer_signed() {
        let transcript = SessionTranscript::new(sample_handover());
        let result = MdocDeviceResponseBuilder::new("org.iso.18013.5.1.mDL", transcript)
            .add_claim("org.iso.18013.5.1", "family_name", json!("Doe"))
            .build(|tbs| Ok::<Vec<u8>, std::convert::Infallible>(vec![0xAA; tbs.len().min(64)]));
        assert!(result.is_err());
        match result.unwrap_err() {
            MdocVpError::EmptyField { field } => assert_eq!(field, "issuer_signed"),
            other => panic!("unexpected error: {other}"),
        }
    }
}