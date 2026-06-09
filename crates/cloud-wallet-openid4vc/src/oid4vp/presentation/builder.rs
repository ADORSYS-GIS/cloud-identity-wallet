use std::collections::BTreeMap;

use crate::oid4vp::authorization::{AuthorizationRequest, Presentation, VpToken};
use crate::oid4vp::dcql::{CredentialFormat, CredentialQuery};
use crate::oid4vp::presentation::vp_token::VpTokenBuilder;
use crate::oid4vp::selection::CredentialCandidate;

use super::error::PresentationBuilderError;

pub type Result<T> = std::result::Result<T, PresentationBuilderError>;

/// A credential selected for presentation with its pre-built presentation string.
///
/// This struct wraps a [`CredentialCandidate`] from the DCQL matching engine
/// and adds the format-specific presentation string that will be sent to the verifier.
///
/// The presentation string is built by format-specific code (e.g., SD-JWT presentation
/// builder) before being passed here, ensuring all cryptographic binding proofs
/// and selective disclosures are already incorporated.
#[derive(Debug, Clone)]
pub struct SelectedCredential {
    /// The credential query ID this presentation satisfies.
    pub credential_query_id: String,
    /// The wallet credential identifier (mirrors [`CredentialCandidate::credential_id`]).
    pub credential_id: String,
    /// The DCQL credential format.
    pub format: CredentialFormat,
    /// The complete presentation string (e.g., SD-JWT compact presentation with disclosures and KB-JWT).
    pub presentation: String,
}

impl SelectedCredential {
    /// Creates a new selected credential for presentation.
    pub fn new(
        credential_query_id: impl Into<String>,
        credential_id: impl Into<String>,
        format: CredentialFormat,
        presentation: impl Into<String>,
    ) -> Self {
        Self {
            credential_query_id: credential_query_id.into(),
            credential_id: credential_id.into(),
            format,
            presentation: presentation.into(),
        }
    }

    /// Creates a selected credential from a [`CredentialCandidate`] with a pre-built presentation.
    pub fn from_candidate(
        candidate: CredentialCandidate,
        format: CredentialFormat,
        presentation: impl Into<String>,
    ) -> Self {
        Self {
            credential_query_id: candidate.credential_query_id,
            credential_id: candidate.credential_id,
            format,
            presentation: presentation.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PresentationBuilder {
    nonce: String,
    client_id: String,
    credentials: Vec<SelectedCredential>,
}

impl PresentationBuilder {
    pub fn new(authorization_request: &AuthorizationRequest) -> Self {
        Self {
            nonce: authorization_request.nonce.clone(),
            client_id: authorization_request.client_id.clone(),
            credentials: Vec::new(),
        }
    }

    pub fn from_parts(nonce: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            nonce: nonce.into(),
            client_id: client_id.into(),
            credentials: Vec::new(),
        }
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn add_credential(mut self, credential: SelectedCredential) -> Self {
        self.credentials.push(credential);
        self
    }

    pub fn add_credentials(mut self, credentials: Vec<SelectedCredential>) -> Self {
        self.credentials.extend(credentials);
        self
    }

    pub fn build_vp_token(
        self,
        credential_queries: &[CredentialQuery],
    ) -> Result<VpToken> {
        if self.credentials.is_empty() {
            return Err(PresentationBuilderError::NoCredentialsSelected);
        }

        for credential in &self.credentials {
            let query = credential_queries
                .iter()
                .find(|q| q.id == credential.credential_query_id)
                .ok_or_else(|| {
                    PresentationBuilderError::QueryNotFound(credential.credential_query_id.clone())
                })?;

            let query_format = format!("{}", query.format);
            let credential_format = format!("{}", credential.format);

            if query_format != credential_format {
                return Err(PresentationBuilderError::FormatMismatch {
                    credential_format,
                    query_format,
                });
            }
        }

        let mut entries: BTreeMap<String, Vec<Presentation>> = BTreeMap::new();

        for credential in self.credentials {
            entries
                .entry(credential.credential_query_id)
                .or_default()
                .push(Presentation::String(credential.presentation));
        }

        VpToken::new(entries).map_err(PresentationBuilderError::InvalidVpToken)
    }

    pub fn build(self) -> Result<PresentationBuilderOutput> {
        if self.credentials.is_empty() {
            return Err(PresentationBuilderError::NoCredentialsSelected);
        }

        let mut entries: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for credential in self.credentials {
            entries
                .entry(credential.credential_query_id)
                .or_default()
                .push(credential.presentation);
        }

        Ok(PresentationBuilderOutput {
            entries,
            nonce: self.nonce,
            client_id: self.client_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PresentationBuilderOutput {
    pub entries: BTreeMap<String, Vec<String>>,
    pub nonce: String,
    pub client_id: String,
}

impl PresentationBuilderOutput {
    pub fn into_vp_token_builder(self) -> VpTokenBuilder {
        VpTokenBuilder::new(self.entries)
            .with_nonce(self.nonce)
            .with_client_id(self.client_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid4vp::authorization::{ResponseMode, ResponseType};
    use crate::oid4vp::dcql::{CredentialMeta, DcqlQuery};

    fn create_test_query() -> CredentialQuery {
        CredentialQuery {
            id: "test-credential".to_string(),
            format: CredentialFormat::DcSdJwt,
            multiple: None,
            meta: CredentialMeta::SdJwt {
                vct_values: vec!["https://example.com/credential".to_string()],
            },
            claims: None,
            claim_sets: None,
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
        }
    }

    fn create_test_authorization_request() -> AuthorizationRequest {
        use url::Url;

        AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: "https://verifier.example.com".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: "test-nonce-123".to_string(),
            response_mode: ResponseMode::DirectPost,
            response_uri: Some(Url::parse("https://verifier.example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: Some(DcqlQuery {
                credentials: vec![create_test_query()],
                credential_sets: None,
            }),
            client_metadata: None,
            client_metadata_uri: None,
            request: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
        }
    }

    #[test]
    fn presentation_builder_creates_output_with_nonce_and_client_id() {
        let request = create_test_authorization_request();
        let builder = PresentationBuilder::new(&request);

        assert_eq!(builder.nonce(), "test-nonce-123");
        assert_eq!(builder.client_id(), "https://verifier.example.com");
    }

    #[test]
    fn presentation_builder_from_parts() {
        let builder =
            PresentationBuilder::from_parts("custom-nonce", "https://custom-verifier.example.com");

        assert_eq!(builder.nonce(), "custom-nonce");
        assert_eq!(builder.client_id(), "https://custom-verifier.example.com");
    }

    #[test]
    fn selected_credential_stores_presentation() {
        let credential = SelectedCredential::new(
            "test-credential",
            "credential-uuid-123",
            CredentialFormat::DcSdJwt,
            "eyJhbGciOiJFUzI1NiJ9.payload.signature~",
        );

        assert_eq!(credential.credential_query_id, "test-credential");
        assert_eq!(credential.credential_id, "credential-uuid-123");
        assert_eq!(credential.presentation, "eyJhbGciOiJFUzI1NiJ9.payload.signature~");
    }

    #[test]
    fn build_vp_token_with_single_credential() {
        let request = create_test_authorization_request();
        let query = create_test_query();

        let builder = PresentationBuilder::new(&request).add_credential(SelectedCredential::new(
            "test-credential",
            "credential-uuid-123",
            CredentialFormat::DcSdJwt,
            "jwt.payload.signature~",
        ));

        let result = builder
            .build_vp_token(std::slice::from_ref(&query))
            .unwrap();

        assert!(result.entries().contains_key("test-credential"));
        assert_eq!(result.entries()["test-credential"].len(), 1);
    }

    #[test]
    fn build_vp_token_with_multiple_credentials_same_query() {
        let request = create_test_authorization_request();
        let query = create_test_query();

        let builder = PresentationBuilder::new(&request)
            .add_credential(SelectedCredential::new(
                "test-credential",
                "credential-uuid-1",
                CredentialFormat::DcSdJwt,
                "jwt1.payload.signature~",
            ))
            .add_credential(SelectedCredential::new(
                "test-credential",
                "credential-uuid-2",
                CredentialFormat::DcSdJwt,
                "jwt2.payload.signature~",
            ));

        let result = builder
            .build_vp_token(std::slice::from_ref(&query))
            .unwrap();

        assert_eq!(result.entries()["test-credential"].len(), 2);
    }

    #[test]
    fn build_vp_token_fails_on_format_mismatch() {
        let request = create_test_authorization_request();
        let query = create_test_query();

        let builder = PresentationBuilder::new(&request).add_credential(SelectedCredential::new(
            "test-credential",
            "credential-uuid-123",
            CredentialFormat::MsoMdoc,
            "mdoc-payload",
        ));

        let result = builder.build_vp_token(std::slice::from_ref(&query));

        assert!(matches!(
            result,
            Err(PresentationBuilderError::FormatMismatch { .. })
        ));
    }

    #[test]
    fn build_vp_token_fails_on_unknown_query_id() {
        let request = create_test_authorization_request();

        let builder = PresentationBuilder::new(&request).add_credential(SelectedCredential::new(
            "unknown-query-id",
            "credential-uuid-123",
            CredentialFormat::DcSdJwt,
            "jwt.payload.signature~",
        ));

        let result = builder.build_vp_token(&[]);

        assert!(matches!(
            result,
            Err(PresentationBuilderError::QueryNotFound(_))
        ));
    }

    #[test]
    fn build_output_creates_vp_token_builder() {
        let request = create_test_authorization_request();

        let output = PresentationBuilder::new(&request)
            .add_credential(SelectedCredential::new(
                "test-credential",
                "credential-uuid-123",
                CredentialFormat::DcSdJwt,
                "jwt.payload.signature~",
            ))
            .build()
            .unwrap();

        assert_eq!(output.nonce, "test-nonce-123");
        assert_eq!(output.client_id, "https://verifier.example.com");
        assert!(output.entries.contains_key("test-credential"));
    }
}
