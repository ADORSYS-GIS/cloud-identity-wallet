use std::collections::BTreeMap;

use crate::oid4vp::authorization::AuthorizationRequest;
use crate::oid4vp::dcql::{CredentialFormat, CredentialQuery};
use crate::oid4vp::presentation::vp_token::VpTokenBuilder;

use super::error::PresentationBuilderError;
use super::holder_binding::{HolderBinding, KeyBindingInput};

pub type Result<T> = std::result::Result<T, PresentationBuilderError>;

#[derive(Debug, Clone)]
pub struct SelectedCredential {
    pub query_id: String,
    pub credential_id: uuid::Uuid,
    pub format: CredentialFormat,
    pub raw_credential: String,
    pub disclosures: Vec<String>,
    pub holder_binding: Option<HolderBinding>,
}

impl SelectedCredential {
    pub fn new(
        query_id: impl Into<String>,
        credential_id: uuid::Uuid,
        format: CredentialFormat,
        raw_credential: impl Into<String>,
    ) -> Self {
        Self {
            query_id: query_id.into(),
            credential_id,
            format,
            raw_credential: raw_credential.into(),
            disclosures: Vec::new(),
            holder_binding: None,
        }
    }

    pub fn with_disclosures(mut self, disclosures: Vec<String>) -> Self {
        self.disclosures = disclosures;
        self
    }

    pub fn with_holder_binding(mut self, binding: HolderBinding) -> Self {
        self.holder_binding = Some(binding);
        self
    }

    pub fn to_presentation_string(&self) -> String {
        match &self.holder_binding {
            Some(HolderBinding::SdJwt(kb)) => {
                let parts: Vec<&str> = std::iter::once(self.raw_credential.as_str())
                    .chain(self.disclosures.iter().map(|s| s.as_str()))
                    .collect();
                let base = parts.join("~");
                format!("{}~{}", base, kb.key_binding_jwt)
            }
            Some(HolderBinding::Mdoc(_)) => self.raw_credential.clone(),
            None => {
                let parts: Vec<&str> = std::iter::once(self.raw_credential.as_str())
                    .chain(self.disclosures.iter().map(|s| s.as_str()))
                    .collect();
                let base = parts.join("~");
                if self.disclosures.is_empty() {
                    format!("{}~", base)
                } else {
                    base
                }
            }
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

    pub fn key_binding_input(&self, sd_hash: impl Into<String>) -> KeyBindingInput {
        KeyBindingInput::new(&self.nonce, &self.client_id, sd_hash)
    }

    pub fn build_vp_token(
        self,
        credential_queries: &[CredentialQuery],
    ) -> Result<BTreeMap<String, Vec<String>>> {
        if self.credentials.is_empty() {
            return Err(PresentationBuilderError::NoCredentialsSelected);
        }

        for credential in &self.credentials {
            let query = credential_queries
                .iter()
                .find(|q| q.id == credential.query_id)
                .ok_or_else(|| {
                    PresentationBuilderError::QueryNotFound(credential.query_id.clone())
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

        let mut entries: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for credential in self.credentials {
            let presentation = credential.to_presentation_string();
            entries
                .entry(credential.query_id)
                .or_default()
                .push(presentation);
        }

        Ok(entries)
    }

    pub fn build(self) -> Result<PresentationBuilderOutput> {
        if self.credentials.is_empty() {
            return Err(PresentationBuilderError::NoCredentialsSelected);
        }

let mut entries: BTreeMap<String, Vec<String>> = BTreeMap::new();
        
        for credential in self.credentials {
            let presentation = credential.to_presentation_string();
            entries
                .entry(credential.query_id)
                .or_default()
                .push(presentation);
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
    use crate::oid4vp::presentation::SdJwtHolderBinding;

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
    fn selected_credential_converts_to_presentation_string_without_binding() {
        let credential = SelectedCredential::new(
            "test-credential",
            uuid::Uuid::nil(),
            CredentialFormat::DcSdJwt,
            "eyJhbGciOiJFUzI1NiJ9.payload.signature",
        );

        let presentation = credential.to_presentation_string();
        assert_eq!(presentation, "eyJhbGciOiJFUzI1NiJ9.payload.signature~");
    }

    #[test]
    fn selected_credential_converts_to_presentation_string_with_disclosures() {
        let credential = SelectedCredential::new(
            "test-credential",
            uuid::Uuid::nil(),
            CredentialFormat::DcSdJwt,
            "eyJhbGciOiJFUzI1NiJ9.payload.signature",
        )
        .with_disclosures(vec!["disclosure1".to_string(), "disclosure2".to_string()]);

        let presentation = credential.to_presentation_string();
        assert_eq!(
            presentation,
            "eyJhbGciOiJFUzI1NiJ9.payload.signature~disclosure1~disclosure2"
        );
    }

    #[test]
    fn selected_credential_converts_to_presentation_string_with_key_binding() {
        let credential = SelectedCredential::new(
            "test-credential",
            uuid::Uuid::nil(),
            CredentialFormat::DcSdJwt,
            "eyJhbGciOiJFUzI1NiJ9.payload.signature",
        )
        .with_disclosures(vec!["disclosure1".to_string()])
        .with_holder_binding(HolderBinding::SdJwt(SdJwtHolderBinding::new(
            "key.binding.jwt",
        )));

        let presentation = credential.to_presentation_string();
        assert_eq!(
            presentation,
            "eyJhbGciOiJFUzI1NiJ9.payload.signature~disclosure1~key.binding.jwt"
        );
    }

    #[test]
    fn build_vp_token_with_single_credential() {
        let request = create_test_authorization_request();
        let query = create_test_query();

        let builder = PresentationBuilder::new(&request).add_credential(SelectedCredential::new(
            "test-credential",
            uuid::Uuid::nil(),
            CredentialFormat::DcSdJwt,
            "jwt.payload.signature",
        ));

        let result = builder.build_vp_token(std::slice::from_ref(&query)).unwrap();

        assert!(result.contains_key("test-credential"));
        assert_eq!(result["test-credential"].len(), 1);
    }

    #[test]
    fn build_vp_token_with_multiple_credentials_same_query() {
        let request = create_test_authorization_request();
        let query = create_test_query();

        let builder = PresentationBuilder::new(&request)
            .add_credential(SelectedCredential::new(
                "test-credential",
                uuid::Uuid::nil(),
                CredentialFormat::DcSdJwt,
                "jwt1.payload.signature",
            ))
            .add_credential(SelectedCredential::new(
                "test-credential",
                uuid::Uuid::nil(),
                CredentialFormat::DcSdJwt,
                "jwt2.payload.signature",
            ));

        let result = builder.build_vp_token(std::slice::from_ref(&query)).unwrap();

        assert_eq!(result["test-credential"].len(), 2);
    }

    #[test]
    fn build_vp_token_fails_on_format_mismatch() {
        let request = create_test_authorization_request();
        let query = create_test_query();

        let builder = PresentationBuilder::new(&request).add_credential(SelectedCredential::new(
            "test-credential",
            uuid::Uuid::nil(),
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
            uuid::Uuid::nil(),
            CredentialFormat::DcSdJwt,
            "jwt.payload.signature",
        ));

        let result = builder.build_vp_token(&[]);

        assert!(matches!(
            result,
            Err(PresentationBuilderError::QueryNotFound(_))
        ));
    }

    #[test]
    fn key_binding_input_includes_nonce_and_audience() {
        let input =
            KeyBindingInput::new("test-nonce", "https://verifier.example.com", "hash-value");

        assert_eq!(input.nonce, "test-nonce");
        assert_eq!(input.audience, "https://verifier.example.com");
        assert_eq!(input.sd_hash, "hash-value");
    }

    #[test]
    fn build_output_creates_vp_token_builder() {
        let request = create_test_authorization_request();

        let output = PresentationBuilder::new(&request)
            .add_credential(SelectedCredential::new(
                "test-credential",
                uuid::Uuid::nil(),
                CredentialFormat::DcSdJwt,
                "jwt.payload.signature",
            ))
            .build()
            .unwrap();

        assert_eq!(output.nonce, "test-nonce-123");
        assert_eq!(output.client_id, "https://verifier.example.com");
        assert!(output.entries.contains_key("test-credential"));
    }
}
