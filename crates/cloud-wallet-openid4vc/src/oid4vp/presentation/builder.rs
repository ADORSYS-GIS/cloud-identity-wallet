use std::collections::BTreeMap;

use crate::oid4vp::authorization::{Presentation, VpToken};
use crate::oid4vp::dcql::CredentialQuery;

use super::error::{PresentationBuilderError, VpTokenError};

pub type Result<T> = std::result::Result<T, PresentationBuilderError>;

#[derive(Debug, Clone)]
pub struct SelectedCredential {
    pub query_id: String,
    pub presentation: Presentation,
}

impl SelectedCredential {
    pub fn new(query_id: impl Into<String>, presentation: Presentation) -> Self {
        Self {
            query_id: query_id.into(),
            presentation,
        }
    }

    pub fn string(query_id: impl Into<String>, presentation: impl Into<String>) -> Self {
        Self {
            query_id: query_id.into(),
            presentation: Presentation::String(presentation.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PresentationBuilder {
    credentials: Vec<SelectedCredential>,
}

impl Default for PresentationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PresentationBuilder {
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
        }
    }

    pub fn add_credential(mut self, credential: SelectedCredential) -> Self {
        self.credentials.push(credential);
        self
    }

    pub fn add_credentials(mut self, credentials: Vec<SelectedCredential>) -> Self {
        self.credentials.extend(credentials);
        self
    }

    pub fn build_vp_token(self, credential_queries: &[CredentialQuery]) -> Result<VpToken> {
        if self.credentials.is_empty() {
            return Err(PresentationBuilderError::NoCredentialsSelected);
        }

        for credential in &self.credentials {
            credential_queries
                .iter()
                .find(|q| q.id == credential.query_id)
                .ok_or_else(|| {
                    PresentationBuilderError::QueryNotFound(credential.query_id.clone())
                })?;
        }

        let mut entries: BTreeMap<String, Vec<Presentation>> = BTreeMap::new();

        for credential in self.credentials {
            entries
                .entry(credential.query_id)
                .or_default()
                .push(credential.presentation);
        }

        for (query_id, presentations) in &entries {
            let query = credential_queries
                .iter()
                .find(|q| &q.id == query_id)
                .expect("query already validated");
            let allows_multiple = query.multiple.unwrap_or(false);
            if !allows_multiple && presentations.len() > 1 {
                return Err(PresentationBuilderError::VpToken(
                    VpTokenError::MultiplePresentationsNotAllowed {
                        query_id: query_id.clone(),
                    },
                ));
            }
        }

        VpToken::new(entries).map_err(|e| {
            if e.contains("at least one credential query entry") {
                VpTokenError::Empty.into()
            } else if e.contains("valid DCQL credential query id") {
                VpTokenError::InvalidQueryId {
                    query_id: extract_query_id(&e),
                }
                .into()
            } else if e.contains("at least one presentation") {
                VpTokenError::EmptyPresentationList {
                    query_id: extract_query_id(&e),
                }
                .into()
            } else {
                VpTokenError::Empty.into()
            }
        })
    }
}

fn extract_query_id(error_message: &str) -> String {
    let start = error_message.find('\'').unwrap_or(0);
    let end = error_message.rfind('\'').unwrap_or(error_message.len());
    if start < end {
        error_message[start + 1..end].to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid4vp::dcql::{CredentialFormat, CredentialMeta};

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

    fn create_test_query_with_multiple() -> CredentialQuery {
        CredentialQuery {
            id: "test-credential".to_string(),
            format: CredentialFormat::DcSdJwt,
            multiple: Some(true),
            meta: CredentialMeta::SdJwt {
                vct_values: vec!["https://example.com/credential".to_string()],
            },
            claims: None,
            claim_sets: None,
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
        }
    }

    #[test]
    fn selected_credential_new() {
        let credential = SelectedCredential::new(
            "test-credential",
            Presentation::String("jwt.payload.signature~".to_string()),
        );

        assert_eq!(credential.query_id, "test-credential");
        assert_eq!(
            credential.presentation,
            Presentation::String("jwt.payload.signature~".to_string())
        );
    }

    #[test]
    fn selected_credential_string_convenience() {
        let credential = SelectedCredential::string("test-credential", "jwt.payload.signature~");

        assert_eq!(credential.query_id, "test-credential");
        assert_eq!(
            credential.presentation,
            Presentation::String("jwt.payload.signature~".to_string())
        );
    }

    #[test]
    fn build_vp_token_with_single_credential() {
        let query = create_test_query();

        let builder = PresentationBuilder::new().add_credential(SelectedCredential::string(
            "test-credential",
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
        let query = create_test_query_with_multiple();

        let builder = PresentationBuilder::new()
            .add_credential(SelectedCredential::string(
                "test-credential",
                "jwt1.payload.signature~",
            ))
            .add_credential(SelectedCredential::string(
                "test-credential",
                "jwt2.payload.signature~",
            ));

        let result = builder
            .build_vp_token(std::slice::from_ref(&query))
            .unwrap();

        assert_eq!(result.entries()["test-credential"].len(), 2);
    }

    #[test]
    fn build_vp_token_fails_on_multiple_credentials_without_multiple_flag() {
        let query = create_test_query();

        let builder = PresentationBuilder::new()
            .add_credential(SelectedCredential::string(
                "test-credential",
                "jwt1.payload.signature~",
            ))
            .add_credential(SelectedCredential::string(
                "test-credential",
                "jwt2.payload.signature~",
            ));

        let result = builder.build_vp_token(std::slice::from_ref(&query));

        assert!(matches!(
            result,
            Err(PresentationBuilderError::VpToken(VpTokenError::MultiplePresentationsNotAllowed { query_id }))
            if query_id == "test-credential"
        ));
    }

    #[test]
    fn build_vp_token_fails_on_unknown_query_id() {
        let builder = PresentationBuilder::new().add_credential(SelectedCredential::string(
            "unknown-query-id",
            "jwt.payload.signature",
        ));

        let result = builder.build_vp_token(&[]);

        assert!(matches!(
            result,
            Err(PresentationBuilderError::QueryNotFound(_))
        ));
    }

    #[test]
    fn build_vp_token_fails_on_empty_credentials() {
        let builder = PresentationBuilder::new();

        let result = builder.build_vp_token(&[]);

        assert!(matches!(
            result,
            Err(PresentationBuilderError::NoCredentialsSelected)
        ));
    }

    #[test]
    fn build_vp_token_with_object_presentation() {
        let query = create_test_query();

        let mut presentation = serde_json::Map::new();
        presentation.insert("format".to_string(), serde_json::json!("ldp_vp"));

        let builder = PresentationBuilder::new().add_credential(SelectedCredential::new(
            "test-credential",
            Presentation::Object(presentation.clone()),
        ));

        let result = builder
            .build_vp_token(std::slice::from_ref(&query))
            .unwrap();

        assert!(result.entries().contains_key("test-credential"));
        assert_eq!(result.entries()["test-credential"].len(), 1);
    }
}
