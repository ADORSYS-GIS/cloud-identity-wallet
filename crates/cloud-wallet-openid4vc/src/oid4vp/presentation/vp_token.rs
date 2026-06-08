use std::collections::BTreeMap;

use crate::oid4vp::authorization::{Presentation, VpToken};

use super::error::VpTokenBuilderError;

pub type Result<T> = std::result::Result<T, VpTokenBuilderError>;

#[derive(Debug, Clone)]
pub struct VpTokenBuilder {
    entries: BTreeMap<String, Vec<String>>,
    nonce: Option<String>,
    client_id: Option<String>,
}

impl VpTokenBuilder {
    pub fn new(entries: BTreeMap<String, Vec<String>>) -> Self {
        Self {
            entries,
            nonce: None,
            client_id: None,
        }
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn add_entry(
        mut self,
        query_id: impl Into<String>,
        presentation: impl Into<String>,
    ) -> Self {
        self.entries
            .entry(query_id.into())
            .or_insert_with(Vec::new)
            .push(presentation.into());
        self
    }

    pub fn add_presentations(
        mut self,
        query_id: impl Into<String>,
        presentations: Vec<String>,
    ) -> Self {
        self.entries
            .entry(query_id.into())
            .or_insert_with(Vec::new)
            .extend(presentations);
        self
    }

    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    pub fn entries(&self) -> &BTreeMap<String, Vec<String>> {
        &self.entries
    }

    pub fn build(self) -> Result<VpToken> {
        if self.entries.is_empty() {
            return Err(VpTokenBuilderError::EmptyEntries);
        }

        for (query_id, presentations) in &self.entries {
            if presentations.is_empty() {
                return Err(VpTokenBuilderError::EmptyPresentation {
                    query_id: query_id.clone(),
                });
            }

            if !is_valid_dcql_query_id(query_id) {
                return Err(VpTokenBuilderError::InvalidQueryId(query_id.clone()));
            }
        }

        let entries = self
            .entries
            .into_iter()
            .map(|(query_id, presentations)| {
                let pres: Vec<Presentation> = presentations
                    .into_iter()
                    .map(|s| Presentation::String(s))
                    .collect();
                (query_id, pres)
            })
            .collect();

        VpToken::new(entries).map_err(|e| VpTokenBuilderError::InvalidQueryId(e))
    }

    pub fn build_string(self) -> Result<String> {
        let vp_token = self.build()?;
        let entries = vp_token.entries();
        Ok(serde_json::to_string(entries)
            .map_err(|e| VpTokenBuilderError::InvalidQueryId(e.to_string()))?)
    }
}

fn is_valid_dcql_query_id(query_id: &str) -> bool {
    !query_id.is_empty()
        && query_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[derive(Debug, Clone)]
pub struct VpTokenResponse {
    pub vp_token: VpToken,
    pub nonce: Option<String>,
    pub client_id: Option<String>,
}

impl VpTokenResponse {
    pub fn new(vp_token: VpToken) -> Self {
        Self {
            vp_token,
            nonce: None,
            client_id: None,
        }
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn vp_token(&self) -> &VpToken {
        &self.vp_token
    }

    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entries() -> BTreeMap<String, Vec<String>> {
        let mut entries = BTreeMap::new();
        entries.insert(
            "test-credential".to_string(),
            vec!["jwt1.payload.signature~".to_string()],
        );
        entries
    }

    #[test]
    fn vp_token_builder_creates_valid_token() {
        let result = VpTokenBuilder::new(create_test_entries()).build().unwrap();

        assert!(result.entries().contains_key("test-credential"));
        assert_eq!(result.entries()["test-credential"].len(), 1);
    }

    #[test]
    fn vp_token_builder_with_nonce_and_client_id() {
        let builder = VpTokenBuilder::new(create_test_entries())
            .with_nonce("test-nonce")
            .with_client_id("https://verifier.example.com");

        assert_eq!(builder.nonce(), Some("test-nonce"));
        assert_eq!(builder.client_id(), Some("https://verifier.example.com"));
    }

    #[test]
    fn vp_token_builder_add_entry() {
        let builder = VpTokenBuilder::new(BTreeMap::new())
            .add_entry("credential-1", "presentation-1")
            .add_entry("credential-2", "presentation-2");

        assert!(builder.entries().contains_key("credential-1"));
        assert!(builder.entries().contains_key("credential-2"));
    }

    #[test]
    fn vp_token_builder_add_presentations() {
        let builder = VpTokenBuilder::new(BTreeMap::new()).add_presentations(
            "credential-1",
            vec!["presentation-1".to_string(), "presentation-2".to_string()],
        );

        assert_eq!(builder.entries()["credential-1"].len(), 2);
    }

    #[test]
    fn vp_token_builder_rejects_empty_entries() {
        let result = VpTokenBuilder::new(BTreeMap::new()).build();
        assert!(matches!(result, Err(VpTokenBuilderError::EmptyEntries)));
    }

    #[test]
    fn vp_token_builder_rejects_empty_presentations() {
        let mut entries = BTreeMap::new();
        entries.insert("test-credential".to_string(), Vec::new());

        let result = VpTokenBuilder::new(entries).build();
        assert!(matches!(
            result,
            Err(VpTokenBuilderError::EmptyPresentation { .. })
        ));
    }

    #[test]
    fn vp_token_builder_rejects_invalid_query_id() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "invalid/query/id".to_string(),
            vec!["presentation".to_string()],
        );

        let result = VpTokenBuilder::new(entries).build();
        assert!(matches!(
            result,
            Err(VpTokenBuilderError::InvalidQueryId(_))
        ));
    }

    #[test]
    fn vp_token_builder_build_string_serializes_to_json() {
        let json = VpTokenBuilder::new(create_test_entries())
            .build_string()
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
        assert!(parsed.get("test-credential").is_some());
    }

    #[test]
    fn is_valid_dcql_query_id_rejects_invalid_chars() {
        assert!(is_valid_dcql_query_id("valid_id"));
        assert!(is_valid_dcql_query_id("valid-id"));
        assert!(is_valid_dcql_query_id("valid123"));
        assert!(!is_valid_dcql_query_id("invalid/id"));
        assert!(!is_valid_dcql_query_id("invalid id"));
        assert!(!is_valid_dcql_query_id(""));
    }

    #[test]
    fn vp_token_response_builder() {
        let entries = create_test_entries();
        let builder = VpTokenBuilder::new(entries);
        let vp_token = builder.build().unwrap();

        let response = VpTokenResponse::new(vp_token)
            .with_nonce("nonce-value")
            .with_client_id("https://verifier.example.com");

        assert!(response.nonce().is_some());
        assert!(response.client_id().is_some());
    }

    #[test]
    fn multi_credential_vp_token() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "credential-1".to_string(),
            vec!["jwt1.payload.signature~".to_string()],
        );
        entries.insert(
            "credential-2".to_string(),
            vec!["jwt2.payload.signature~".to_string()],
        );

        let result = VpTokenBuilder::new(entries).build().unwrap();

        assert!(result.entries().contains_key("credential-1"));
        assert!(result.entries().contains_key("credential-2"));
    }

    #[test]
    fn nonce_embedding_verification() {
        let test_nonce = "unique-nonce-12345";
        let builder = VpTokenBuilder::new(create_test_entries()).with_nonce(test_nonce);

        assert_eq!(builder.nonce(), Some(test_nonce));

        let vp_token = builder.build().unwrap();
        assert!(vp_token.entries().contains_key("test-credential"));
    }

    #[test]
    fn audience_binding_verification() {
        let test_audience = "https://verifier.example.com";
        let builder = VpTokenBuilder::new(create_test_entries()).with_client_id(test_audience);

        assert_eq!(builder.client_id(), Some(test_audience));
    }
}
