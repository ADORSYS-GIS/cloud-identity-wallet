use std::collections::BTreeMap;

use crate::oid4vp::authorization::{Presentation, VpToken};

pub struct VpTokenBuilder {
    entries: BTreeMap<String, Vec<String>>,
}

impl Default for VpTokenBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VpTokenBuilder {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn from_entries(entries: BTreeMap<String, Vec<String>>) -> Self {
        Self { entries }
    }

    pub fn add_entry(
        mut self,
        query_id: impl Into<String>,
        presentation: impl Into<String>,
    ) -> Self {
        self.entries
            .entry(query_id.into())
            .or_default()
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
            .or_default()
            .extend(presentations);
        self
    }

    pub fn build(self) -> Result<VpToken, String> {
        let entries = self
            .entries
            .into_iter()
            .map(|(query_id, presentations)| {
                let pres: Vec<Presentation> = presentations
                    .into_iter()
                    .map(Presentation::String)
                    .collect();
                (query_id, pres)
            })
            .collect();

        VpToken::new(entries)
    }

    pub fn entries(&self) -> &BTreeMap<String, Vec<String>> {
        &self.entries
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
        let result = VpTokenBuilder::new()
            .add_entry("test-credential", "jwt1.payload.signature~")
            .build()
            .unwrap();

        assert!(result.entries().contains_key("test-credential"));
        assert_eq!(result.entries()["test-credential"].len(), 1);
    }

    #[test]
    fn vp_token_builder_from_entries() {
        let result = VpTokenBuilder::from_entries(create_test_entries())
            .build()
            .unwrap();

        assert!(result.entries().contains_key("test-credential"));
        assert_eq!(result.entries()["test-credential"].len(), 1);
    }

    #[test]
    fn vp_token_builder_add_entry() {
        let builder = VpTokenBuilder::new()
            .add_entry("credential-1", "presentation-1")
            .add_entry("credential-2", "presentation-2");

        assert!(builder.entries().contains_key("credential-1"));
        assert!(builder.entries().contains_key("credential-2"));
    }

    #[test]
    fn vp_token_builder_add_presentations() {
        let builder = VpTokenBuilder::new().add_presentations(
            "credential-1",
            vec!["presentation-1".to_string(), "presentation-2".to_string()],
        );

        assert_eq!(builder.entries()["credential-1"].len(), 2);
    }

    #[test]
    fn vp_token_builder_rejects_empty_entries() {
        let result = VpTokenBuilder::new().build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("at least one credential query entry")
        );
    }

    #[test]
    fn vp_token_builder_rejects_empty_presentations() {
        let mut entries = BTreeMap::new();
        entries.insert("test-credential".to_string(), Vec::new());

        let result = VpTokenBuilder::from_entries(entries).build();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one presentation"));
    }

    #[test]
    fn vp_token_builder_rejects_invalid_query_id() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "invalid/query/id".to_string(),
            vec!["presentation".to_string()],
        );

        let result = VpTokenBuilder::from_entries(entries).build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("valid DCQL credential query id")
        );
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

        let result = VpTokenBuilder::from_entries(entries).build().unwrap();

        assert!(result.entries().contains_key("credential-1"));
        assert!(result.entries().contains_key("credential-2"));
    }
}
