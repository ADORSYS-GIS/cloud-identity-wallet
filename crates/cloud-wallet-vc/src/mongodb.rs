//! MongoDB-backed credential repository.

use async_trait::async_trait;
use mongodb::{
    Collection, IndexModel,
    bson::{Bson, doc},
};
use uuid::Uuid;

use crate::{
    credential::Credential,
    repository::{CredentialFilter, CredentialRepository, StoreError},
};

/// MongoDB-backed implementation of [`CredentialRepository`].
pub struct MongoCredentialRepository {
    collection: Collection<Credential>,
}

impl MongoCredentialRepository {
    /// Create a new repository from a MongoDB collection.
    pub fn new(collection: Collection<Credential>) -> Self {
        Self { collection }
    }

    /// Ensure indexes for performance and uniqueness.
    pub async fn ensure_indexes(&self) -> Result<(), StoreError> {
        let indexes = vec![
            IndexModel::builder()
                .keys(doc! { "id": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .unique(true)
                        .build(),
                )
                .build(),
            IndexModel::builder()
                .keys(doc! { "metadata.iss": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "metadata.sub": 1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "metadata.exp": 1 })
                .build(),
            IndexModel::builder().keys(doc! { "format": 1 }).build(),
        ];

        self.collection
            .create_indexes(indexes)
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?;

        Ok(())
    }
}

#[async_trait]
impl CredentialRepository for MongoCredentialRepository {
    async fn store(&self, credential: Credential) -> Result<(), StoreError> {
        self.collection.insert_one(&credential).await.map_err(|e| {
            if e.to_string().contains("E11000") {
                StoreError::DuplicateId(credential.id)
            } else {
                StoreError::Storage(Box::new(e))
            }
        })?;

        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Credential, StoreError> {
        let filter = doc! { "id": mongodb::bson::Binary { subtype: mongodb::bson::spec::BinarySubtype::Generic, bytes: id.into_bytes().to_vec() } };
        self.collection
            .find_one(filter)
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?
            .ok_or(StoreError::NotFound(id))
    }

    async fn find_all(&self) -> Result<Vec<Credential>, StoreError> {
        let mut cursor = self
            .collection
            .find(doc! {})
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?;

        let mut results = Vec::new();
        while cursor
            .advance()
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?
        {
            results.push(
                cursor
                    .deserialize_current()
                    .map_err(|e| StoreError::Storage(Box::new(e)))?,
            );
        }
        Ok(results)
    }

    async fn find_by_filter(
        &self,
        filter: CredentialFilter,
    ) -> Result<Vec<Credential>, StoreError> {
        let mut mongo_filter = doc! {};

        if let Some(format) = filter.format {
            mongo_filter.insert("format", format.to_string());
        }
        if let Some(iss) = filter.iss {
            mongo_filter.insert("metadata.iss", iss);
        }
        if let Some(vct) = filter.vct {
            mongo_filter.insert("metadata.vct", vct);
        }
        if let Some(doctype) = filter.doctype {
            mongo_filter.insert("metadata.doctype", doctype);
        }
        if let Some(sub) = filter.sub {
            mongo_filter.insert("metadata.sub", sub);
        }
        if let Some(not_expired_at) = filter.not_expired_at {
            // Since Chrono serializes to RFC3339 strings by default in BSON, we must filter with strings
            let dt_str = not_expired_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
            // (exp IS NULL OR exp > not_expired_at)
            mongo_filter.insert(
                "$or",
                vec![
                    doc! { "metadata.exp": Bson::Null },
                    doc! { "metadata.exp": { "$gt": dt_str } },
                ],
            );
        }

        let mut cursor = self
            .collection
            .find(mongo_filter)
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?;

        let mut results = Vec::new();
        while cursor
            .advance()
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?
        {
            results.push(
                cursor
                    .deserialize_current()
                    .map_err(|e| StoreError::Storage(Box::new(e)))?,
            );
        }
        Ok(results)
    }

    async fn update(&self, mut credential: Credential) -> Result<(), StoreError> {
        credential.updated_at = chrono::Utc::now();
        let filter = doc! { "id": mongodb::bson::Binary { subtype: mongodb::bson::spec::BinarySubtype::Generic, bytes: credential.id.into_bytes().to_vec() } };

        let result = self
            .collection
            .replace_one(filter, &credential)
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?;

        if result.matched_count == 0 {
            Err(StoreError::NotFound(credential.id))
        } else {
            Ok(())
        }
    }

    async fn delete(&self, id: Uuid) -> Result<(), StoreError> {
        let filter = doc! { "id": mongodb::bson::Binary { subtype: mongodb::bson::spec::BinarySubtype::Generic, bytes: id.into_bytes().to_vec() } };
        let result = self
            .collection
            .delete_one(filter)
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?;

        if result.deleted_count == 0 {
            Err(StoreError::NotFound(id))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CredentialFormat, CredentialMetadata};
    use chrono::Utc;
    use std::env;

    async fn setup_repo() -> Option<MongoCredentialRepository> {
        let uri = env::var("MONGODB_URI").ok()?;
        let client = mongodb::Client::with_uri_str(&uri).await.ok()?;
        let db = client.database("wallet_test_in_file");
        let collection = db.collection::<Credential>("credentials");
        let repo = MongoCredentialRepository::new(collection);
        repo.ensure_indexes().await.ok()?;
        Some(repo)
    }

    #[tokio::test]
    async fn test_mongodb_crud() {
        let Some(repo) = setup_repo().await else {
            println!("Skipping MongoDB integration test: MONGODB_URI not set");
            return;
        };

        let id = Uuid::new_v4();
        let cred = Credential {
            id,
            format: CredentialFormat::DcSdJwt,
            raw_credential: "raw".to_string(),
            metadata: CredentialMetadata {
                iss: "https://issuer.com".to_string(),
                iat: Utc::now(),
                exp: None,
                sub: None,
                vct: None,
                doctype: None,
                credential_type: None,
                credential_configuration_id: None,
                status: None,
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Store
        repo.store(cred.clone()).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(id).await.unwrap();
        assert_eq!(found.id, id);

        // Update
        let mut to_update = found;
        to_update.metadata.iss = "https://new.com".to_string();
        repo.update(to_update).await.unwrap();

        let updated = repo.find_by_id(id).await.unwrap();
        assert_eq!(updated.metadata.iss, "https://new.com");

        // Find all
        let all = repo.find_all().await.unwrap();
        assert!(all.iter().any(|c| c.id == id));

        // Delete
        repo.delete(id).await.unwrap();
        let result = repo.find_by_id(id).await;
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }
}
