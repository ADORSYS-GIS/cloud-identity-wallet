//! Common test utilities for integration tests.

use cloud_wallet_openid4vc::credential::{Credential, CredentialFormat, CredentialStatus};
use sqlx::AnyPool;
use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

pub fn sample_credential(tenant_id: Uuid) -> Credential {
    Credential {
        id: Uuid::new_v4(),
        tenant_id,
        issuer: "https://issuer.example".to_string(),
        subject: Some("did:example:alice".to_string()),
        credential_types: vec![
            "VerifiableCredential".to_string(),
            "EmployeeBadge".to_string(),
        ],
        format: CredentialFormat::JwtVcJson,
        external_id: Some("https://issuer.example/ext-123".to_string()),
        status: CredentialStatus::Active,
        issued_at: UtcDateTime::now(),
        valid_until: None,
        is_revoked: false,
        status_location: Some(Url::parse("https://status.example/42").unwrap()),
        status_index: Some(42),
        raw_credential: "eyJhbGciOiJFZERTQSJ9.payload.signature".to_string(),
    }
}

pub async fn insert_tenant(pool: &AnyPool, id: Uuid, name: &str) {
    #[cfg(feature = "postgres")]
    let query = "INSERT INTO tenants (id, name) VALUES ($1, $2)";
    #[cfg(not(feature = "postgres"))]
    let query = "INSERT INTO tenants (id, name) VALUES (?, ?)";
    sqlx::query(query)
        .bind(id.to_string())
        .bind(name)
        .execute(pool)
        .await
        .unwrap();
}
