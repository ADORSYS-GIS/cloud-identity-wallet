//! Storage backend compatibility tests to ensure all backends behave consistently.

pub mod utils;

use cloud_identity_wallet::{
    domain::{
        models::credential::{
            CredentialDisplayMetadata, CredentialError, CredentialFilter, CredentialStatus,
        },
        ports::CredentialRepo,
    },
    outbound::{MemoryCredentialRepo, SqlCredentialRepo},
};
use cloud_wallet_openid4vc::issuance::credential_configuration::CredentialDisplay;
use sqlx::any::AnyPoolOptions;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

fn sample_display_metadata(name: &str, credential_type: &str) -> CredentialDisplayMetadata {
    CredentialDisplayMetadata {
        display: CredentialDisplay {
            name: name.to_string(),
            description: Some("Official credential display metadata".to_string()),
            locale: Some("en-US".to_string()),
            ..Default::default()
        },
        issuer_name: "Example Issuer".to_string(),
        credential_type: credential_type.to_string(),
    }
}

/// Generic CRUD suite that all repository backends must pass.
async fn test_repository_backend<R: CredentialRepo>(
    repository: &R,
    tenant_a: Uuid,
    tenant_b: Uuid,
) {
    let credential_a = utils::sample_credential(tenant_a);
    let mut credential_b = utils::sample_credential(tenant_b);
    credential_b.subject = Some("did:example:bob".to_string());
    credential_b.external_id = Some("https://issuer.example/ext-456".to_string());

    // Inserts credentials
    let inserted_id = repository
        .upsert(
            credential_a.clone(),
            Some(sample_display_metadata(
                "Credential A",
                &credential_a.credential_types[0],
            )),
        )
        .await
        .unwrap();
    assert_eq!(inserted_id, credential_a.id);
    repository
        .upsert(
            credential_b.clone(),
            Some(sample_display_metadata(
                "Credential B",
                &credential_b.credential_types[0],
            )),
        )
        .await
        .unwrap();

    // Finds credential for tenant A
    let found = repository
        .find_by_id(credential_a.id, credential_a.tenant_id)
        .await
        .unwrap();
    assert_eq!(found.id, credential_a.id);
    assert_eq!(found.raw_credential, credential_a.raw_credential);
    assert_eq!(found.credential_types, credential_a.credential_types);

    // Lists credential summaries for tenant A
    let listed = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_a),
            credential_types: Some(credential_a.credential_types.clone()),
            format: Some(credential_a.format),
            issuer: Some(credential_a.issuer.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    // Should find only credential A
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, credential_a.id);

    // Lists credential summaries with reversed types — containment is order-independent
    let mut reversed_types = credential_a.credential_types.clone();
    reversed_types.reverse();
    let order_independent = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_a),
            credential_types: Some(reversed_types),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        order_independent.len(),
        1,
        "reversed type order must still match"
    );
    assert_eq!(order_independent[0].id, credential_a.id);

    // Lists credential summaries by a type subset — a credential with extra types must also match
    let subset_types = credential_a.credential_types[..1].to_vec();
    let superset_match = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_a),
            credential_types: Some(subset_types),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        superset_match.len(),
        1,
        "subset filter must match a credential that has extra types"
    );
    assert_eq!(superset_match[0].id, credential_a.id);

    // Updates credential
    let mut updated = found.clone();
    updated.status = CredentialStatus::Revoked;
    updated.is_revoked = true;
    updated.raw_credential = "updated.payload.value".to_string();
    repository.upsert(updated.clone(), None).await.unwrap();

    // Reloads credential to verify update
    let reloaded = repository
        .find_by_id(updated.id, updated.tenant_id)
        .await
        .unwrap();
    assert_eq!(reloaded.status, CredentialStatus::Revoked);
    assert!(reloaded.is_revoked);
    assert_eq!(reloaded.raw_credential, "updated.payload.value");

    repository
        .delete(credential_a.id, credential_a.tenant_id)
        .await
        .unwrap();
    // Verifies credential is deleted
    assert!(matches!(
        repository
            .find_by_id(credential_a.id, credential_a.tenant_id)
            .await,
        Err(CredentialError::NotFound { .. })
    ));

    // Verifies tenant B still has its credential
    let tenant_b_records = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_b),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(tenant_b_records.len(), 1);
    assert_eq!(tenant_b_records[0].id, credential_b.id);
}

/// Display metadata and list test suite.
async fn test_display_metadata<R: CredentialRepo>(repository: &R, tenant_a: Uuid, tenant_b: Uuid) {
    let credential_a = utils::sample_credential(tenant_a);
    let credential_b = utils::sample_credential(tenant_b);

    // Build display metadata for credential_a
    let display = CredentialDisplayMetadata {
        display: CredentialDisplay {
            name: "EU Personal ID".to_string(),
            description: Some("Official EU personal identity document".to_string()),
            locale: Some("en-US".to_string()),
            ..Default::default()
        },
        issuer_name: "Example EU Authority".to_string(),
        credential_type: "eu.europa.ec.eudi.pid.1".to_string(),
    };

    // Insert credential_a with display metadata (atomic)
    repository
        .upsert(credential_a.clone(), Some(display.clone()))
        .await
        .unwrap();
    // Insert credential_b without display metadata
    repository.upsert(credential_b.clone(), None).await.unwrap();

    // list should return credential_a with display metadata
    let summaries = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_a),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, credential_a.id);
    assert_eq!(summaries[0].display.display.name, "EU Personal ID");
    assert_eq!(summaries[0].display.issuer_name, "Example EU Authority");
    assert_eq!(
        summaries[0].display.credential_type,
        "eu.europa.ec.eudi.pid.1"
    );
    let serialized_summary = serde_json::to_value(&summaries[0]).unwrap();
    let expected_issued_at = summaries[0].issued_at.format(&Rfc3339).unwrap();
    assert_eq!(
        serialized_summary["issued_at"].as_str(),
        Some(expected_issued_at.as_str())
    );

    // Upserting the same credential with new display metadata should update the
    // metadata row instead of failing on the credential_id primary key.
    let updated_display = CredentialDisplayMetadata {
        display: CredentialDisplay {
            name: "Updated EU Personal ID".to_string(),
            description: Some("Updated credential display metadata".to_string()),
            locale: Some("fr-FR".to_string()),
            ..Default::default()
        },
        issuer_name: "Updated EU Authority".to_string(),
        credential_type: "eu.europa.ec.eudi.pid.updated".to_string(),
    };
    repository
        .upsert(credential_a.clone(), Some(updated_display))
        .await
        .unwrap();
    let updated_summaries = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_a),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(updated_summaries.len(), 1);
    assert_eq!(updated_summaries[0].id, credential_a.id);
    assert_eq!(
        updated_summaries[0].display.display.name,
        "Updated EU Personal ID"
    );
    assert_eq!(
        updated_summaries[0].display.issuer_name,
        "Updated EU Authority"
    );
    assert_eq!(
        updated_summaries[0].display.credential_type,
        "eu.europa.ec.eudi.pid.updated"
    );

    // list for tenant_b (no display metadata) should return empty
    // (INNER JOIN semantics: only credentials with display metadata)
    let summaries_b = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_b),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        summaries_b.is_empty(),
        "credentials without display metadata should not appear in summaries"
    );

    // Deleting credential_a should cascade-delete its display metadata
    repository.delete(credential_a.id, tenant_a).await.unwrap();
    let summaries_after = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_a),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(summaries_after.is_empty());

    // Clean up
    repository.delete(credential_b.id, tenant_b).await.unwrap();
}

#[tokio::test]
async fn test_inmemory_storage_backend() {
    let repository = MemoryCredentialRepo::new();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    test_repository_backend(&repository, tenant_a, tenant_b).await;

    let tenant_c = Uuid::new_v4();
    let tenant_d = Uuid::new_v4();
    test_display_metadata(&repository, tenant_c, tenant_d).await;
}

#[tokio::test]
async fn test_sqlite_storage_backend() {
    sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    let repository = SqlCredentialRepo::new(pool.clone());
    repository.init_schema().await.unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_a, "Tenant A").await;
    utils::insert_tenant(&pool, tenant_b, "Tenant B").await;

    test_repository_backend(&repository, tenant_a, tenant_b).await;

    let tenant_c = Uuid::new_v4();
    let tenant_d = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_c, "Tenant C").await;
    utils::insert_tenant(&pool, tenant_d, "Tenant D").await;
    test_display_metadata(&repository, tenant_c, tenant_d).await;
}

#[tokio::test]
async fn test_postgres_storage_backend() {
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

    let container = Postgres::default()
        .with_tag("18-alpine")
        .start()
        .await
        .expect("Failed to start Postgres container");

    let connection_string = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        container.get_host().await.unwrap(),
        container.get_host_port_ipv4(5432).await.unwrap()
    );

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await
        .expect("Failed to connect to PostgreSQL");

    let repository = SqlCredentialRepo::new(pool.clone());
    repository.init_schema().await.unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_a, "Tenant A").await;
    utils::insert_tenant(&pool, tenant_b, "Tenant B").await;

    test_repository_backend(&repository, tenant_a, tenant_b).await;

    let tenant_c = Uuid::new_v4();
    let tenant_d = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_c, "Tenant C").await;
    utils::insert_tenant(&pool, tenant_d, "Tenant D").await;
    test_display_metadata(&repository, tenant_c, tenant_d).await;
}

#[tokio::test]
async fn test_mysql_storage_backend() {
    use testcontainers_modules::mysql::Mysql;
    use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

    let container = Mysql::default()
        .with_tag("9-oracle")
        .start()
        .await
        .expect("Failed to start MySQL container");

    let connection_string = format!(
        "mysql://{}:{}/test",
        container.get_host().await.unwrap(),
        container.get_host_port_ipv4(3306).await.unwrap()
    );

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await
        .expect("Failed to connect to MySQL");

    let repository = SqlCredentialRepo::new(pool.clone());
    repository.init_schema().await.unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_a, "Tenant A").await;
    utils::insert_tenant(&pool, tenant_b, "Tenant B").await;

    test_repository_backend(&repository, tenant_a, tenant_b).await;

    let tenant_c = Uuid::new_v4();
    let tenant_d = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_c, "Tenant C").await;
    utils::insert_tenant(&pool, tenant_d, "Tenant D").await;
    test_display_metadata(&repository, tenant_c, tenant_d).await;
}
