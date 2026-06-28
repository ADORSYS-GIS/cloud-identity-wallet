#![cfg(all(feature = "sqlite", feature = "local-kms"))]

mod utils;

use cloud_identity_wallet::domain::models::credential::{
    CredentialDisplayMetadata, CredentialFormat, CredentialStatus,
};
use cloud_identity_wallet::domain::models::tenants::RegisterTenantRequest;
use cloud_identity_wallet::domain::ports::{CredentialRepo, TenantRepo};
use cloud_identity_wallet::outbound::{SqlCredentialRepo, SqlTenantRepo, TenantKeyAlg};
use cloud_wallet_kms::provider::LocalProvider;
use sqlx::any::AnyPoolOptions;
use uuid::Uuid;

fn display_metadata() -> CredentialDisplayMetadata {
    CredentialDisplayMetadata {
        display: cloud_wallet_openid4vc::oid4vci::metadata::CredentialDisplay {
            name: "SQLite Test Credential".to_string(),
            ..Default::default()
        },
        issuer_name: "SQLite Issuer".to_string(),
        credential_type: "SQLiteCredential".to_string(),
    }
}

#[tokio::test]
async fn sqlite_feature_backend_initializes_schema_and_round_trips_encrypted_data() {
    sqlx::any::install_default_drivers();

    let temp_dir = tempfile::tempdir().expect("temp dir should be created");
    let db_path = temp_dir.path().join("wallet.db");
    let database_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("sqlite connection should open");

    let tenant_repo =
        SqlTenantRepo::new(pool.clone(), TenantKeyAlg::default(), LocalProvider::new());
    tenant_repo
        .init_schema()
        .await
        .expect("tenant schema should initialize");

    let credential_repo = SqlCredentialRepo::with_cipher(pool, LocalProvider::new());
    credential_repo
        .init_schema()
        .await
        .expect("credential schema should initialize");

    let tenant = tenant_repo
        .create(RegisterTenantRequest {
            name: "SQLite Tenant".to_string(),
        })
        .await
        .expect("tenant should be created");
    let tenant_id = Uuid::parse_str(&tenant.tenant_id).expect("tenant id should be UUID");
    let tenant_key = tenant_repo
        .find_key(tenant_id)
        .await
        .expect("encrypted tenant key should decrypt");
    assert!(!tenant_key.der_bytes.is_empty());

    let mut credential = utils::sample_credential(tenant_id);
    credential.format = CredentialFormat::SdJwtVc;
    credential.status = CredentialStatus::Active;
    credential.raw_credential = "header.payload.signature".to_string();
    let credential_id = credential.id;

    credential_repo
        .upsert(credential.clone(), Some(display_metadata()))
        .await
        .expect("credential should be stored");

    let loaded = credential_repo
        .find_by_id(credential_id, tenant_id)
        .await
        .expect("encrypted credential should decrypt");
    assert_eq!(loaded.raw_credential, credential.raw_credential);
    assert_eq!(loaded.tenant_id, tenant_id);
}
