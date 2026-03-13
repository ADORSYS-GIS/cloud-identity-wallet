//! Live demonstration of format-aware credential encryption at rest.
//!
//! This example:
//! 1. Connects to PostgreSQL using `DATABASE_URL`.
//! 2. Initializes an [`EncryptingRepository`] over a [`PostgresCredentialRepository`].
//! 3. Stores credentials with encrypted claims.
//! 4. Verifies they can be retrieved and decrypted transparently.
//! 5. Inspects the database directly to verify encryption (DEKs, ciphertexts)
//!    and plaintext metadata (credential_type, etc.).
//!
//! # Running
//!
//! ```bash
//! export DATABASE_URL="postgres://postgres:postgres@localhost:5432/postgres"
//! cargo run -p cloud-wallet-openid4vc --example live_credential_storage --features postgres,encryption
//! ```

use cloud_wallet_openid4vc::{
    EncryptingRepository, Kek, PostgresCredentialRepository,
    models::{Binding, Claims, Credential, CredentialMetadata, CredentialType},
    repository::CredentialRepository,
};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::env;
use time::{Duration, OffsetDateTime};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup DB connection
    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());
    println!("Connecting to database: {}", db_url);
    let pool = PgPool::connect(&db_url).await?;

    // 2. Setup Repository with Encryption
    // In a real app, the KEK would come from a KMS or secure secret.
    let kek = Kek::generate()?;
    println!("Initialised KEK for envelope encryption");

    let backend = PostgresCredentialRepository::new(pool.clone()).await?;
    let repo = EncryptingRepository::new(backend, kek);

    // 3. Create and Store Credentials
    println!("\n--- Storing Credentials ---");

    // A. Identity Credential
    let cred = Credential::new(
        "https://issuer.example.com",
        "user-alex",
        CredentialType::new("https://credentials.example.com/identity"),
        Claims::new(json!({ "given_name": "Alex", "family_name": "Smith" })),
        OffsetDateTime::now_utc(),
        Some(OffsetDateTime::now_utc() + Duration::days(365)),
        None,
        Binding,
        CredentialMetadata {},
    )?;
    let id = cred.id.clone();
    repo.store(cred).await?;
    println!("Stored Identity Credential (ID: {})", id);

    // 4. Verify Transparent Decryption
    println!("\n--- Retrieving and Decrypting ---");
    let retrieved = repo.find_by_id(&id).await?;
    println!(
        "Retrieved: Issuer={}, Subject={}",
        retrieved.issuer, retrieved.subject
    );
    println!("  Decrypted Claims: {}", retrieved.claims.as_value());

    // 5. Inspect Database Directly (The "Secret" View)
    println!("\n--- Inspecting Database Rows (Plaintext vs Encrypted) ---");
    let row = sqlx::query("SELECT * FROM credentials WHERE id = $1")
        .bind(id.as_ref())
        .fetch_one(&pool)
        .await?;

    let credential_type: String = row.get("credential_type");
    let encrypted_dek: Vec<u8> = row.get("encrypted_dek");
    let encrypted_claims: Vec<u8> = row.get("encrypted_claims");

    println!("Database Row (ID: {}):", id);
    println!("  Credential Type: {}", credential_type);
    println!(
        "  Encrypted DEK:    {} bytes (HEX: {:02x?})",
        encrypted_dek.len(),
        &encrypted_dek[..8]
    );
    println!(
        "  Encrypted Claims: {} bytes (HEX: {:02x?})",
        encrypted_claims.len(),
        &encrypted_claims[..8]
    );

    println!("\n✅ Live test completed successfully!");

    Ok(())
}
