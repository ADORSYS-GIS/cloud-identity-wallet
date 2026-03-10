//! Live demonstration of format-aware credential encryption at rest.
//!
//! This example:
//! 1. Connects to PostgreSQL using `DATABASE_URL`.
//! 2. Initializes an [`EncryptingRepository`] over a [`PostgresCredentialRepository`].
//! 3. Stores multiple credential formats (SD-JWT, mdoc, JWT VC).
//! 4. Verifies they can be retrieved and decrypted transparently.
//! 5. Inspects the database directly to verify encryption (DEKs, ciphertexts)
//!    and plaintext metadata (vct, doc_type, etc.).
//!
//! # Running
//!
//! ```bash
//! export DATABASE_URL="postgres://postgres:postgres@localhost:5432/postgres"
//! cargo run -p cloud-wallet-openid4vc --example live_credential_storage --features postgres,encryption
//! ```

use cloud_wallet_openid4vc::{
    encrypted_repository::EncryptingRepository,
    encryption::Kek,
    models::{Credential, CredentialPayload, MsoMdocCredential, SdJwtCredential},
    postgres::PostgresCredentialRepository,
    repository::CredentialRepository,
};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
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

    // A. SD-JWT (Identity)
    let sd_jwt = Credential::new(
        "https://issuer.example.com",
        "user-alex",
        OffsetDateTime::now_utc(),
        Some(OffsetDateTime::now_utc() + Duration::days(365)),
        "id_card",
        CredentialPayload::DcSdJwt(SdJwtCredential {
            token: "ey...sig~disclosure~".to_string(),
            vct: "https://credentials.example.com/identity".to_string(),
            claims: json!({ "given_name": "Alex", "family_name": "Smith" }),
        }),
    )?;
    let id_sdjwt = sd_jwt.id.clone();
    repo.store(sd_jwt).await?;
    println!("Stored SD-JWT Identity Credential (ID: {})", id_sdjwt);

    // B. mdoc (Driver's License)
    let mut namespaces = HashMap::new();
    namespaces.insert("org.iso.18013.5.1".into(), json!({ "given_name": "Alex" }));
    let mdoc = Credential::new(
        "https://dmv.example.com",
        "user-alex",
        OffsetDateTime::now_utc(),
        None,
        "mDL",
        CredentialPayload::MsoMdoc(MsoMdocCredential {
            doc_type: "org.iso.18013.5.1.mDL".into(),
            namespaces,
            issuer_signed: "issuer-signed-binary-blob".into(),
        }),
    )?;
    let id_mdoc = mdoc.id.clone();
    repo.store(mdoc).await?;
    println!("Stored mdoc Driver's License (ID: {})", id_mdoc);

    // 4. Verify Transparent Decryption
    println!("\n--- Retrieving and Decrypting ---");
    let retrieved = repo.find_by_id(&id_sdjwt).await?;
    println!(
        "Retrieved SD-JWT: Issuer={}, Subject={}",
        retrieved.issuer, retrieved.subject
    );
    if let CredentialPayload::DcSdJwt(payload) = &retrieved.credential {
        println!("  Decrypted Claims: {}", payload.claims);
    }

    // 5. Inspect Database Directly (The "Secret" View)
    println!("\n--- Inspecting Database Rows (Plaintext vs Encrypted) ---");
    let row = sqlx::query("SELECT * FROM credentials WHERE id = $1")
        .bind(&id_sdjwt)
        .fetch_one(&pool)
        .await?;

    let format: String = row.get("format");
    let vct: Option<String> = row.get("vct");
    let encrypted_dek: Vec<u8> = row.get("encrypted_dek");
    let encrypted_payload: Vec<u8> = row.get("encrypted_payload");

    println!("Database Row (ID: {}):", id_sdjwt);
    println!("  Format:     {}", format);
    println!("  Plain vct:  {:?}", vct);
    println!(
        "  Encrypted DEK:     {} bytes (HEX: {:02x?})",
        encrypted_dek.len(),
        &encrypted_dek[..8]
    );
    println!(
        "  Encrypted Payload: {} bytes (HEX: {:02x?})",
        encrypted_payload.len(),
        &encrypted_payload[..8]
    );

    println!("\n✅ Live test completed successfully!");

    Ok(())
}
