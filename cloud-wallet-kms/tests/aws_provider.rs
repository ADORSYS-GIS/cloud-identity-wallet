//! Integration tests for AWS KMS provider using LocalStack.

#![cfg(feature = "aws-kms")]

mod common;

use cloud_wallet_kms::provider::{AwsProvider, Provider};
use cloud_wallet_kms::storage::InMemoryBackend;

#[tokio::test]
async fn test_encrypt_decrypt_roundtrip() {
    let aws_config = common::setup().await;

    // Create provider
    let storage = InMemoryBackend::new();
    let provider = AwsProvider::new(&aws_config, "test-hostname", storage);

    // Test data
    let aad = common::SAMPLE_AAD;
    let mut in_out = common::SAMPLE_PLAINTEXT.to_vec();

    // Encrypt
    provider
        .encrypt(aad, &mut in_out)
        .await
        .expect("Encryption failed");

    // Decrypt
    let decrypted = provider
        .decrypt(aad, &mut in_out)
        .await
        .expect("Decryption failed");

    assert_eq!(decrypted, common::SAMPLE_PLAINTEXT,);
}

#[tokio::test]
async fn test_with_encryption_context() {
    let aws_config = common::setup().await;

    // Create providers with different encryption contexts
    let storage1 = InMemoryBackend::new();
    let provider1 = AwsProvider::new(&aws_config, "test-hostname", storage1)
        .with_encryption_context("environment", "test");

    let storage2 = InMemoryBackend::new();
    let provider2 = AwsProvider::new(&aws_config, "test-hostname", storage2)
        .with_encryption_context("environment", "production");

    // Test data
    let aad = common::SAMPLE_AAD;
    let mut plaintext = common::SAMPLE_PLAINTEXT.to_vec();

    // Encrypt with provider1
    provider1
        .encrypt(aad, &mut plaintext)
        .await
        .expect("Encryption failed");

    // Decrypt with provider1 should succeed
    let mut ciphertext_clone = plaintext.clone();
    let decrypted = provider1
        .decrypt(aad, &mut ciphertext_clone)
        .await
        .expect("Decryption with correct context failed");
    assert_eq!(decrypted, common::SAMPLE_PLAINTEXT,);

    // Decrypt with provider2 should fail
    let result = provider2.decrypt(aad, &mut plaintext).await;
    assert!(result.is_err());
    assert!(matches!(result, Err(cloud_wallet_kms::Error::Provider(_))));
}

#[tokio::test]
async fn test_concurrent_operations() {
    let aws_config = common::setup().await;

    // Create provider
    let storage = InMemoryBackend::new();
    let provider = AwsProvider::new(&aws_config, "test-hostname-concurrent", storage);

    let mut handles = vec![];

    // Spawn 10 concurrent encryption/decryption operations
    for i in 0..10 {
        let provider = provider.clone();
        let handle = tokio::spawn(async move {
            let aad = format!("concurrent-aad-{}", i).into_bytes();
            let mut in_out = format!("concurrent-plaintext-{}", i).into_bytes();
            let original_plaintext = in_out.clone();

            provider
                .encrypt(&aad, &mut in_out)
                .await
                .expect("Encryption failed");

            let decrypted = provider
                .decrypt(&aad, &mut in_out)
                .await
                .expect("Decryption failed");

            assert_eq!(decrypted, original_plaintext);
        });
        handles.push(handle);
    }

    // Wait for all operations
    for handle in handles {
        handle.await.expect("Task failed");
    }
}

#[tokio::test]
async fn test_decryption_failure_corrupted_data() {
    let aws_config = common::setup().await;

    // Create provider
    let storage = InMemoryBackend::new();
    let provider = AwsProvider::new(&aws_config, "test-hostname", storage);

    // Encrypt
    let mut data = common::SAMPLE_PLAINTEXT.to_vec();
    provider.encrypt(&[], &mut data).await.unwrap();

    // Decrypting corrupted data should fail
    let mut decrypted = data.clone();
    decrypted[0] ^= 1;
    let result = provider.decrypt(&[], &mut decrypted).await;
    assert!(result.is_err());
}
