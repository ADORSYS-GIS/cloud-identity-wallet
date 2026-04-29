mod utils;

use reqwest::Client;

#[tokio::test]
async fn test_home_works() {
    let addr = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .get(format!("{addr}/"))
        .send()
        .await
        .expect("Failed to execute request.");

    // Verify the response
    assert!(response.status().is_success());
    let body = response.text().await.unwrap();
    assert!(body.contains("Cloud Identity Wallet"));
}
