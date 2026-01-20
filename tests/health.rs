mod utils;

use reqwest::Client;

#[tokio::test]
async fn test_health_check_works() {
    let addr = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .get(format!("{addr}/health"))
        .send()
        .await
        .expect("Failed to execute request.");

    // Verify the response
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}
