pub async fn home() -> &'static str {
    "Cloud Identity Wallet"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_home() {
        let response = home().await;
        assert_eq!(response, "Cloud Identity Wallet");
    }
}
