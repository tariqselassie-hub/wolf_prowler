//! Integration tests for Wolf Prowler system startup and basic functionality

#[cfg(test)]
mod integration_tests {
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_system_startup() {
        // Test that the system can start up without panicking
        let mut child = Command::new("cargo")
            .args(&["run", "--quiet"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start wolf_prowler");

        // Let it run for a few seconds
        sleep(Duration::from_secs(5)).await;

        // Check if it's still running (should be serving on port 3031)
        let status = child.try_wait().unwrap();
        assert!(status.is_none(), "System should still be running");

        // Kill the process
        let _ = child.kill();
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        // Start the system
        let mut child = Command::new("cargo")
            .args(&["run", "--quiet"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start wolf_prowler");

        // Wait for startup
        sleep(Duration::from_secs(3)).await;

        // Test health endpoint
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let response = client
            .get("https://127.0.0.1:3031/api/v1/health")
            .send()
            .await;

        assert!(response.is_ok(), "Health endpoint should respond");

        let status = response.unwrap().status();
        assert!(status.is_success(), "Health endpoint should return success");

        // Kill the process
        let _ = child.kill();
    }

    #[tokio::test]
    async fn test_api_endpoints() {
        // Start the system
        let mut child = Command::new("cargo")
            .args(&["run", "--quiet"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start wolf_prowler");

        // Wait for startup
        sleep(Duration::from_secs(3)).await;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        // Test multiple endpoints
        let endpoints = vec![
            "https://127.0.0.1:3031/api/v1/status",
            "https://127.0.0.1:3031/api/v1/network/status",
            "https://127.0.0.1:3031/api/v1/security/status",
        ];

        for endpoint in endpoints {
            let response = client.get(endpoint).send().await;
            assert!(response.is_ok(), "Endpoint {} should respond", endpoint);

            let status = response.unwrap().status();
            assert!(
                status.is_success(),
                "Endpoint {} should return success",
                endpoint
            );
        }

        // Kill the process
        let _ = child.kill();
    }
}
