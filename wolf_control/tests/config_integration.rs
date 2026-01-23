//! Integration tests for wolf_control configuration

use std::fs;
use std::process::Command;
use tempfile::tempdir;
use wolf_control::config::{Config, WolfIdentity};

#[test]
fn test_config_round_trip() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("config.toml");

    // Create a config with all fields set
    let mut original_config = Config::default();
    original_config.api_url = "https://test.example.com:8443".to_string();
    original_config.poll_interval_secs = 10;
    original_config.verbose = true;
    original_config.theme = "light".to_string();
    original_config.show_timestamps = false;
    original_config.auto_scroll_logs = false;
    original_config.max_retries = 5;
    original_config.accept_invalid_certs = false;
    original_config.admin_password = "secure_password".to_string();
    original_config.api_timeout_secs = 60;
    original_config.enable_compression = false;
    original_config.enable_caching = false;
    original_config.cache_ttl_secs = 600;

    // Save to file
    Config::save_to_path(&original_config, file_path.to_str().unwrap()).unwrap();

    // Load from file
    let loaded_config = Config::load_from_path(file_path.to_str().unwrap());

    // Verify all fields match
    assert_eq!(loaded_config.api_url, original_config.api_url);
    assert_eq!(
        loaded_config.poll_interval_secs,
        original_config.poll_interval_secs
    );
    assert_eq!(loaded_config.verbose, original_config.verbose);
    assert_eq!(loaded_config.theme, original_config.theme);
    assert_eq!(
        loaded_config.show_timestamps,
        original_config.show_timestamps
    );
    assert_eq!(
        loaded_config.auto_scroll_logs,
        original_config.auto_scroll_logs
    );
    assert_eq!(loaded_config.max_retries, original_config.max_retries);
    assert_eq!(
        loaded_config.accept_invalid_certs,
        original_config.accept_invalid_certs
    );
    assert_eq!(loaded_config.admin_password, original_config.admin_password);
    assert_eq!(
        loaded_config.api_timeout_secs,
        original_config.api_timeout_secs
    );
    assert_eq!(
        loaded_config.enable_compression,
        original_config.enable_compression
    );
    assert_eq!(loaded_config.enable_caching, original_config.enable_caching);
    assert_eq!(loaded_config.cache_ttl_secs, original_config.cache_ttl_secs);
}

#[test]
fn test_config_load_certs_with_temp_files() {
    let dir = tempdir().unwrap();

    // Create dummy cert and key files
    let cert_path = dir.path().join("client.crt");
    let key_path = dir.path().join("client.key");
    let ca_path = dir.path().join("ca.crt");

    fs::write(&cert_path, "dummy cert content").unwrap();
    fs::write(&key_path, "dummy key content").unwrap();
    fs::write(&ca_path, "dummy ca content").unwrap();

    let mut config = Config::default();
    config.client_cert = Some(cert_path.to_str().unwrap().to_string());
    config.client_key = Some(key_path.to_str().unwrap().to_string());
    config.ca_cert = Some(ca_path.to_str().unwrap().to_string());

    // This will fail because the content is not valid PEM, but we test the file reading logic
    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(config.load_certs());
    // Should fail with PEM parsing error, not file reading error
    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("Failed to create client identity")
            || err_str.contains("Failed to create CA certificate")
    );
}

#[test]
fn test_config_http_client_creation() {
    let config = Config::default();
    let identity = WolfIdentity::default();

    let result = config.create_http_client(&identity);
    // Should succeed with default config
    assert!(result.is_ok());

    let client = result.unwrap();
    // We can't easily test the client configuration, but at least it was created
    assert!(client.get("https://httpbin.org/status/200").build().is_ok());
}

#[test]
fn test_config_with_token() {
    let mut config = Config::default();
    config.api_token = Some("test_token_123".to_string());

    let identity = WolfIdentity::default();
    let client = config.create_http_client(&identity).unwrap();

    // Check that the client has the authorization header
    // This is a bit tricky to test directly, but we can verify the client was created
    let _req = client.get("https://example.com").build().unwrap();
    // The authorization header should be set internally
}

#[test]
fn test_config_validation_edge_cases() {
    // Test with only client key (should fail)
    let mut config = Config::default();
    config.client_key = Some("key.pem".to_string());
    assert!(config.validate().is_err());

    // Test with only CA cert (should pass)
    let mut config = Config::default();
    config.ca_cert = Some("ca.pem".to_string());
    assert!(config.validate().is_ok());

    // Test with both cert and key (should pass)
    let mut config = Config::default();
    config.client_cert = Some("cert.pem".to_string());
    config.client_key = Some("key.pem".to_string());
    config.ca_cert = Some("ca.pem".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_build() {
    // Test that we can build the binary
    let output = Command::new("cargo")
        .args(&["build", "-p", "wolf_control"])
        .output()
        .expect("Failed to run cargo build");

    assert!(
        output.status.success(),
        "Build failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}
