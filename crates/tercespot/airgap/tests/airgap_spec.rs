//! Comprehensive tests for the Quantum-Proof Air Gap Bridge

use airgap::pulse::*;
// use airgap::udev::*;
use airgap::*;
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer};
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use tempfile::TempDir;

#[tokio::test]
async fn test_air_gap_bridge_creation() {
    let temp_dir = TempDir::new().unwrap();
    let mount_path = temp_dir.path().join("mount");
    let worm_path = temp_dir.path().join("worm");

    let config = AirGapConfig {
        usb_monitor_path: "/tmp/usb_monitor".to_string(),
        mount_base_path: mount_path.to_string_lossy().to_string(),
        worm_drive_path: worm_path.to_string_lossy().to_string(),
        authorized_keys: vec![],
        execution_timeout: 30000,
        verbose: true,
    };

    let bridge = AirGapBridge::new(config).unwrap();
    assert!(bridge.config.mount_base_path == mount_path.to_string_lossy().to_string());
}

#[tokio::test]
async fn test_forensic_logger() {
    let temp_dir = TempDir::new().unwrap();
    let worm_path = temp_dir.path().to_string_lossy().to_string();

    let logger = ForensicLogger::new(&worm_path).unwrap();

    let entry = ForensicLogEntry {
        timestamp: SystemTime::now(),
        file_hash: "test_hash".to_string(),
        usb_device: "sdb1".to_string(),
        reason: "Invalid signature".to_string(),
        file_path: "/test/file.tersec".to_string(),
    };

    logger.log_rejected_file(entry).unwrap();

    // Check that log file was created
    let log_file = format!("{}/forensic_log.txt", worm_path);
    assert!(Path::new(&log_file).exists());

    let log_content = fs::read_to_string(&log_file).unwrap();
    assert!(log_content.contains("test_hash"));
    assert!(log_content.contains("Invalid signature"));
}

#[tokio::test]
async fn test_sha256_calculation() {
    let temp_dir = TempDir::new().unwrap();
    let worm_path = temp_dir.path().to_string_lossy().to_string();

    let config = AirGapConfig {
        usb_monitor_path: "/tmp/usb_monitor".to_string(),
        mount_base_path: "/tmp/mount".to_string(),
        worm_drive_path: worm_path,
        authorized_keys: vec![],
        execution_timeout: 30000,
        verbose: false,
    };

    let bridge = AirGapBridge::new(config).unwrap();

    let data = b"test data for hashing";
    let hash = bridge.calculate_sha256(data);

    // Expected SHA-256 hash for "test data for hashing"
    assert_eq!(
        hash,
        "f7eb7961d8a233e6256d3a6257548bbb9293c3a08fb3574c88c7d6b429dbb9f5"
    );
}

#[tokio::test]
async fn test_package_signature_verification() {
    // Generate test keypair
    let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();

    let temp_dir = TempDir::new().unwrap();
    let worm_path = temp_dir.path().to_string_lossy().to_string();

    let config = AirGapConfig {
        usb_monitor_path: "/tmp/usb_monitor".to_string(),
        mount_base_path: "/tmp/mount".to_string(),
        worm_drive_path: worm_path,
        authorized_keys: vec![hex::encode(pk.into_bytes())],
        execution_timeout: 30000,
        verbose: false,
    };

    let bridge = AirGapBridge::new(config).unwrap();

    // Create test package data
    let command_data = b"echo 'test command'";
    let signature = sk.try_sign(command_data, b"tersec").unwrap();

    // Create package: command_data + signature
    let mut package_data = Vec::new();
    package_data.extend_from_slice(command_data);
    package_data.extend_from_slice(&signature);

    // Verify signature
    assert!(bridge.verify_package_signature(&package_data));

    // Test with invalid signature
    let mut invalid_package = Vec::new();
    invalid_package.extend_from_slice(command_data);
    invalid_package.extend_from_slice(&[0u8; 2420]); // Invalid signature

    assert!(!bridge.verify_package_signature(&invalid_package));
}

#[tokio::test]
async fn test_pulse_manager() {
    let manager = PulseManager::new(
        Some("/dev/ttyUSB0".to_string()),
        Some("/dev/ttyUSB1".to_string()),
    );

    let _subscriber = manager.subscribe();

    // Test device status checking
    let is_ready = manager.is_execution_ready().await;
    assert!(!is_ready); // No devices connected initially

    // Test identity validation (would fail without connected device)
    let result = manager.validate_identity_token("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_usb_port_controller() {
    // Test port power operations
    let result = UsbPortController::power_off_port("sdb1");
    assert!(result.is_ok());

    let result = UsbPortController::power_on_port("sdb1");
    assert!(result.is_ok());

    let status = UsbPortController::get_port_status("sdb1");
    assert!(status.is_ok());
}

#[tokio::test]
async fn test_device_scanner() {
    let devices = DeviceScanner::scan_devices().await;

    // This test may return empty results in CI environment
    // but should not panic or error
    assert!(devices.is_ok());
}

#[tokio::test]
async fn test_complete_air_gap_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let mount_path = temp_dir.path().join("mount");
    let worm_path = temp_dir.path().join("worm");

    // Create test directories
    fs::create_dir_all(&mount_path).unwrap();
    fs::create_dir_all(&worm_path).unwrap();

    // Generate test keypair
    let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();

    let config = AirGapConfig {
        usb_monitor_path: mount_path.to_string_lossy().to_string(),
        mount_base_path: mount_path.to_string_lossy().to_string(),
        worm_drive_path: worm_path.to_string_lossy().to_string(),
        authorized_keys: vec![hex::encode(pk.into_bytes())],
        execution_timeout: 5000,
        verbose: true,
    };

    let mut bridge = AirGapBridge::new(config.clone()).unwrap();

    // Initialize components
    bridge = bridge.with_udev_listener().unwrap();
    bridge = bridge
        .with_pulse_manager(
            Some("/dev/ttyUSB0".to_string()),
            Some("/dev/ttyUSB1".to_string()),
        )
        .unwrap();

    // Create test .tersec package
    let command_data = b"echo 'air gap test'";
    let signature = sk.try_sign(command_data, b"tersec").unwrap();

    let mut package_data = Vec::new();
    package_data.extend_from_slice(command_data);
    package_data.extend_from_slice(&signature);

    let package_path = mount_path.join("test_package.tersec");
    fs::write(&package_path, &package_data).unwrap();

    // Test package processing
    let result = bridge.process_package(&package_path, "sdb1").await;

    // Expect error because Pulse devices are missing in this environment
    assert!(
        result.is_err(),
        "Expected execution block due to missing Pulse devices"
    );

    // Create a new bridge WITHOUT pulse manager to test forensic logging
    // because pulse manager would block execution before signature verification occurs.
    let bridge_logging = AirGapBridge::new(config).unwrap();

    // Test forensic logging for invalid package
    let mut invalid_package = Vec::new();
    invalid_package.extend_from_slice(command_data);
    invalid_package.extend_from_slice(&[0u8; 2420]); // Invalid signature

    let invalid_package_path = mount_path.join("invalid_package.tersec");
    fs::write(&invalid_package_path, &invalid_package).unwrap();

    let result = bridge_logging
        .process_package(&invalid_package_path, "sdb1")
        .await;
    assert!(result.is_err());

    // Check that forensic log was created
    let log_file = worm_path.join("forensic_log.txt");
    assert!(log_file.exists());

    let log_content = fs::read_to_string(&log_file).unwrap();
    assert!(log_content.contains("Invalid signature"));
}

#[test]
fn test_pulse_device_types() {
    let data_device = PulseDevice {
        device_path: "/dev/ttyUSB0".to_string(),
        device_type: PulseDeviceType::DataPort,
        serial_number: "DATA_001".to_string(),
        last_seen: SystemTime::now(),
        status: PulseDeviceStatus::Connected,
    };

    let identity_device = PulseDevice {
        device_path: "/dev/ttyUSB1".to_string(),
        device_type: PulseDeviceType::IdentityPort,
        serial_number: "IDENTITY_001".to_string(),
        last_seen: SystemTime::now(),
        status: PulseDeviceStatus::Connected,
    };

    assert_eq!(data_device.device_type, PulseDeviceType::DataPort);
    assert_eq!(identity_device.device_type, PulseDeviceType::IdentityPort);
}

#[test]
fn test_forensic_log_entry() {
    let entry = ForensicLogEntry {
        timestamp: SystemTime::now(),
        file_hash: "abc123def456".to_string(),
        usb_device: "sdb1".to_string(),
        reason: "Signature verification failed".to_string(),
        file_path: "/usb/test.tersec".to_string(),
    };

    assert_eq!(entry.file_hash, "abc123def456");
    assert_eq!(entry.reason, "Signature verification failed");
    assert_eq!(entry.usb_device, "sdb1");
}
