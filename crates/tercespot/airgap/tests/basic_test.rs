//! Basic tests for Air Gap Bridge functionality

use airgap::{AirGapBridge, AirGapConfig};
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
    // Test that the bridge was created successfully
    assert!(bridge.forensic_log.worm_path.len() > 0);
}

#[test]
fn test_sha256_calculation() {
    let config = AirGapConfig {
        usb_monitor_path: "".to_string(),
        mount_base_path: "".to_string(),
        worm_drive_path: "".to_string(),
        authorized_keys: vec![],
        execution_timeout: 0,
        verbose: false,
    };

    let bridge = AirGapBridge::new(config).unwrap();

    let data = b"test data";
    let hash = bridge.calculate_sha256(data);

    // Expected SHA-256 hash for "test data"
    assert_eq!(
        hash,
        "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
    );
}
