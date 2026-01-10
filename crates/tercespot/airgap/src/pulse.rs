//! Hardware Pulse Integration for Defense Applications
//!
//! This module implements the "Identity Token" requirement for the Air Gap Bridge,
//! ensuring that data USB in Port A + Identity Token in Port B = Execution.

#![allow(missing_docs)]
use crate::error::{AirGapError, Result};

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::broadcast;
use tokio::time::sleep;

/// Hardware pulse device types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PulseDeviceType {
    /// Data USB port (for .tersec packages)
    DataPort,
    /// Identity token port (for authentication)
    IdentityPort,
    /// Biometric scanner for multi-factor authentication
    BiometricScanner,
}

/// Hardware pulse device information
#[derive(Debug, Clone)]
pub struct PulseDevice {
    /// Device path (e.g., /dev/ttyUSB0)
    pub device_path: String,

    /// Device type
    pub device_type: PulseDeviceType,

    /// Device serial number
    pub serial_number: String,

    /// Last seen timestamp
    pub last_seen: SystemTime,

    /// Device status
    pub status: PulseDeviceStatus,
}

/// Device status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PulseDeviceStatus {
    /// Device is connected and ready
    Connected,
    /// Device is disconnected
    Disconnected,
    /// Device is in error state
    Error(String),
}

/// Pulse event types
#[derive(Debug, Clone)]
pub enum PulseEvent {
    /// Device connected
    DeviceConnected(PulseDevice),
    /// Device disconnected
    DeviceDisconnected(PulseDevice),
    /// Device status changed
    DeviceStatusChanged(PulseDevice),
    /// Identity token validated
    IdentityValidated { serial: String },
    /// Identity token validation failed
    IdentityValidationFailed { serial: String, reason: String },
}

/// Hardware pulse manager
pub struct PulseManager {
    /// Channel for sending pulse events
    event_sender: broadcast::Sender<PulseEvent>,

    /// Configured data port
    _data_port: Option<String>,

    /// Configured identity port
    _identity_port: Option<String>,

    /// Connected devices
    connected_devices: Arc<tokio::sync::RwLock<HashMap<String, PulseDevice>>>,
}

impl PulseManager {
    /// Create a new pulse manager
    #[must_use]
    pub fn new(data_port: Option<String>, identity_port: Option<String>) -> Self {
        let (tx, _rx) = broadcast::channel(100);

        let connected_devices = Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        // Start the pulse monitoring task
        let devices_clone = Arc::clone(&connected_devices);
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            Self::monitor_pulse_devices(tx_clone, devices_clone).await;
        });

        Self {
            event_sender: tx,
            _data_port: data_port,
            _identity_port: identity_port,
            connected_devices,
        }
    }

    /// Get a receiver for pulse events
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<PulseEvent> {
        self.event_sender.subscribe()
    }

    /// Monitor pulse devices
    async fn monitor_pulse_devices(
        tx: broadcast::Sender<PulseEvent>,
        connected_devices: Arc<tokio::sync::RwLock<HashMap<String, PulseDevice>>>,
    ) {
        loop {
            // Scan for devices
            match DeviceScanner::scan_devices().await {
                Ok(scanned_devices) => {
                    let mut stored_devices = connected_devices.write().await;

                    // Check for new devices
                    for device in &scanned_devices {
                        if !stored_devices.contains_key(&device.serial_number) {
                            // New device found
                            stored_devices.insert(device.serial_number.clone(), device.clone());
                            let _ = tx.send(PulseEvent::DeviceConnected(device.clone()));
                        }
                    }

                    // Check for removed devices
                    let current_serials: Vec<String> = scanned_devices
                        .iter()
                        .map(|d| d.serial_number.clone())
                        .collect();
                    let removed_serials: Vec<String> = stored_devices
                        .keys()
                        .filter(|k| !current_serials.contains(k))
                        .cloned()
                        .collect();

                    for serial in removed_serials {
                        if let Some(device) = stored_devices.remove(&serial) {
                            let _ = tx.send(PulseEvent::DeviceDisconnected(device));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error scanning pulse devices: {e}");
                }
            }

            // Check for device presence logging
            Self::check_device_presence(&connected_devices).await;

            sleep(Duration::from_secs(1)).await;
        }
    }

    /// Check device presence and send events
    async fn check_device_presence(
        connected_devices: &tokio::sync::RwLock<HashMap<String, PulseDevice>>,
    ) {
        let devices = connected_devices.read().await;

        // Check if we have both required devices
        let has_data_port = devices.values().any(|d| {
            d.device_type == PulseDeviceType::DataPort && d.status == PulseDeviceStatus::Connected
        });
        let has_identity_port = devices.values().any(|d| {
            d.device_type == PulseDeviceType::IdentityPort
                && d.status == PulseDeviceStatus::Connected
        });
        let has_biometric = devices.values().any(|d| {
            d.device_type == PulseDeviceType::BiometricScanner
                && d.status == PulseDeviceStatus::Connected
        });

        if has_data_port && has_identity_port && has_biometric {
            // Both devices present, ready for execution
            // println!("✅ All required devices connected - system ready");
        } else {
            // println!("⚠️  Missing required devices:");
            // if !has_data_port { println!(" - Data Port"); }
            // if !has_identity_port { println!(" - Identity Port"); }
            // if !has_biometric { println!(" - Biometric Scanner"); }
        }
    }

    /// Validate identity token
    ///
    /// # Errors
    /// Returns an error if the identity token is not found or is not an identity port.
    pub async fn validate_identity_token(&self, serial: &str) -> Result<()> {
        let devices = self.connected_devices.read().await;

        if let Some(device) = devices.get(serial) {
            if device.device_type == PulseDeviceType::IdentityPort
                && device.status == PulseDeviceStatus::Connected
            {
                // In a real implementation, this would:
                // 1. Read challenge from data port
                // 2. Send challenge to identity token
                // 3. Verify response with stored credentials

                println!("✅ Identity token {serial} validated");
                Ok(())
            } else {
                Err(AirGapError::PermissionDenied(
                    "Device is not an identity port or not connected".to_string(),
                ))
            }
        } else {
            Err(AirGapError::PermissionDenied(
                "Identity token not found".to_string(),
            ))
        }
    }

    /// Validate biometric scan
    ///
    /// # Errors
    /// Returns an error if the biometric scanner is not found or verification fails.
    pub async fn validate_biometric_scan(&self, serial: &str) -> Result<()> {
        let devices = self.connected_devices.read().await;

        if let Some(device) = devices.get(serial) {
            if device.device_type == PulseDeviceType::BiometricScanner
                && device.status == PulseDeviceStatus::Connected
            {
                // In a real implementation, this would:
                // 1. Trigger scan on device
                // 2. Receive biometric template
                // 3. Match against stored hash

                // Simulate processing delay
                sleep(Duration::from_millis(500)).await;

                println!("✅ Biometric scan verified for device {serial}");
                Ok(())
            } else {
                Err(AirGapError::PermissionDenied(
                    "Device is not a biometric scanner or not connected".to_string(),
                ))
            }
        } else {
            Err(AirGapError::PermissionDenied(
                "Biometric scanner not found".to_string(),
            ))
        }
    }

    /// Check if both required devices are present and valid
    pub async fn is_execution_ready(&self) -> bool {
        let devices = self.connected_devices.read().await;

        let has_data_port = devices.values().any(|d| {
            d.device_type == PulseDeviceType::DataPort && d.status == PulseDeviceStatus::Connected
        });

        let has_identity_port = devices.values().any(|d| {
            d.device_type == PulseDeviceType::IdentityPort
                && d.status == PulseDeviceStatus::Connected
        });

        let has_biometric = devices.values().any(|d| {
            d.device_type == PulseDeviceType::BiometricScanner
                && d.status == PulseDeviceStatus::Connected
        });

        has_data_port && has_identity_port && has_biometric
    }
}

/// USB port power controller
pub struct UsbPortController;

impl UsbPortController {
    /// Power off a specific USB port
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn power_off_port(port: &str) -> io::Result<()> {
        println!("Powering off USB port: {port}");

        // In a real implementation, this would use:
        // 1. sysfs interface: /sys/bus/usb/devices/usbX/power/level
        // 2. Or udev rules to control port power
        // 3. Or hardware-specific APIs

        // For now, we'll simulate the operation
        Ok(())
    }

    /// Power on a specific USB port
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn power_on_port(port: &str) -> io::Result<()> {
        println!("Powering on USB port: {port}");

        // Simulated operation
        Ok(())
    }

    /// Get USB port status
    ///
    /// # Errors
    /// Returns an error if the status cannot be retrieved.
    pub const fn get_port_status(_port: &str) -> io::Result<PortStatus> {
        // In a real implementation, this would read from sysfs
        // For now, return a simulated status
        Ok(PortStatus::PoweredOff)
    }
}

/// USB port status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortStatus {
    /// Port is powered on
    PoweredOn,
    /// Port is powered off
    PoweredOff,
    /// Port is in error state
    Error,
}

/// Device scanner for detecting pulse devices
pub struct DeviceScanner;

impl DeviceScanner {
    /// Scan for connected pulse devices
    ///
    /// # Errors
    /// Returns an error if the scanning operation fails.
    pub async fn scan_devices() -> io::Result<Vec<PulseDevice>> {
        let mut devices = Vec::new();

        // Scan for USB serial devices
        if let Ok(serial_devices) = Self::scan_serial_devices().await {
            for device in serial_devices {
                if let Some(pulse_device) = Self::identify_pulse_device(&device) {
                    devices.push(pulse_device);
                }
            }
        }

        Ok(devices)
    }

    /// Scan for USB serial devices
    async fn scan_serial_devices() -> io::Result<Vec<String>> {
        let dev_dir = std::env::var("TERSEC_PULSE_DEV_DIR").unwrap_or_else(|_| "/dev".to_string());
        let mut devices = Vec::new();

        let mut entries = tokio::fs::read_dir(&dev_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("ttyUSB") {
                devices.push(format!("{}/{}", dev_dir, name_str));
            }
        }

        Ok(devices)
    }

    /// Identify if a device is a pulse device
    fn identify_pulse_device(device_path: &str) -> Option<PulseDevice> {
        // In a real implementation, this would:
        // 1. Open the serial device
        // 2. Send identification command
        // 3. Read response to determine device type

        // For simulation, we'll assume certain patterns
        if device_path.contains("ttyUSB0") {
            Some(PulseDevice {
                device_path: device_path.to_string(),
                device_type: PulseDeviceType::DataPort,
                serial_number: "DATA_PORT_001".to_string(),
                last_seen: SystemTime::now(),
                status: PulseDeviceStatus::Connected,
            })
        } else if device_path.contains("ttyUSB1") {
            Some(PulseDevice {
                device_path: device_path.to_string(),
                device_type: PulseDeviceType::IdentityPort,
                serial_number: "IDENTITY_TOKEN_001".to_string(),
                last_seen: SystemTime::now(),
                status: PulseDeviceStatus::Connected,
            })
        } else if device_path.contains("ttyUSB2") {
            Some(PulseDevice {
                device_path: device_path.to_string(),
                device_type: PulseDeviceType::BiometricScanner,
                serial_number: "BIO_SCANNER_001".to_string(),
                last_seen: SystemTime::now(),
                status: PulseDeviceStatus::Connected,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pulse_manager_creation() {
        let manager = PulseManager::new(
            Some("/dev/ttyUSB0".to_string()),
            Some("/dev/ttyUSB1".to_string()),
        );

        let mut subscriber = manager.subscribe();

        // Should be able to receive events from subscriber
        // Note: Broadcast channel might lag or not receive previous events.
        // But scanning happens in background.
        assert!(subscriber.try_recv().is_err()); // No events initially
    }

    #[test]
    fn test_pulse_device_status() {
        let device = PulseDevice {
            device_path: "/dev/ttyUSB0".to_string(),
            device_type: PulseDeviceType::DataPort,
            serial_number: "TEST_001".to_string(),
            last_seen: SystemTime::now(),
            status: PulseDeviceStatus::Connected,
        };

        assert_eq!(device.device_type, PulseDeviceType::DataPort);
        assert_eq!(device.status, PulseDeviceStatus::Connected);
    }

    #[tokio::test]
    async fn test_device_scanner_with_mock_fs() {
        use std::fs::File;
        use tempfile::tempdir;

        // 1. Create temp directory to simulate /dev
        let dir = tempdir().unwrap();
        let dev_path = dir.path().to_str().unwrap().to_string();

        // 2. Create dummy device files
        File::create(dir.path().join("ttyUSB0")).unwrap(); // Should be identified as Data Port
        File::create(dir.path().join("ttyUSB1")).unwrap(); // Should be identified as Identity Port
        File::create(dir.path().join("ttyUSB2")).unwrap(); // Should be identified as Biometric Scanner

        // 3. Set env var to point scanner to temp dir
        std::env::set_var("TERSEC_PULSE_DEV_DIR", &dev_path);

        // 4. Run scan
        let devices = DeviceScanner::scan_devices().await.unwrap();

        // 5. Verify results
        assert_eq!(devices.len(), 3);
        let serials: Vec<String> = devices.iter().map(|d| d.serial_number.clone()).collect();
        assert!(serials.contains(&"DATA_PORT_001".to_string()));
        assert!(serials.contains(&"IDENTITY_TOKEN_001".to_string()));
        assert!(serials.contains(&"BIO_SCANNER_001".to_string()));

        // Cleanup
        std::env::remove_var("TERSEC_PULSE_DEV_DIR");
    }

    #[tokio::test]
    async fn test_pulse_handshake_simulation() {
        use std::fs::File;
        use std::time::Duration;
        use tempfile::tempdir;

        // 1. Create temp directory to simulate /dev
        let dir = tempdir().unwrap();
        let dev_path = dir.path().to_str().unwrap().to_string();

        // 2. Create dummy device files
        // ttyUSB0 -> Data Port
        File::create(dir.path().join("ttyUSB0")).unwrap();
        // ttyUSB1 -> Identity Token
        File::create(dir.path().join("ttyUSB1")).unwrap();
        // ttyUSB2 -> Biometric Scanner
        File::create(dir.path().join("ttyUSB2")).unwrap();

        // 3. Set env var to point scanner to temp dir
        std::env::set_var("TERSEC_PULSE_DEV_DIR", &dev_path);

        // 4. Initialize PulseManager
        let manager = PulseManager::new(None, None);
        let mut rx = manager.subscribe();

        // 5. Wait for devices to be detected
        // PulseManager scans every 1s. We wait for 3 connection events.
        let mut connected_count = 0;
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                Ok(event) = rx.recv() => {
                    if let PulseEvent::DeviceConnected(_) = event {
                        connected_count += 1;
                        if connected_count >= 3 {
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        // 6. Verify Execution Ready state
        assert!(
            manager.is_execution_ready().await,
            "System should be ready (Data + Identity + Biometric)"
        );

        // 7. Simulate Handshake
        let result = manager.validate_identity_token("IDENTITY_TOKEN_001").await;
        assert!(result.is_ok(), "Handshake should succeed");

        // 8. Simulate Biometric Scan
        let bio_result = manager.validate_biometric_scan("BIO_SCANNER_001").await;
        assert!(bio_result.is_ok(), "Biometric scan should succeed");

        // 9. Test Disconnection
        std::fs::remove_file(dir.path().join("ttyUSB1")).unwrap();

        // Wait for disconnection event
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);
        let mut disconnected = false;

        loop {
            tokio::select! {
                Ok(event) = rx.recv() => {
                    if let PulseEvent::DeviceDisconnected(device) = event {
                        if device.serial_number == "IDENTITY_TOKEN_001" {
                            disconnected = true;
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        assert!(
            disconnected,
            "Should detect disconnection of Identity Token"
        );
        assert!(
            !manager.is_execution_ready().await,
            "System should no longer be ready"
        );

        // Cleanup
        std::env::remove_var("TERSEC_PULSE_DEV_DIR");
    }
}
