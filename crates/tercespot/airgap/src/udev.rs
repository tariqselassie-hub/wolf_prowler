#![allow(missing_docs)]
//! udev Event Listener for USB Device Detection
//!
//! This module provides real-time monitoring of USB device insertion and removal
//! events using the Linux udev subsystem for the Air Gap Bridge.

use std::io::{self};
use std::process::{Command, Stdio};
// use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::task;

/// USB device event types
#[derive(Debug, Clone)]
pub enum UsbEvent {
    /// USB device inserted
    Inserted {
        device_path: String,
        device_name: String,
        vendor_id: Option<String>,
        product_id: Option<String>,
    },
    /// USB device removed
    Removed {
        device_path: String,
        device_name: String,
    },
}

/// udev event listener
pub struct UdevListener {
    /// Channel for sending USB events
    event_sender: broadcast::Sender<UsbEvent>,
}

impl UdevListener {
    /// Create a new udev listener
    ///
    /// # Errors
    /// Returns an error if the listener cannot be initialized.
    pub fn new() -> io::Result<Self> {
        let (tx, _rx) = broadcast::channel(100);

        let tx_clone = tx.clone();

        // Start the udev monitoring task
        task::spawn(async move {
            Self::monitor_udev_events(tx_clone).await;
        });

        Ok(Self { event_sender: tx })
    }

    /// Get a receiver for USB events
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<UsbEvent> {
        self.event_sender.subscribe()
    }

    /// Monitor udev events in a background task
    async fn monitor_udev_events(tx: broadcast::Sender<UsbEvent>) {
        // This is a simplified implementation
        // In production, you would use a proper udev library or direct netlink socket

        loop {
            // Check for new USB devices every 2 seconds
            // Optimization: Run blocking IO in spawn_blocking to avoid blocking the async runtime
            let devices_result = task::spawn_blocking(Self::get_usb_devices).await;

            if let Ok(Ok(devices)) = devices_result {
                for device in devices {
                    let event = UsbEvent::Inserted {
                        device_path: device.path,
                        device_name: device.name,
                        vendor_id: device.vendor_id,
                        product_id: device.product_id,
                    };

                    // Broadcast event (ignore error if no receivers)
                    let _ = tx.send(event);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }

    /// Get list of current USB devices
    fn get_usb_devices() -> io::Result<Vec<UsbDevice>> {
        let output = Command::new("lsusb")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            return Err(io::Error::other("Failed to run lsusb command"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut devices = Vec::new();

        for line in stdout.lines() {
            if let Some(device) = Self::parse_lsusb_line(line) {
                devices.push(device);
            }
        }

        Ok(devices)
    }

    /// Parse a single lsusb output line
    fn parse_lsusb_line(line: &str) -> Option<UsbDevice> {
        // Example lsusb output: "Bus 001 Device 002: ID 8087:0024 Intel Corp. Integrated Rate Matching Hub"
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() >= 6 && parts[2] == "Device" {
            let device_path = format!(
                "/dev/bus/usb/{}/{}",
                parts[1],
                parts[3].trim_end_matches(':')
            );
            let device_name = parts[6..].join(" ");

            // Extract vendor:product ID
            let id_part = parts[5];
            let id_parts: Vec<&str> = id_part.split(':').collect();

            let vendor_id = id_parts.first().map(std::string::ToString::to_string);
            let product_id = id_parts.get(1).map(std::string::ToString::to_string);

            Some(UsbDevice {
                path: device_path,
                name: device_name,
                vendor_id,
                product_id,
            })
        } else {
            None
        }
    }
}

/// USB device information
#[derive(Debug, Clone)]
struct UsbDevice {
    path: String,
    name: String,
    vendor_id: Option<String>,
    product_id: Option<String>,
}

/// Enhanced udev listener with netlink socket support
pub struct NetlinkUdevListener {
    event_sender: broadcast::Sender<UsbEvent>,
}

impl NetlinkUdevListener {
    /// Create a new netlink-based udev listener
    ///
    /// # Errors
    /// Returns an error if the listener cannot be initialized.
    pub fn new() -> io::Result<Self> {
        let (tx, _rx) = broadcast::channel(100);
        let tx_clone = tx.clone();

        // Start the netlink monitoring task
        task::spawn(async move {
            Self::monitor_netlink_events(tx_clone).await;
        });

        Ok(Self { event_sender: tx })
    }

    /// Get a receiver for USB events
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<UsbEvent> {
        self.event_sender.subscribe()
    }

    /// Monitor udev events via netlink socket
    async fn monitor_netlink_events(tx: broadcast::Sender<UsbEvent>) {
        // This would require the netlink-proto crate or similar
        // For now, we'll use a simplified polling approach

        loop {
            // Poll for USB events
            let events = Self::poll_usb_events();
            for event in events {
                let _ = tx.send(event);
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }

    /// Poll for USB events (simplified implementation)
    const fn poll_usb_events() -> Vec<UsbEvent> {
        // In a real implementation, this would use netlink sockets
        // to receive real-time udev events

        // For now, return empty vector
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lsusb_line() {
        let line = "Bus 001 Device 002: ID 8087:0024 Intel Corp. Integrated Rate Matching Hub";
        let device = UdevListener::parse_lsusb_line(line).unwrap();

        assert_eq!(device.path, "/dev/bus/usb/001/002");
        assert_eq!(device.name, "Intel Corp. Integrated Rate Matching Hub");
        assert_eq!(device.vendor_id, Some("8087".to_string()));
        assert_eq!(device.product_id, Some("0024".to_string()));
    }

    #[test]
    fn test_parse_lsusb_line_invalid() {
        let line = "Invalid lsusb output";
        let device = UdevListener::parse_lsusb_line(line);

        assert!(device.is_none());
    }
}
