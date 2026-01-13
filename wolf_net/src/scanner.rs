//! Network Scanner Module
//!
//! Provides LAN device discovery capabilities using ICMP ping and ARP scanning.
//! This module discovers devices on the local network that are not running Wolf Prowler.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Discovered network device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDevice {
    /// IP address of the device
    pub ip: IpAddr,
    /// Optional hostname if resolvable
    pub hostname: Option<String>,
    /// Optional MAC address (filled after ARP scan)
    pub mac_address: Option<String>,
    /// Measured latency in milliseconds
    pub latency_ms: u64,
    /// Classified device type
    pub device_type: DeviceType,
    /// Timestamp of the last observation
    pub last_seen: chrono::DateTime<chrono::Utc>,
    /// Reachability flag
    pub is_reachable: bool,
}

/// Device type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceType {
    /// Router devices (gateways)
    Router,
    /// General computers (desktops, laptops)
    Computer,
    /// Mobile phones
    Phone,
    /// Network printers
    Printer,
    /// Internet of Things devices
    IoT,
    /// Unknown or unclassified devices
    Unknown,
}

/// Network scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Subnet in CIDR notation to scan (e.g., "192.168.1.0/24")
    pub subnet: String,
    /// Timeout per ping in milliseconds
    pub timeout_ms: u64,
    /// Maximum concurrent ping tasks
    pub max_concurrent: usize,
    /// Optional network interface to bind to
    pub interface: Option<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            subnet: "192.168.1.0/24".to_string(),
            timeout_ms: 1000,
            max_concurrent: 50,
            interface: None,
        }
    }
}

/// Network scanner for LAN device discovery
pub struct NetworkScanner {
    config: ScannerConfig,
}

impl NetworkScanner {
    /// Create a new network scanner
    #[must_use]
    pub const fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    /// Run the reporting service event loop, batching and sending telemetry events to the hub.
    pub async fn run(&mut self) -> anyhow::Result<Self> {
        let subnet = Self::detect_local_subnet().await?;
        Ok(Self {
            config: ScannerConfig {
                subnet,
                ..Default::default()
            },
        })
    }

    /// Auto-detect local subnet from network interfaces
    async fn detect_local_subnet() -> anyhow::Result<String> {
        // Use `ip route` on Linux to find default gateway subnet
        let output = tokio::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Parse output like: "default via 192.168.1.1 dev eth0"
            for line in stdout.lines() {
                if line.contains("default") {
                    if let Some(via_pos) = line.find("via") {
                        let after_via = &line[via_pos.saturating_add(4)..];
                        if let Some(ip_str) = after_via.split_whitespace().next() {
                            // Extract network from gateway IP
                            if let Ok(gateway) = ip_str.parse::<Ipv4Addr>() {
                                let octets = gateway.octets();
                                let subnet =
                                    format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                                tracing::info!("🔍 Auto-detected subnet: {subnet}");
                                return Ok(subnet);
                            }
                        }
                    }
                }
            }
        }

        // Fallback to default
        tracing::warn!("Could not auto-detect subnet, using default 192.168.1.0/24");
        Ok("192.168.1.0/24".to_string())
    }

    /// Scan the local network for devices
    pub async fn scan_network(&self) -> anyhow::Result<Vec<NetworkDevice>> {
        tracing::info!("🔍 Starting network scan on {}", self.config.subnet);

        let mut devices = Vec::new();

        // Get local subnet IPs to scan
        let ips = self.get_subnet_ips()?;

        // Scan each IP concurrently
        let mut tasks = Vec::new();
        for ip in ips {
            let timeout_ms = self.config.timeout_ms;
            tasks.push(tokio::spawn(async move {
                Self::ping_host(ip, timeout_ms).await
            }));
        }

        // Collect results
        for task in tasks {
            if let Ok(Ok(Some(device))) = task.await {
                devices.push(device);
            }
        }

        // Resolve MAC addresses for discovered devices
        Self::resolve_mac_addresses(&mut devices).await;

        tracing::info!("✅ Network scan complete: found {} devices", devices.len());
        Ok(devices)
    }

    /// Ping a single host
    async fn ping_host(ip: IpAddr, timeout_ms: u64) -> anyhow::Result<Option<NetworkDevice>> {
        let start = Instant::now();

        // Use system ping command for simplicity
        let result = timeout(
            Duration::from_millis(timeout_ms),
            tokio::task::spawn_blocking(move || {
                Command::new("ping")
                    .arg("-c")
                    .arg("1")
                    .arg("-W")
                    .arg("1")
                    .arg(ip.to_string())
                    .output()
            }),
        )
        .await;

        match result {
            Ok(Ok(Ok(output))) => {
                if output.status.success() {
                    let latency = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

                    // Try to resolve hostname
                    let hostname = Self::resolve_hostname(&ip).await;

                    // Classify device type based on hostname or other heuristics
                    let device_type = Self::classify_device(hostname.as_ref());

                    Ok(Some(NetworkDevice {
                        ip,
                        hostname,
                        mac_address: None, // Populated later by resolve_mac_addresses
                        latency_ms: latency,
                        device_type,
                        last_seen: chrono::Utc::now(),
                        is_reachable: true,
                    }))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    /// Resolve hostname for an IP address
    async fn resolve_hostname(ip: &IpAddr) -> Option<String> {
        tokio::task::spawn_blocking({
            let ip = *ip;
            move || dns_lookup::lookup_addr(&ip).ok()
        })
        .await
        .ok()
        .flatten()
    }

    /// Resolve MAC addresses using ARP table
    async fn resolve_mac_addresses(devices: &mut [NetworkDevice]) {
        // Read ARP table
        let arp_table = match Self::read_arp_table().await {
            Ok(table) => table,
            Err(e) => {
                tracing::warn!("Failed to read ARP table: {}", e);
                return;
            }
        };

        // Match devices with ARP entries
        for device in devices.iter_mut() {
            if let Some(mac) = arp_table.get(&device.ip.to_string()) {
                device.mac_address = Some(mac.clone());
            }
        }
    }

    /// Read system ARP table
    async fn read_arp_table() -> anyhow::Result<HashMap<String, String>> {
        let output = tokio::process::Command::new("arp")
            .arg("-a")
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("ARP command failed"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut arp_table = HashMap::new();

        // Parse ARP output
        // Format: "hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Look for IP in parentheses and MAC address
            for (i, part) in parts.iter().enumerate() {
                if part.starts_with('(') && part.ends_with(')') {
                    let ip = part.trim_matches(|c| c == '(' || c == ')');

                    // Look for MAC address (format: xx:xx:xx:xx:xx:xx)
                    if let Some(mac_part) = parts.get(i.saturating_add(2)) {
                        if mac_part.contains(':') && mac_part.len() == 17 {
                            arp_table.insert(ip.to_string(), (*mac_part).to_string());
                        }
                    }
                }
            }
        }

        tracing::debug!("📡 Read {} ARP entries", arp_table.len());
        Ok(arp_table)
    }

    /// Classify device type based on hostname
    fn classify_device(hostname: Option<&String>) -> DeviceType {
        hostname.map_or(DeviceType::Unknown, |name| {
            let name_lower = name.to_lowercase();

            if name_lower.contains("router") || name_lower.contains("gateway") {
                DeviceType::Router
            } else if name_lower.contains("printer")
                || name_lower.contains("hp")
                || name_lower.contains("canon")
            {
                DeviceType::Printer
            } else if name_lower.contains("phone")
                || name_lower.contains("android")
                || name_lower.contains("iphone")
            {
                DeviceType::Phone
            } else if name_lower.contains("iot") || name_lower.contains("smart") {
                DeviceType::IoT
            } else if name_lower.contains("pc")
                || name_lower.contains("laptop")
                || name_lower.contains("desktop")
            {
                DeviceType::Computer
            } else {
                DeviceType::Unknown
            }
        })
    }

    /// Get list of IPs in the subnet
    fn get_subnet_ips(&self) -> anyhow::Result<Vec<IpAddr>> {
        // Parse subnet (e.g., "192.168.1.0/24")
        let parts: Vec<&str> = self.config.subnet.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid subnet format"));
        }

        let base_ip: Ipv4Addr = parts
            .first()
            .ok_or_else(|| anyhow::anyhow!("Invalid subnet"))?
            .parse()?;
        let prefix: u8 = parts
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("Invalid prefix"))?
            .parse()?;

        // Calculate number of hosts
        let host_bits = 32u8.saturating_sub(prefix);
        let num_hosts = 2u32.saturating_pow(u32::from(host_bits)).saturating_sub(2); // Exclude network and broadcast

        let base = u32::from(base_ip);
        let mut ips = Vec::new();

        // Generate IPs (skip first and last)
        for i in 1..=num_hosts.min(254) {
            let ip = Ipv4Addr::from(base.saturating_add(i));
            ips.push(IpAddr::V4(ip));
        }

        Ok(ips)
    }

    /// List available network interfaces with their subnets
    pub async fn list_interfaces() -> anyhow::Result<Vec<NetworkInterface>> {
        let output = tokio::process::Command::new("ip")
            .args(["-j", "-4", "addr", "show"])
            .output()
            .await?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to list interfaces"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries: Vec<IpAddrEntry> = serde_json::from_str(&stdout)?;

        let mut interfaces = Vec::new();
        for entry in entries {
            if entry.ifname == "lo" {
                continue;
            }

            for addr in entry.addr_info {
                if addr.family == "inet" && !addr.local.is_loopback() {
                    let octets = addr.local.octets();
                    // Calculate network address from IP and prefix length
                    // Simple approximation: assumes /24 for now if prefix logic is complex,
                    // but we can compute it properly.
                    // For simplicity in this demo, we'll construct the CIDR string.
                    let cidr = format!("{}/{}", addr.local, addr.prefixlen);

                    // Basic subnet calculation for /24 equivalence (typical home use)
                    // Just zeroing last octet for standard Class C
                    let subnet = format!(
                        "{}.{}.{}.0/{}",
                        octets[0], octets[1], octets[2], addr.prefixlen
                    );

                    interfaces.push(NetworkInterface {
                        name: entry.ifname.clone(),
                        ip: addr.local.to_string(),
                        cidr,
                        subnet,
                    });
                }
            }
        }

        Ok(interfaces)
    }
}

/// Network Interface Info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface name (e.g., "eth0")
    pub name: String,
    /// IP address of the interface
    pub ip: String,
    /// CIDR representation of the interface address
    pub cidr: String,
    /// Subnet derived from the CIDR
    pub subnet: String,
}

// Internal structs for parsing `ip -j addr`
#[derive(Deserialize)]
struct IpAddrEntry {
    ifname: String,
    addr_info: Vec<AddrInfo>,
}

#[derive(Deserialize)]
struct AddrInfo {
    family: String,
    local: Ipv4Addr,
    prefixlen: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_parsing() {
        let scanner = NetworkScanner::new(ScannerConfig {
            subnet: "192.168.1.0/24".to_string(),
            ..Default::default()
        });

        let ips = scanner.get_subnet_ips().unwrap();
        assert!(ips.len() > 0);
        assert!(ips.len() <= 254);
    }

    #[test]
    fn test_device_classification() {
        assert_eq!(
            NetworkScanner::classify_device(Some(&"router-home".to_string())),
            DeviceType::Router
        );
        assert_eq!(
            NetworkScanner::classify_device(Some(&"hp-printer-123".to_string())),
            DeviceType::Printer
        );
    }

    #[tokio::test]
    async fn test_list_interfaces() {
        // This test requires `ip` command which might not be available in all test environments
        if let Ok(interfaces) = NetworkScanner::list_interfaces().await {
            tracing::info!("Found interfaces: {:?}", interfaces);
            // Just check it doesn't crash
        }
    }
}
