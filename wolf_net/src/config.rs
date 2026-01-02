//! Configuration management for Wolf Net.

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

/// Main configuration structure for Wolf Net.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfConfig {
    /// Network configuration.
    pub network: NetworkConfig,
    /// Discovery configuration.
    pub discovery: DiscoveryConfig,
}

/// Network-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Port to listen on (0 for random).
    pub listen_port: u16,
    /// Maximum number of concurrent connections.
    pub max_connections: usize,
    /// Bootstrap nodes for P2P discovery.
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Enable SaaS integration features.
    pub enable_saas_features: bool,
    /// URL of the Central SaaS Hub.
    pub hub_url: String,
    /// Organization ID for multi-tenancy.
    pub org_id: String,
    /// API Key for Hub authentication.
    pub api_key: String,
    /// Unique Agent ID.
    pub agent_id: String,
    /// Run in headless mode (no UI).
    pub headless_mode: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            max_connections: 50,
            bootstrap_peers: Vec::new(),
            enable_saas_features: false,
            hub_url: "https://hub.wolfprowler.com".to_string(),
            org_id: String::new(),
            api_key: String::new(),
            agent_id: String::new(),
            headless_mode: false,
        }
    }
}

/// Discovery-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable mDNS discovery.
    pub enable_mdns: bool,
    /// Enable DHT discovery.
    pub enable_dht: bool,
    /// Enable active port scanning.
    pub enable_active_scan: bool,
    /// Discovery interval in seconds.
    pub discovery_interval_secs: u64,
    /// Peer timeout in seconds.
    pub peer_timeout_secs: u64,
    /// Maximum peers to maintain.
    pub max_peers: usize,
    /// Ports to scan for active discovery.
    pub scan_ports: Vec<u16>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            enable_dht: true,
            enable_active_scan: false,
            discovery_interval_secs: 30,
            peer_timeout_secs: 300,
            max_peers: 1000,
            scan_ports: vec![8080, 8081, 8082, 8083, 8084, 8085],
        }
    }
}

impl WolfConfig {
    /// Creates a new default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads configuration from a JSON file.
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let config = serde_json::from_reader(reader)?;
        Ok(config)
    }

    /// Saves configuration to a JSON file.
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> anyhow::Result<()> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn test_save_and_load_config() {
        let mut path = std::env::temp_dir();
        path.push(format!("wolf_net_test_config_{}.json", Uuid::new_v4()));

        let mut config = WolfConfig::default();
        config.network.listen_port = 12345;

        assert!(config.save_to_file(&path).is_ok());

        let loaded = WolfConfig::load_from_file(&path).expect("Failed to load config");
        assert_eq!(loaded.network.listen_port, 12345);

        let _ = fs::remove_file(path);
    }
}
