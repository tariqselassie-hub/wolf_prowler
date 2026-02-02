use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SystemStats {
    pub volume_size: String,
    pub encrypted_sectors: f32,
    pub entropy: f32,
    pub db_status: String,
    pub active_nodes: usize,
    pub threat_level: String,
    pub active_alerts: usize,
    pub scanner_status: String,
    pub network_status: String,
    pub firewall: FirewallStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallStats {
    pub rules_count: usize,
    pub blocked_connections: usize,
    pub allowed_connections: usize,
}

impl Default for FirewallStats {
    fn default() -> Self {
        Self {
            rules_count: 0,
            blocked_connections: 0,
            allowed_connections: 0,
        }
    }
}
