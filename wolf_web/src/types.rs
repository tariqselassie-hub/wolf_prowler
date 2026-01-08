use serde::{Deserialize, Serialize};

/// System statistics for dashboard display
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemStats {
    /// Total size of the encrypted volume
    pub volume_size: String,
    /// Percentage of sectors encrypted
    pub encrypted_sectors: f32,
    /// System entropy level
    pub entropy: f32,
    /// Database connection status
    pub db_status: String,
    /// Number of active nodes in the network
    pub active_nodes: usize,
    /// Current threat level
    pub threat_level: String,
    /// Number of active alerts
    pub active_alerts: usize,
    /// Status of the background scanner
    pub scanner_status: String,
    /// Network connectivity status
    pub network_status: String,
}

/// View model for a database record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordView {
    /// Unique record identifier
    pub id: String,
    /// JSON string of the record data
    pub data: String, // Scrubbed or raw JSON
    /// Whether the record has vector embedding
    pub has_vector: bool,
}
