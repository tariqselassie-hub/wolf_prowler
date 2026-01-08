use serde::{Deserialize, Serialize};

/// Metrics representing the health and state of the Wolf Ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfEcosystemMetrics {
    /// Overall health score (0.0 - 1.0).
    pub health: f64,
    /// Number of currently active security threats.
    pub active_threats: u64,
    /// Number of connected peers in the network.
    pub connected_peers: u64,
    /// Current system load/utilization.
    pub system_load: f64,
}

/// Represents a security or system operation within the ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfOperation {
    /// Unique identifier for the operation.
    pub id: String,
    /// Type of operation (e.g., "Scanning", "Rotation").
    pub op_type: String,
    /// Current status of the operation.
    pub status: OperationStatus,
    /// Human-readable description.
    pub description: String,
}

/// Status of a Wolf Ecosystem operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationStatus {
    /// Operation is scheduled but hasn't started
    Pending,
    /// Operation is currently running
    Active,
    /// Operation successfully finished
    Completed,
    /// Operation failed to complete
    Failed,
    /// Operation was manually aborted
    Cancelled,
}
