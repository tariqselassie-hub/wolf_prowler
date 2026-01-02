use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfEcosystemMetrics {
    pub health: f64,
    pub active_threats: u64,
    pub connected_peers: u64,
    pub system_load: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfOperation {
    pub id: String,
    pub op_type: String,
    pub status: OperationStatus,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationStatus {
    Pending,
    Active,
    Completed,
    Failed,
    Cancelled,
}
