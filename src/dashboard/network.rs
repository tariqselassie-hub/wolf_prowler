use serde::{Deserialize, Serialize};

/// Response struct for the network topology API endpoint.
/// This structure is designed to be consumed by the frontend visualization.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkTopologyResponse {
    /// The local node's ID, useful for highlighting the current node.
    pub local_node_id: String,
    /// List of all known nodes (including local).
    pub nodes: Vec<NetworkNode>,
    /// List of active connections between nodes.
    pub links: Vec<NetworkLink>,
    /// Global network metrics for the dashboard summary.
    pub metrics: NetworkOverview,
    /// Detailed topology information using extended node/link structures
    pub detailed_topology: Option<DetailedTopology>,
}

/// Represents a node in the network visualization.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkNode {
    pub id: String,
    pub label: String,             // Short ID or name
    pub role: String,              // "Alpha", "Beta", "Omega", "Unknown"
    pub status: String,            // "Online", "Offline", "Unknown"
    pub last_seen: Option<String>, // ISO timestamp
    pub version: Option<String>,
    pub addresses: Option<Vec<String>>,
}

/// Represents a connection between nodes.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkLink {
    pub source: String,
    pub target: String,
    pub latency: Option<u64>,
    pub protocol: Option<String>,
}

/// High-level network statistics.
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkOverview {
    pub total_peers: usize,
    pub active_connections: usize,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DialRequest {
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkMetricsResponse {
    pub overall_health_score: f64,
    pub node_metrics: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeTopology {
    // Placeholder for node topology data if distinct from NetworkNode
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeLink {
    // Placeholder for node link if distinct from NetworkLink
    pub from: String,
    pub to: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DetailedTopology {
    pub nodes: Vec<NodeTopology>,
    pub links: Vec<NodeLink>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub id: String,
    pub address: Vec<String>,
    pub status: String,
    pub last_seen: String,
}
