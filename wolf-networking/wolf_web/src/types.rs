use serde::{Deserialize, Serialize};

/// System statistics for dashboard display
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
    /// Firewall status information
    pub firewall: FirewallStats,
}

/// View model for a database record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordView {
    /// Unique record identifier
    pub id: String,
    /// JSON string of the record data
    pub data: String, // Scrubbed or raw JSON
    /// Whether the record has vector embedding
    pub has_vector: bool,
}

/// Firewall statistics and status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallStats {
    /// Whether the firewall is enabled
    pub enabled: bool,
    /// Default policy (Allow/Deny)
    pub policy: String,
    /// Number of active rules
    pub active_rules: usize,
    /// Number of blocked events
    pub blocked_count: usize,
    /// Active firewall rules
    pub rules: Vec<FirewallRuleView>,
    /// Recent firewall events
    pub recent_events: Vec<FirewallEventView>,
}

impl Default for FirewallStats {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: "Default".to_string(),
            active_rules: 0,
            blocked_count: 0,
            rules: Vec::new(),
            recent_events: Vec::new(),
        }
    }
}

/// View model for a firewall rule

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]

pub struct FirewallRuleView {
    /// Human-readable name
    pub name: String,

    /// Target of the rule (IP, Port, `PeerID`)
    pub target: String,

    /// Protocol (TCP, UDP, etc.)
    pub protocol: String,

    /// Action (Allow/Deny)
    pub action: String,

    /// Direction (Inbound/Outbound)
    pub direction: String,
}

/// View model for a firewall event

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]

pub struct FirewallEventView {
    /// Time of the event
    pub timestamp: String,

    /// Source of the traffic
    pub source: String,

    /// Action taken
    pub action: String,

    /// Reason for the action
    pub reason: String,
}

/// Telemetry data for the Wolf Pack system

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]

pub struct WolfPackTelemetry {
    /// The node's unique identifier
    pub node_id: String,

    /// Current Raft consensus state
    pub raft_state: String, // "Leader", "Follower", "Candidate"

    /// Current term number
    pub term: u64,

    /// Index of the last committed entry
    pub commit_index: u64,

    /// Timestamp of the last heartbeat
    pub last_heartbeat: String,

    /// List of connected peers
    pub peers: Vec<PeerStatus>,

    /// Overall network health score (0.0 - 1.0)
    pub network_health: f64,

    /// Active hunts
    pub active_hunts: Vec<ActiveHuntView>,

    /// Current role of the node
    pub role: String,

    /// Prestige score of the node
    pub prestige: u32,

    /// Aggregate reputation statistics
    pub reputation_stats: ReputationStats,
}

/// Statistics for the overall reputation of the network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ReputationStats {
    /// Average reputation score (0.0 - 1.0)
    pub average_score: f64,
    /// Number of highly trusted peers
    pub highly_trusted_count: usize,
    /// Number of trusted peers
    pub trusted_count: usize,
    /// Number of neutral peers
    pub neutral_count: usize,
    /// Number of suspicious peers
    pub suspicious_count: usize,
    /// Number of malicious peers
    pub malicious_count: usize,
}

/// Status of a peer in the Wolf Pack

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]

pub struct PeerStatus {
    /// Peer ID
    pub id: String,

    /// Connection status
    pub status: String, // "Active", "Unknown"

    /// Role in the pack
    pub role: String, // "Voter", "Learner"

    /// Round-trip time in milliseconds
    pub rtt_ms: u64,

    /// Reputation score (0.0 - 1.0)
    pub reputation: f64,

    /// Trust tier label (Highly Trusted, Trusted, etc.)
    pub reputation_tier: String,
}

/// View model for an active hunt

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]

pub struct ActiveHuntView {
    /// Unique hunt ID
    pub id: String,

    /// Target IP address
    pub target: String,

    /// Current status
    pub status: String,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,

    /// Start time
    pub start_time: String,
}

/// Compliance metric for dashboard

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]

pub struct ComplianceMetric {
    /// Name of the compliance control
    pub name: String,

    /// Status of the control (PASS, FAIL, WARN)
    pub status: String,

    /// Detailed description or reason
    pub details: String,
}
