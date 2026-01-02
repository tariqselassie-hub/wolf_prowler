// FILE: src/core/defaults.rs
// Default configuration values for Wolf Prowler

/// Default network port
pub const DEFAULT_PORT: u16 = 3030;

/// Default dashboard port  
pub const DEFAULT_DASHBOARD_PORT: u16 = 3031;

/// Default maximum number of peers
pub const MAX_PEERS: usize = 50;

/// Default heartbeat interval in seconds
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Default connection timeout in seconds
pub const CONNECTION_TIMEOUT_SECS: u64 = 10;

/// Default message buffer size
pub const MESSAGE_BUFFER_SIZE: usize = 1024;

/// Default trust score threshold
pub const TRUST_THRESHOLD: f64 = 0.5;

/// Default reputation decay rate
pub const REPUTATION_DECAY_RATE: f64 = 0.01;
