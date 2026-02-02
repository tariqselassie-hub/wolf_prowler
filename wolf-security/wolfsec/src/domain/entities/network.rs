// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/entities/network.rs
use serde::{Deserialize, Serialize};

/// Definitive set of protection levels for network communications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Minimal protection, prioritizing performance and connectivity.
    Low,
    /// Balanced protection for general system use.
    Standard,
    /// Elevated protection, enforcing stricter verification.
    High,
    /// Maximum protection for extremely sensitive operational environments.
    Critical,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Standard
    }
}

/// Configuration parameters governing the security posture of the network layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    /// Current enforced protection level.
    pub level: SecurityLevel,
    /// Whether all traffic must be cryptographically protected.
    pub require_encryption: bool,
    /// Whether connections without prior authentication are permitted.
    pub allow_anonymous: bool,
    /// Rate limit for concurrent connections from a single IP address.
    pub max_connections_per_ip: u32,
}

impl Default for NetworkSecurityConfig {
    fn default() -> Self {
        Self {
            level: SecurityLevel::Standard,
            require_encryption: true,
            allow_anonymous: false,
            max_connections_per_ip: 10,
        }
    }
}

/// Real-time snapshot of the network security subsystem's operational state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityStatus {
    /// Total number of established network connections.
    pub active_connections: u32,
    /// Number of distinct IP addresses currently prohibited from connecting.
    pub blocked_ips: u32,
    /// The active security policy being enforced.
    pub current_level: SecurityLevel,
}
