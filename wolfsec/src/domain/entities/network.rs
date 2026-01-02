// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/entities/network.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    Low,
    Standard,
    High,
    Critical,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Standard
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    pub level: SecurityLevel,
    pub require_encryption: bool,
    pub allow_anonymous: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityStatus {
    pub active_connections: u32,
    pub blocked_ips: u32,
    pub current_level: SecurityLevel,
}
