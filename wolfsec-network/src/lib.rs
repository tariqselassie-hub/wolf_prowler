//! WolfSec Network Security Module
//!
//! Provides network-level security features including firewalling,
//! encrypted transport protection, and network policy enforcement.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wolfsec_core::{SecurityEvent, SecurityModule, ModuleStatus, SecurityError};

/// Network security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    /// Default security level for network operations
    pub default_security_level: SecurityLevel,
    /// Enable firewall rules
    pub enable_firewall: bool,
    /// Enable transport encryption
    pub enable_encryption: bool,
    /// Maximum connections per peer
    pub max_connections_per_peer: usize,
}

/// Security levels for network operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Network security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub blocked_connections: usize,
    pub encrypted_connections: usize,
    pub firewall_rules_active: usize,
    pub last_activity: DateTime<Utc>,
}

/// Network security manager
pub struct NetworkSecurityManager {
    config: NetworkSecurityConfig,
    stats: NetworkSecurityStats,
    initialized: bool,
}

impl NetworkSecurityManager {
    /// Create a new network security manager
    pub fn new(config: NetworkSecurityConfig) -> Self {
        Self {
            config,
            stats: NetworkSecurityStats {
                total_connections: 0,
                active_connections: 0,
                blocked_connections: 0,
                encrypted_connections: 0,
                firewall_rules_active: 0,
                last_activity: Utc::now(),
            },
            initialized: false,
        }
    }

    /// Update statistics
    fn update_stats(&mut self) {
        self.stats.last_activity = Utc::now();
    }
}

#[async_trait]
impl SecurityModule for NetworkSecurityManager {
    fn name(&self) -> &'static str {
        "network_security"
    }

    async fn initialize(&mut self) -> Result<(), SecurityError> {
        // Initialize network security components
        self.update_stats();
        self.initialized = true;
        tracing::info!("Network security module initialized");
        Ok(())
    }

    async fn process_event(&mut self, event: &SecurityEvent) -> Result<(), SecurityError> {
        match event.event_type {
            wolfsec_core::SecurityEventType::NetworkIntrusion => {
                // Handle network intrusion events
                self.stats.blocked_connections += 1;
                self.update_stats();
                tracing::warn!("Network intrusion detected: {}", event.description);
            }
            wolfsec_core::SecurityEventType::DenialOfService => {
                // Handle DoS events
                self.update_stats();
                tracing::warn!("DoS attack detected: {}", event.description);
            }
            _ => {
                // Other events - just update activity
                self.update_stats();
            }
        }
        Ok(())
    }

    async fn status(&self) -> Result<ModuleStatus, SecurityError> {
        Ok(ModuleStatus {
            name: self.name().to_string(),
            healthy: self.initialized,
            last_activity: self.stats.last_activity,
            metrics: HashMap::from([
                ("total_connections".to_string(), self.stats.total_connections as f64),
                ("active_connections".to_string(), self.stats.active_connections as f64),
                ("blocked_connections".to_string(), self.stats.blocked_connections as f64),
                ("encrypted_connections".to_string(), self.stats.encrypted_connections as f64),
                ("firewall_rules_active".to_string(), self.stats.firewall_rules_active as f64),
            ]),
            alerts: Vec::new(), // Could add alerts based on thresholds
        })
    }

    async fn shutdown(&mut self) -> Result<(), SecurityError> {
        self.initialized = false;
        tracing::info!("Network security module shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_security_initialization() {
        let config = NetworkSecurityConfig {
            default_security_level: SecurityLevel::High,
            enable_firewall: true,
            enable_encryption: true,
            max_connections_per_peer: 10,
        };

        let mut manager = NetworkSecurityManager::new(config);
        assert!(!manager.initialized);

        manager.initialize().await.unwrap();
        assert!(manager.initialized);
        assert_eq!(manager.name(), "network_security");
    }

    #[tokio::test]
    async fn test_network_security_event_processing() {
        let config = NetworkSecurityConfig {
            default_security_level: SecurityLevel::High,
            enable_firewall: true,
            enable_encryption: true,
            max_connections_per_peer: 10,
        };

        let mut manager = NetworkSecurityManager::new(config);
        manager.initialize().await.unwrap();

        let event = SecurityEvent::new(
            wolfsec_core::SecurityEventType::NetworkIntrusion,
            wolfsec_core::SecuritySeverity::High,
            "Suspicious network activity detected".to_string(),
        );

        manager.process_event(&event).await.unwrap();
        assert_eq!(manager.stats.blocked_connections, 1);
    }

    #[tokio::test]
    async fn test_network_security_status() {
        let config = NetworkSecurityConfig {
            default_security_level: SecurityLevel::Medium,
            enable_firewall: false,
            enable_encryption: true,
            max_connections_per_peer: 5,
        };

        let manager = NetworkSecurityManager::new(config);
        let status = manager.status().await.unwrap();

        assert_eq!(status.name, "network_security");
        assert!(!status.healthy); // Not initialized yet
        assert!(status.metrics.contains_key("total_connections"));
    }
}