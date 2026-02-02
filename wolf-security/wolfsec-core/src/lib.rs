//! WolfSec Core - Security Framework Orchestrator
//!
//! This crate provides the core types, interfaces, and orchestrator for the WolfSec security framework.
//! It defines the common security event types, severity levels, and integration patterns used
//! across all WolfSec modules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// Severity levels for security events
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecuritySeverity {
    /// Low impact event, informational
    Low,
    /// Minor issue needing attention
    Medium,
    /// Significant security risk
    High,
    /// Immediate threat or confirmed breach
    Critical,
}

/// Classification of security events
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityEventType {
    /// Failed login or identity check
    AuthenticationFailure,
    /// Access control violation
    AuthorizationFailure,
    /// Pattern suggesting malicious intent
    SuspiciousActivity,
    /// Cryptographic key likely leaked
    KeyCompromise,
    /// Unauthorized network access
    NetworkIntrusion,
    /// Deviation from security guidelines
    PolicyViolation,
    /// Unauthorized data extraction
    DataBreach,
    /// Virus or malicious software found
    MalwareDetected,
    /// Network service interruption attack
    DenialOfService,
    /// Scanning or probing activity
    Reconnaissance,
    /// Other unclassified events
    Other(String),
}

/// A discrete security incident or system audit log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique identifier for the event
    pub id: String,
    /// Point in time when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Classification of the security activity
    pub event_type: SecurityEventType,
    /// Criticality and urgency of the individual event
    pub severity: SecuritySeverity,
    /// Human-readable narrative explaining the incident context
    pub description: String,
    /// Optional identifier of a peer associated with the activity
    pub peer_id: Option<String>,
    /// Supplemental metadata providing technical or system context
    pub metadata: HashMap<String, String>,
}

impl SecurityEvent {
    /// Create a new security event with default metadata
    pub fn new(
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        description: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            severity,
            description,
            peer_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Associate a peer with the event
    pub fn with_peer(mut self, peer_id: String) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Add metadata to the event
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Core security orchestrator trait
///
/// This trait defines the interface that all security modules must implement
/// to integrate with the WolfSec framework.
#[async_trait::async_trait]
pub trait SecurityModule: Send + Sync {
    /// Get the module name
    fn name(&self) -> &'static str;

    /// Initialize the security module
    async fn initialize(&mut self) -> Result<(), SecurityError>;

    /// Process a security event
    async fn process_event(&mut self, event: &SecurityEvent) -> Result<(), SecurityError>;

    /// Get the current status of the module
    async fn status(&self) -> Result<ModuleStatus, SecurityError>;

    /// Shutdown the security module gracefully
    async fn shutdown(&mut self) -> Result<(), SecurityError>;
}

/// Status information for a security module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    /// Module name
    pub name: String,
    /// Current health status
    pub healthy: bool,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// Module-specific metrics
    pub metrics: HashMap<String, f64>,
    /// Current alerts or issues
    pub alerts: Vec<String>,
}

/// Security framework orchestrator
///
/// This struct coordinates all security modules and provides a unified
/// interface for security operations.
pub struct SecurityOrchestrator {
    modules: HashMap<String, Box<dyn SecurityModule>>,
    event_bus: tokio::sync::broadcast::Sender<SecurityEvent>,
}

impl SecurityOrchestrator {
    /// Create a new security orchestrator
    pub fn new() -> Self {
        let (event_bus, _) = tokio::sync::broadcast::channel(1000);
        Self {
            modules: HashMap::new(),
            event_bus,
        }
    }

    /// Register a security module
    pub fn register_module(&mut self, module: Box<dyn SecurityModule>) -> Result<(), SecurityError> {
        let name = module.name().to_string();
        if self.modules.contains_key(&name) {
            return Err(SecurityError::ModuleAlreadyRegistered(name));
        }
        self.modules.insert(name, module);
        Ok(())
    }

    /// Initialize all registered modules
    pub async fn initialize_all(&mut self) -> Result<(), SecurityError> {
        for module in self.modules.values_mut() {
            module.initialize().await?;
        }
        Ok(())
    }

    /// Process an event through all modules
    pub async fn process_event(&mut self, event: SecurityEvent) -> Result<(), SecurityError> {
        // Broadcast to event bus
        let _ = self.event_bus.send(event.clone());

        // Process through all modules
        for module in self.modules.values_mut() {
            module.process_event(&event).await?;
        }
        Ok(())
    }

    /// Get status of all modules
    pub async fn status_all(&self) -> Result<HashMap<String, ModuleStatus>, SecurityError> {
        let mut status = HashMap::new();
        for (name, module) in &self.modules {
            status.insert(name.clone(), module.status().await?);
        }
        Ok(status)
    }

    /// Shutdown all modules
    pub async fn shutdown_all(&mut self) -> Result<(), SecurityError> {
        for module in self.modules.values_mut() {
            module.shutdown().await?;
        }
        Ok(())
    }

    /// Subscribe to security events
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<SecurityEvent> {
        self.event_bus.subscribe()
    }
}

impl Default for SecurityOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

/// WolfSec error types
#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Module '{0}' is already registered")]
    ModuleAlreadyRegistered(String),

    #[error("Module '{0}' not found")]
    ModuleNotFound(String),

    #[error("Initialization failed: {0}")]
    InitializationError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Processing error: {0}")]
    ProcessingError(String),

    #[error("Shutdown error: {0}")]
    ShutdownError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent::new(
            SecurityEventType::AuthenticationFailure,
            SecuritySeverity::High,
            "Failed login attempt".to_string(),
        )
        .with_peer("malicious-peer".to_string())
        .with_metadata("source_ip".to_string(), "192.168.1.100".to_string());

        assert_eq!(event.severity, SecuritySeverity::High);
        assert_eq!(event.peer_id, Some("malicious-peer".to_string()));
        assert_eq!(
            event.metadata.get("source_ip"),
            Some(&"192.168.1.100".to_string())
        );
    }

    #[test]
    fn test_security_orchestrator_creation() {
        let orchestrator = SecurityOrchestrator::new();
        assert!(orchestrator.modules.is_empty());
    }
}