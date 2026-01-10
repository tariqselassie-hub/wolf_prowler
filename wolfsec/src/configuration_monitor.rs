//! Configuration Monitor
//!
//! Monitors critical configuration files for unauthorized changes.
//! Computes checksums and periodically verifies file integrity.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::fs;
use tracing::{error, info, warn};

use crate::{SecurityEvent, SecurityEventType, SecuritySeverity};

/// Configuration Monitor
pub struct ConfigurationMonitor {
    /// Map of file paths to their last known checksums
    watched_files: HashMap<PathBuf, String>,
    /// Event bus to report violations
    event_bus: tokio::sync::broadcast::Sender<SecurityEvent>,
}

impl ConfigurationMonitor {
    /// Create a new Configuration Monitor
    pub fn new(event_bus: tokio::sync::broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            watched_files: HashMap::new(),
            event_bus,
        }
    }

    /// Add a file to be watched
    pub async fn watch_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            warn!("Configuration file not found: {:?}", path);
            return Ok(());
        }

        let checksum = self.compute_checksum(&path).await?;
        info!("Started monitoring config file: {:?} (Hash: {})", path, &checksum[..8]);
        self.watched_files.insert(path, checksum);
        Ok(())
    }

    /// Check all watched files for changes
    pub async fn check_files(&mut self) {
        let mut changes = Vec::new();

        for (path, last_checksum) in &self.watched_files {
            match self.compute_checksum(path).await {
                Ok(current_checksum) => {
                    if *last_checksum != current_checksum {
                        changes.push((path.clone(), current_checksum));
                    }
                }
                Err(e) => {
                    error!("Failed to check config file {:?}: {}", path, e);
                    // Report missing file or read error as integrity violation
                    self.report_violation(path, &format!("File access error: {}", e));
                }
            }
        }

        // Update checksums and report changes
        for (path, new_checksum) in changes {
            let msg = format!("Configuration file modified: {:?}", path);
            warn!("🚨 {}", msg);
            self.report_violation(&path, "Unauthorized Modification Detected");
            self.watched_files.insert(path, new_checksum);
        }
    }

    /// Compute SHA-256 checksum of a file
    async fn compute_checksum(&self, path: &Path) -> Result<String> {
        let content = fs::read(path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// Report a configuration violation
    fn report_violation(&self, path: &Path, details: &str) {
        let event = SecurityEvent::new(
            SecurityEventType::PolicyViolation,
            SecuritySeverity::High,
            format!("Configuration Integrity Violation: {:?} - {}", path, details),
        )
        .with_metadata("component".to_string(), "ConfigurationMonitor".to_string())
        .with_metadata("file".to_string(), format!("{:?}", path));

        if let Err(e) = self.event_bus.send(event) {
            error!("Failed to broadcast configuration violation: {}", e);
        }
    }
}
