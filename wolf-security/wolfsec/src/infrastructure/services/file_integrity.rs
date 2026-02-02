use anyhow::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::domain::services::integrity::IntegrityMonitor;
use crate::{SecurityEvent, SecurityEventType, SecuritySeverity};

/// File System based Integrity Monitor
pub struct FileIntegrityMonitor {
    /// Map of file paths to their last known checksums
    watched_files: HashMap<PathBuf, String>,
    /// Event bus to report violations
    event_bus: broadcast::Sender<SecurityEvent>,
}

impl FileIntegrityMonitor {
    /// Create a new File Integrity Monitor
    pub fn new(event_bus: broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            watched_files: HashMap::new(),
            event_bus,
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
            format!(
                "Configuration Integrity Violation: {:?} - {}",
                path, details
            ),
        )
        .with_metadata("component".to_string(), "FileIntegrityMonitor".to_string())
        .with_metadata("file".to_string(), format!("{:?}", path));

        if let Err(e) = self.event_bus.send(event) {
            error!("Failed to broadcast configuration violation: {}", e);
        }
    }
}

#[async_trait]
impl IntegrityMonitor for FileIntegrityMonitor {
    async fn watch_file(&mut self, path: &Path) -> Result<()> {
        let path = path.to_path_buf();
        if !path.exists() {
            warn!("Configuration file not found: {:?}", path);
            return Ok(());
        }

        let checksum = self.compute_checksum(&path).await?;
        info!(
            "Started monitoring config file: {:?} (Hash: {})",
            path,
            &checksum[..8]
        );
        self.watched_files.insert(path, checksum);
        Ok(())
    }

    async fn check_integrity(&mut self) {
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
}
