use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;

/// Interface for system integrity monitoring
#[async_trait]
pub trait IntegrityMonitor: Send + Sync {
    /// Add a file path to be watched for changes
    async fn watch_file(&mut self, path: &Path) -> Result<()>;

    /// Verify integrity of all watched resources
    async fn check_integrity(&mut self);
}
