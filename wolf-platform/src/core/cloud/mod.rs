use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use anyhow::Result;
use std::collections::HashMap;

pub mod aws;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CloudResource {
    pub id: String,
    pub name: String,
    pub resource_type: String, // "EC2", "S3", etc.
    pub region: String,
    pub status: String,
    pub public_access: bool,
    pub tags: HashMap<String, String>,
    pub details: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CloudScanResult {
    pub provider: String,
    pub resources: Vec<CloudResource>,
    pub findings: Vec<SecurityFinding>,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SecurityFinding {
    pub severity: String, // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub title: String,
    pub description: String,
    pub resource_id: String,
}

#[async_trait]
pub trait CloudProvider: Send + Sync {
    /// Perform a security scan of the cloud environment
    async fn scan(&self) -> Result<CloudScanResult>;
    /// Get the connection status
    async fn status(&self) -> Result<String>;
}
