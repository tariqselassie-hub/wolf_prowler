// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/domain/services/network_security.rs
use crate::domain::entities::network::{NetworkSecurityConfig, NetworkSecurityStatus};
use crate::domain::error::DomainError;
use async_trait::async_trait;

/// A domain service trait defining network security operations.
#[async_trait]
pub trait NetworkSecurityService: Send + Sync {
    async fn update_config(&self, config: NetworkSecurityConfig) -> Result<(), DomainError>;
    async fn get_status(&self) -> Result<NetworkSecurityStatus, DomainError>;
    async fn block_ip(&self, ip: &str) -> Result<(), DomainError>;
    async fn unblock_ip(&self, ip: &str) -> Result<(), DomainError>;
}
