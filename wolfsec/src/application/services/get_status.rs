// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/queries/network/get_status.rs
use crate::application::error::ApplicationError;
use crate::application::services::NetworkSecurityService;
use crate::domain::entities::network::NetworkSecurityStatus;
use anyhow::Context;
use std::sync::Arc;

pub struct GetNetworkStatusQuery;

pub struct GetNetworkStatusHandler {
    service: Arc<dyn NetworkSecurityService>,
}

impl GetNetworkStatusHandler {
    pub fn new(service: Arc<dyn NetworkSecurityService>) -> Self {
        Self { service }
    }

    pub async fn handle(
        &self,
        _query: GetNetworkStatusQuery,
    ) -> Result<NetworkSecurityStatus, ApplicationError> {
        let status = self
            .service
            .get_status()
            .await
            .context("Failed to get network security status")?;
        Ok(status)
    }
}
