// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/commands/network/update_config.rs
use crate::application::error::ApplicationError;
use crate::domain::entities::network::NetworkSecurityConfig;
use crate::application::services::NetworkSecurityService;
use anyhow::Context;
use std::sync::Arc;

pub struct UpdateNetworkConfigCommand {
    pub config: NetworkSecurityConfig,
}

pub struct UpdateNetworkConfigHandler {
    service: Arc<dyn NetworkSecurityService>,
}

impl UpdateNetworkConfigHandler {
    pub fn new(service: Arc<dyn NetworkSecurityService>) -> Self {
        Self { service }
    }

    pub async fn handle(
        &self,
        command: UpdateNetworkConfigCommand,
    ) -> Result<(), ApplicationError> {
        self.service
            .update_config(command.config)
            .await
            .context("Failed to update network security configuration")?;
        Ok(())
    }
}
