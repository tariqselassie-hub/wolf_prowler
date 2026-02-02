// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/commands/crypto/encrypt_data.rs
use crate::application::error::ApplicationError;
use crate::application::services::CryptographyProvider;
use crate::domain::entities::crypto::{EncryptedData, SecretKey};
use anyhow::Context;
use std::sync::Arc;

/// Command to encrypt a piece of data.
pub struct EncryptDataCommand {
    pub plaintext: Vec<u8>,
    pub key: SecretKey,
}

/// Handler for the EncryptDataCommand.
pub struct EncryptDataHandler {
    crypto_provider: Arc<dyn CryptographyProvider>,
}

impl EncryptDataHandler {
    pub fn new(crypto_provider: Arc<dyn CryptographyProvider>) -> Self {
        Self { crypto_provider }
    }

    pub async fn handle(
        &self,
        command: EncryptDataCommand,
    ) -> Result<EncryptedData, ApplicationError> {
        let encrypted_data = self
            .crypto_provider
            .encrypt(&command.plaintext, &command.key)
            .await
            .context("Failed to encrypt data")?;
        Ok(encrypted_data)
    }
}
