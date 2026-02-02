// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/queries/crypto/hash_data.rs
use crate::application::error::ApplicationError;
use crate::application::services::CryptographyProvider;
use crate::domain::entities::crypto::HashedData;
use anyhow::Context;
use std::sync::Arc;

/// Query to hash a piece of data.
pub struct HashDataQuery {
    pub data: Vec<u8>,
}

/// Handler for the HashDataQuery.
pub struct HashDataHandler {
    crypto_provider: Arc<dyn CryptographyProvider>,
}

impl HashDataHandler {
    pub fn new(crypto_provider: Arc<dyn CryptographyProvider>) -> Self {
        Self { crypto_provider }
    }

    pub async fn handle(&self, query: HashDataQuery) -> Result<HashedData, ApplicationError> {
        let hashed_data = self
            .crypto_provider
            .hash(&query.data)
            .await
            .context("Failed to hash data")?;
        Ok(hashed_data)
    }
}
