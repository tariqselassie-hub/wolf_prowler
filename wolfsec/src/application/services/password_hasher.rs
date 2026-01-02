use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait PasswordHasher: Send + Sync {
    async fn hash(&self, password: &str) -> Result<String>;
    async fn verify(&self, password: &str, hash: &str) -> Result<bool>;
}
