// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/services/password_hasher.rs
use async_trait::async_trait;
use std::error::Error;

/// An application service trait for hashing and verifying passwords.
/// The concrete implementation (e.g., using Argon2) belongs in the infrastructure layer.
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    async fn hash(&self, password: &str) -> Result<String, Box<dyn Error + Send + Sync>>;
    async fn verify(
        &self,
        password: &str,
        hash: &str,
    ) -> Result<bool, Box<dyn Error + Send + Sync>>;
}
