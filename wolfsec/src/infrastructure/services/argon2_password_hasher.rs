// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/infrastructure/services/argon2_password_hasher.rs
use crate::application::services::password_hasher::PasswordHasher;
use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher as Argon2Hasher, PasswordVerifier,
        SaltString,
    },
    Argon2,
};
use async_trait::async_trait;

pub struct Argon2PasswordHasher;

impl Argon2PasswordHasher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Argon2PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PasswordHasher for Argon2PasswordHasher {
    async fn hash(&self, password: &str) -> anyhow::Result<String> {
        // Argon2 hashing is CPU intensive, so we run it in a blocking task
        let password = password.to_string();
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            Ok(password_hash.to_string())
        })
        .await?
    }

    async fn verify(&self, password: &str, hash: &str) -> anyhow::Result<bool> {
        let password = password.to_string();
        let hash = hash.to_string();
        tokio::task::spawn_blocking(move || {
            let parsed_hash =
                PasswordHash::new(&hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let argon2 = Argon2::default();
            Ok(argon2
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok())
        })
        .await?
    }
}
