use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secure wrapper for a password hash string.
///
/// The internal string is the PHC string format, e.g.,
/// "$argon2id$v=19$m=19456,t=2,p=1$SALT$HASH"
/// It implements `ZeroizeOnDrop` to clear the hash from memory when it goes out of scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PasswordHashString(String);

impl PasswordHashString {
    /// Provides read-only access to the underlying hash string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct AuthConfig {
    // Add fields as needed, e.g.,
    // pub require_mfa: bool,
}

/// Manages user authentication tasks like password hashing and verification.
pub struct AuthManager {
    config: AuthConfig,
    repository: std::sync::Arc<dyn crate::domain::repositories::AuthRepository>,
}

impl std::ops::Deref for AuthManager {
    type Target = AuthConfig;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl AuthManager {
    /// Creates a new `AuthManager`.
    pub fn new(
        config: AuthConfig,
        repository: std::sync::Arc<dyn crate::domain::repositories::AuthRepository>,
    ) -> Self {
        Self { config, repository }
    }

    /// Hashes a password using Argon2id with default recommended parameters.
    ///
    /// This is a CPU-intensive operation and is executed on a blocking thread
    /// to avoid stalling the async runtime.
    ///
    /// # Arguments
    /// * `password` - The plaintext password to hash.
    ///
    /// # Returns
    /// A `Result` containing the securely hashed password as a `PasswordHashString`.
    pub async fn hash_password(&self, password: &[u8]) -> Result<PasswordHashString> {
        let password_bytes = password.to_vec(); // Clone password to move into the thread

        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();

            let password_hash = argon2
                .hash_password(&password_bytes, &salt)
                .map_err(|e| anyhow!("Failed to hash password with Argon2: {}", e))?
                .to_string();

            Ok(PasswordHashString(password_hash))
        })
        .await?
    }

    /// Initialize the authentication manager
    pub async fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    /// Shutdown the authentication manager
    pub async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }

    /// Get authentication status
    pub fn get_status(&self) -> AuthStatus {
        AuthStatus {
            active_sessions: 0,
            total_users: 0,
            auth_failures: 0,
        }
    }

    /// Verifies a plaintext password against a stored Argon2id hash.
    ///
    /// This is a CPU-intensive operation and is executed on a blocking thread.
    ///
    /// # Arguments
    /// * `password` - The plaintext password to verify.
    /// * `hash` - The stored `PasswordHashString` to verify against.
    ///
    /// # Returns
    /// A `Result<bool>` which is `true` if the password is valid, and `false` otherwise.
    /// An `Err` is returned if the hash is malformed or another error occurs.
    pub async fn verify_password(
        &self,
        password: &[u8],
        hash: &PasswordHashString,
    ) -> Result<bool> {
        let hash_str = hash.0.clone();
        let password_bytes = password.to_vec();

        tokio::task::spawn_blocking(move || {
            let parsed_hash = PasswordHash::new(&hash_str)
                .map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;

            match Argon2::default().verify_password(&password_bytes, &parsed_hash) {
                Ok(_) => Ok(true),
                Err(argon2::password_hash::Error::Password) => Ok(false), // Password does not match
                Err(e) => Err(anyhow!("Password verification failed: {}", e)), // Other error
            }
        })
        .await?
    }
}

/// User representation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub roles: Vec<Role>,
    pub permissions: Vec<Permission>,
}

/// Role representation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
    Auditor,
    System,
}

/// Permission representation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum Permission {
    Read,
    Write,
    Execute,
    Admin,
}

/// Authentication status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthStatus {
    pub active_sessions: usize,
    pub total_users: usize,
    pub auth_failures: u64,
}

#[cfg(test)]
mod tests {
    use crate::domain::repositories::AuthRepository;

    use super::*;

    #[tokio::test]
    async fn test_password_hashing_and_verification_roundtrip() {
        let manager = AuthManager::new(
            AuthConfig::default(),
            Arc::new(crate::domain::repositories::AuthRepository),
        );
        let password = b"my_s3cur3_p@ssw0rd_for_wolf_prowler!";

        // 1. Hash the password
        let password_hash = manager.hash_password(password).await.unwrap();
        assert!(!password_hash.as_str().is_empty());

        // 2. Verify the correct password succeeds
        let is_valid = manager
            .verify_password(password, &password_hash)
            .await
            .unwrap();
        assert!(
            is_valid,
            "Verification should succeed for the correct password"
        );

        // 3. Verify an incorrect password fails
        let wrong_password = b"incorrect-password";
        let is_invalid = manager
            .verify_password(wrong_password, &password_hash)
            .await
            .unwrap();
        assert!(
            !is_invalid,
            "Verification should fail for the wrong password"
        );
    }
}
