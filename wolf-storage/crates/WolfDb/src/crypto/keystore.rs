use crate::crypto::aes;
use anyhow::{Context, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Type alias for unlocked keys: (KEM Secret, Optional DSA Secret)
pub type UnlockedKeys = (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>);

/// Secure storage for encrypted PQC keys and configuration
#[derive(Serialize, Deserialize)]
pub struct Keystore {
    /// Base64 encoded encrypted KEM secret key
    pub encrypted_sk: String, // KEM (B64)
    /// Raw KEM public key bytes
    pub pk: Vec<u8>, // KEM
    /// Optional Base64 encoded encrypted DSA secret key
    pub encrypted_dsa_sk: Option<String>, // DSA (B64)
    /// Optional raw DSA public key bytes
    pub dsa_pk: Option<Vec<u8>>, // DSA
    /// Salt used for password-based key derivation (Argon2)
    pub salt: String,
    #[serde(alias = "nonce")]
    /// Base64 encoded nonce for KEM secret key encryption
    pub kem_nonce: String, // B64
    /// Optional Base64 encoded nonce for DSA secret key encryption
    pub dsa_nonce: Option<String>, // B64
    /// Whether HSM wrapping is enabled for the master key
    pub hsm_enabled: bool,
    /// Optional Base64 encoded AES key wrapped by HSM
    pub hsm_wrapped_key: Option<String>, // B64 (AES key wrapped by HSM)
}

impl Keystore {
    /// Creates a new encrypted Keystore from raw PQC keys and a password
    ///
    /// # Errors
    ///
    /// Returns an error if password hashing or symmetric encryption fails.
    pub fn create_encrypted(
        kem_secret_key: &[u8],
        kem_public_key: &[u8],
        dsa_secret_key: &[u8],
        dsa_public_key: &[u8],
        password: &str,
    ) -> Result<Self> {
        let salt = SaltString::generate(&mut thread_rng());
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {e}"))?;

        let hash_output = password_hash.hash.context("No hash output")?;
        let hash_bytes = hash_output.as_bytes();
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(
            hash_bytes
                .get(..32)
                .ok_or_else(|| anyhow::anyhow!("Hash output too short"))?,
        );

        // Encrypt KEM secret key
        let (encrypted_kem, kem_nonce) = aes::encrypt(kem_secret_key, &master_key)?;

        // Encrypt DSA secret key
        let (encrypted_dsa, dsa_nonce) = aes::encrypt(dsa_secret_key, &master_key)?;

        Ok(Self {
            encrypted_sk: general_purpose::STANDARD.encode(encrypted_kem),
            encrypted_dsa_sk: Some(general_purpose::STANDARD.encode(encrypted_dsa)),
            salt: salt.as_str().to_owned(),
            pk: kem_public_key.to_vec(),
            dsa_pk: Some(dsa_public_key.to_vec()),
            kem_nonce: general_purpose::STANDARD.encode(kem_nonce),
            dsa_nonce: Some(general_purpose::STANDARD.encode(dsa_nonce)),
            hsm_enabled: false,
            hsm_wrapped_key: None,
        })
    }

    /// Decrypts the secret keys using the provided password
    ///
    /// # Errors
    ///
    /// Returns an error if password hashing fails, if salt is invalid, or if decryption fails.
    pub fn unlock_keys(&self, password: &str) -> Result<UnlockedKeys> {
        let salt = SaltString::from_b64(&self.salt)
            .map_err(|e| anyhow::anyhow!("Invalid salt in keystore: {e}"))?;
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {e}"))?;

        let hash_output = password_hash.hash.context("No hash output")?;
        let hash_bytes = hash_output.as_bytes();
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(
            hash_bytes
                .get(..32)
                .ok_or_else(|| anyhow::anyhow!("Hash output too short"))?,
        );

        let encrypted_kem_bin = general_purpose::STANDARD.decode(&self.encrypted_sk)?;
        let kem_nonce_bin = general_purpose::STANDARD.decode(&self.kem_nonce)?;

        let mut kem_nonce = [0u8; 12];
        kem_nonce.copy_from_slice(&kem_nonce_bin);
        let kem_secret_key_raw = aes::decrypt(&encrypted_kem_bin, &master_key, &kem_nonce)?;
        let kem_secret_key = Zeroizing::new(kem_secret_key_raw);

        let dsa_secret_key =
            if let (Some(enc_dsa), Some(dsa_n)) = (&self.encrypted_dsa_sk, &self.dsa_nonce) {
                let encrypted_dsa_bin = general_purpose::STANDARD.decode(enc_dsa)?;
                let dsa_nonce_bin = general_purpose::STANDARD.decode(dsa_n)?;
                let mut dsa_nonce = [0u8; 12];
                dsa_nonce.copy_from_slice(&dsa_nonce_bin);
                let dsa_sk_raw = aes::decrypt(&encrypted_dsa_bin, &master_key, &dsa_nonce)?;
                Some(Zeroizing::new(dsa_sk_raw))
            } else {
                None
            };

        Ok((kem_secret_key, dsa_secret_key))
    }

    /// Saves the keystore to a JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file writing fails, or if serialization fails.
    pub fn save(&self, path: &str) -> Result<()> {
        let bin = serde_json::to_vec(self)?;
        let mut file = File::create(path)?;
        file.write_all(&bin)?;
        Ok(())
    }

    /// Loads a keystore from a JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if file reading or deserialization fails.
    pub fn load(path: &str) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut bin = Vec::new();
        file.read_to_end(&mut bin)?;
        let keystore: Self = serde_json::from_slice(&bin)?;
        Ok(keystore)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn test_keystore_lifecycle() {
        let kem_secret = vec![1u8; 32];
        let kem_public = vec![2u8; 32];
        let dsa_secret = vec![3u8; 32];
        let dsa_public = vec![4u8; 32];
        let password = "WolfPassword123";

        let keystore = Keystore::create_encrypted(
            &kem_secret,
            &kem_public,
            &dsa_secret,
            &dsa_public,
            password,
        )
        .expect("Keystore creation failed");

        assert_eq!(keystore.pk, kem_public);
        assert_eq!(keystore.dsa_pk, Some(dsa_public));

        let (unlocked_kem, unlocked_dsa) = keystore.unlock_keys(password).expect("Unlock failed");

        assert_eq!(unlocked_kem.as_slice(), kem_secret.as_slice());
        assert!(unlocked_dsa.is_some());
        assert_eq!(unlocked_dsa.unwrap().as_slice(), dsa_secret.as_slice());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_keystore_wrong_password() {
        let kem_secret = vec![1u8; 32];
        let kem_public = vec![2u8; 32];
        let dsa_secret = vec![3u8; 32];
        let dsa_public = vec![4u8; 32];
        let password = "WolfPassword123";

        let keystore = Keystore::create_encrypted(
            &kem_secret,
            &kem_public,
            &dsa_secret,
            &dsa_public,
            password,
        )
        .expect("Keystore creation failed");

        let result = keystore.unlock_keys("WrongPassword");
        assert!(result.is_err());
    }
}
