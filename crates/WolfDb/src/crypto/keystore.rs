use crate::crypto::aes;
use anyhow::{Context, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use base64::{Engine as _, engine::general_purpose};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
pub struct Keystore {
    pub encrypted_sk: String,     // KEM (B64)
    pub pk: Vec<u8>,              // KEM
    pub encrypted_dsa_sk: Option<String>, // DSA (B64)
    pub dsa_pk: Option<Vec<u8>>,          // DSA
    pub salt: String,
    #[serde(alias = "nonce")]
    pub kem_nonce: String, // B64
    pub dsa_nonce: Option<String>, // B64
    pub hsm_enabled: bool,
    pub hsm_wrapped_key: Option<String>, // B64 (AES key wrapped by HSM)
}

impl Keystore {
    pub fn create_encrypted(
        kem_sk: &[u8],
        kem_pk: &[u8],
        dsa_sk: &[u8],
        dsa_pk: &[u8],
        password: &str,
    ) -> Result<Keystore> {
        let salt = SaltString::generate(&mut thread_rng());
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

        let hash_output = password_hash.hash.context("No hash output")?;
        let hash_bytes = hash_output.as_bytes();
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&hash_bytes[..32]);

        // Encrypt KEM secret key
        let (encrypted_kem, kem_nonce) = aes::encrypt(kem_sk, &master_key)?;

        // Encrypt DSA secret key
        let (encrypted_dsa, dsa_nonce) = aes::encrypt(dsa_sk, &master_key)?;

        Ok(Keystore {
            encrypted_sk: general_purpose::STANDARD.encode(encrypted_kem),
            encrypted_dsa_sk: Some(general_purpose::STANDARD.encode(encrypted_dsa)),
            salt: salt.as_str().to_owned(),
            pk: kem_pk.to_vec(),
            dsa_pk: Some(dsa_pk.to_vec()),
            kem_nonce: general_purpose::STANDARD.encode(kem_nonce),
            dsa_nonce: Some(general_purpose::STANDARD.encode(dsa_nonce)),
            hsm_enabled: false,
            hsm_wrapped_key: None,
        })
    }

    pub fn unlock_keys(
        keystore: &Keystore,
        password: &str,
    ) -> Result<(Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>)> {
        let salt = SaltString::from_b64(&keystore.salt)
            .map_err(|e| anyhow::anyhow!("Invalid salt in keystore: {}", e))?;
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

        let hash_output = password_hash.hash.context("No hash output")?;
        let hash_bytes = hash_output.as_bytes();
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&hash_bytes[..32]);

        let encrypted_kem_bin = general_purpose::STANDARD.decode(&keystore.encrypted_sk)?;
        let kem_nonce_bin = general_purpose::STANDARD.decode(&keystore.kem_nonce)?;

        let mut kem_nonce = [0u8; 12];
        kem_nonce.copy_from_slice(&kem_nonce_bin);
        let kem_sk = aes::decrypt(&encrypted_kem_bin, &master_key, &kem_nonce)?;
        let kem_sk = Zeroizing::new(kem_sk);

        let dsa_sk = if let (Some(enc_dsa), Some(dsa_n)) = (&keystore.encrypted_dsa_sk, &keystore.dsa_nonce) {
             let encrypted_dsa_bin = general_purpose::STANDARD.decode(enc_dsa)?;
             let dsa_nonce_bin = general_purpose::STANDARD.decode(dsa_n)?;
             let mut dsa_nonce = [0u8; 12];
             dsa_nonce.copy_from_slice(&dsa_nonce_bin);
             let dsa_sk_raw = aes::decrypt(&encrypted_dsa_bin, &master_key, &dsa_nonce)?;
             Some(Zeroizing::new(dsa_sk_raw))
        } else {
            None
        };

        Ok((kem_sk, dsa_sk))
    }

    pub fn save(keystore: &Keystore, path: &str) -> Result<()> {
        let bin = serde_json::to_vec(keystore)?;
        let mut file = File::create(path)?;
        file.write_all(&bin)?;
        Ok(())
    }

    pub fn load(path: &str) -> Result<Keystore> {
        let mut file = File::open(path)?;
        let mut bin = Vec::new();
        file.read_to_end(&mut bin)?;
        let keystore: Keystore = serde_json::from_slice(&bin)?;
        Ok(keystore)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_lifecycle() {
        let kem_sk = vec![1u8; 32];
        let kem_pk = vec![2u8; 32];
        let dsa_sk = vec![3u8; 32];
        let dsa_pk = vec![4u8; 32];
        let password = "WolfPassword123";

        let keystore = Keystore::create_encrypted(&kem_sk, &kem_pk, &dsa_sk, &dsa_pk, password)
            .expect("Keystore creation failed");

        assert_eq!(keystore.pk, kem_pk);
        assert_eq!(keystore.dsa_pk, Some(dsa_pk.clone()));

        let (unlocked_kem, unlocked_dsa) =
            Keystore::unlock_keys(&keystore, password).expect("Unlock failed");

        assert_eq!(unlocked_kem.as_slice(), kem_sk.as_slice());
        assert!(unlocked_dsa.is_some());
        assert_eq!(unlocked_dsa.unwrap().as_slice(), dsa_sk.as_slice());
    }

    #[test]
    fn test_keystore_wrong_password() {
        let kem_sk = vec![1u8; 32];
        let kem_pk = vec![2u8; 32];
        let dsa_sk = vec![3u8; 32];
        let dsa_pk = vec![4u8; 32];
        let password = "WolfPassword123";

        let keystore = Keystore::create_encrypted(&kem_sk, &kem_pk, &dsa_sk, &dsa_pk, password)
            .expect("Keystore creation failed");

        let result = Keystore::unlock_keys(&keystore, "WrongPassword");
        assert!(result.is_err());
    }
}
