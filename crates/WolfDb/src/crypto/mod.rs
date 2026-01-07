pub mod aes;
pub mod hsm;
pub mod kem;
pub mod keystore;
pub mod signature;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    pub kem_ciphertext: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub signature: Option<Vec<u8>>, // PQC integrity signature
}

pub struct CryptoManager;

impl CryptoManager {
    pub fn new() -> Self {
        Self
    }

    pub fn encrypt_at_rest(
        &self,
        data: &[u8],
        kem_pk: &[u8],
        dsa_keypair: Option<&signature::Keypair>,
    ) -> Result<EncryptedData> {
        // 1. Encapsulate session key
        let (kem_ct, session_key) = kem::encapsulate_key(kem_pk)?;

        // 2. Encrypt data with AES-GCM using session key
        let (ciphertext, nonce) = aes::encrypt(data, &session_key)?;

        // 3. Optional: Sign for integrity
        let mut signature = None;
        if let Some(keys) = dsa_keypair {
            signature = Some(signature::sign_with_keypair(keys, &ciphertext));
        }

        Ok(EncryptedData {
            kem_ciphertext: kem_ct,
            nonce,
            ciphertext,
            signature,
        })
    }

    pub fn decrypt_at_rest(
        &self,
        encrypted: &EncryptedData,
        kem_sk: &[u8],
        dsa_pk: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // 1. Verify integrity if signature is present
        if let (Some(sig), Some(pk)) = (&encrypted.signature, dsa_pk) {
            if !signature::verify_signature(&encrypted.ciphertext, sig, pk)? {
                return Err(anyhow::anyhow!(
                    "PQC Data Integrity Violation: Signature mismatch"
                ));
            }
        }

        // 2. Decapsulate session key
        let session_key = kem::decapsulate_key(&encrypted.kem_ciphertext, kem_sk)?;

        // 3. Decrypt data
        let plaintext = aes::decrypt(&encrypted.ciphertext, &session_key, &encrypted.nonce)?;

        Ok(plaintext)
    }
}
