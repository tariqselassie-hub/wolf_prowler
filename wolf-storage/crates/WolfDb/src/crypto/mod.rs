/// AES-GCM symmetric encryption
pub mod aes;
/// Hardware Security Module integration (requires 'hsm' feature)
#[cfg(feature = "hsm")]
pub mod hsm;
/// Post-Quantum Key Encapsulation Mechanism (ML-KEM)
pub mod kem;
/// Secure keystore for managing master keys
pub mod keystore;
/// Post-Quantum Digital Signatures (ML-DSA)
pub mod signature;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Container for data encrypted at rest with PQC protections
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    /// KEM ciphertext used to encapsulate the session key
    pub kem_ciphertext: Vec<u8>,
    /// Symmetric ciphertext of the actual data
    pub ciphertext: Vec<u8>,
    /// Nonce used for symmetric encryption
    pub nonce: [u8; 12],
    /// Optional PQC integrity signature
    pub signature: Option<Vec<u8>>, // PQC integrity signature
}

/// Manager for cryptographic operations in `WolfDb`
#[derive(Clone, Copy)]
pub struct CryptoManager;

impl CryptoManager {
    /// Creates a new `CryptoManager`
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Encrypts data for storage using a KEM public key and optional DSA signing
    ///
    /// # Errors
    ///
    /// Returns an error if KEM encapsulation or symmetric encryption fails.
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
        let signature = dsa_keypair.map(|keys| signature::sign_with_keypair(keys, &ciphertext));

        Ok(EncryptedData {
            kem_ciphertext: kem_ct,
            nonce,
            ciphertext,
            signature,
        })
    }

    /// Decrypts data using a KEM secret key and verifies the optional DSA signature
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails (integrity violation) or if decryption fails.
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

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}
