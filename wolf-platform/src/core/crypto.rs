//! Cryptographic engine for Wolf Prowler

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use arrayref::array_ref;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as ChaChaKeyInit};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use hmac::Hmac;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use x25519_dalek::{EphemeralPublic, SharedSecret, StaticSecret as EphemeralSecret};
use zeroize::Zeroize;

/// Cryptographic engine providing identity, encryption, and signing
pub struct CryptoEngine {
    /// Ed25519 keypair for signing
    signing_keypair: Keypair,
    /// X25519 keypair for key exchange
    exchange_keypair: x25519_dalek::EphemeralSecret,
}

/// Encrypted message with metadata
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
    /// Authentication tag
    pub tag: Vec<u8>,
    /// Sender's public key
    pub sender_public_key: Vec<u8>,
}

/// Digital signature
#[derive(Debug, Clone)]
pub struct DigitalSignature {
    /// Signature bytes
    pub signature: Vec<u8>,
    /// Signer's public key
    pub public_key: Vec<u8>,
}

impl CryptoEngine {
    /// Create a new cryptographic engine with fresh keys
    pub fn new() -> Result<Self> {
        let signing_keypair = Keypair::generate(&mut rand::rngs::OsRng);
        let exchange_keypair =
            x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);

        Ok(Self {
            signing_keypair,
            exchange_keypair,
        })
    }

    /// Create from existing seed
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let signing_keypair = Keypair::from_seed(
            &seed[..32]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid seed length"))?,
        )?;
        let exchange_keypair = x25519_dalek::EphemeralSecret::from_bytes(seed);

        Ok(Self {
            signing_keypair,
            exchange_keypair,
        })
    }

    /// Get the public key for signing
    pub fn signing_public_key(&self) -> Vec<u8> {
        self.signing_keypair.public.as_bytes().to_vec()
    }

    /// Get the public key for key exchange
    pub fn exchange_public_key(&self) -> Vec<u8> {
        x25519_dalek::PublicKey::from(&self.exchange_keypair)
            .as_bytes()
            .to_vec()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<DigitalSignature> {
        let signature = self.signing_keypair.sign(message);
        Ok(DigitalSignature {
            signature: signature.to_bytes().to_vec(),
            public_key: self.signing_public_key(),
        })
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &DigitalSignature) -> Result<bool> {
        let public_key = PublicKey::from_bytes(&signature.public_key)?;
        let signature = Signature::from_bytes(&signature.signature)?;

        match public_key.verify(message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Perform ECDH key exchange
    pub fn key_exchange(&self, peer_public_key: &[u8]) -> Result<SharedSecret> {
        let peer_public = x25519_dalek::PublicKey::from(*array_ref![peer_public_key, 0, 32]);
        let shared_secret = self.exchange_keypair.diffie_hellman(&peer_public);
        Ok(shared_secret)
    }

    /// Derive encryption key from shared secret
    pub fn derive_key(shared_secret: &SharedSecret, context: &[u8]) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(context, &mut key)
            .map_err(|e| anyhow::anyhow!("HKDF expansion failed: {:?}", e))?;
        Ok(key)
    }

    /// Encrypt a message with AES-256-GCM
    pub fn encrypt_aes(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedMessage> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        // Split ciphertext and tag (AES-GCM appends tag to ciphertext)
        let tag_start = ciphertext.len() - 16; // GCM tag is 16 bytes
        let ciphertext_data = ciphertext[..tag_start].to_vec();
        let tag = ciphertext[tag_start..].to_vec();

        Ok(EncryptedMessage {
            ciphertext: ciphertext_data,
            nonce: nonce.to_vec(),
            tag,
            sender_public_key: self.signing_public_key(),
        })
    }

    /// Decrypt a message with AES-256-GCM
    pub fn decrypt_aes(&self, encrypted: &EncryptedMessage, key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(&encrypted.nonce);

        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = encrypted.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&encrypted.tag);

        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag.as_slice())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        Ok(plaintext)
    }

    /// Encrypt a message with ChaCha20-Poly1305
    pub fn encrypt_chacha(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedMessage> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut rand::rngs::OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("ChaCha encryption failed: {:?}", e))?;

        // Split ciphertext and tag
        let tag_start = ciphertext.len() - 16; // Poly1305 tag is 16 bytes
        let ciphertext_data = ciphertext[..tag_start].to_vec();
        let tag = ciphertext[tag_start..].to_vec();

        Ok(EncryptedMessage {
            ciphertext: ciphertext_data,
            nonce: nonce.to_vec(),
            tag,
            sender_public_key: self.signing_public_key(),
        })
    }

    /// Decrypt a message with ChaCha20-Poly1305
    pub fn decrypt_chacha(&self, encrypted: &EncryptedMessage, key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = chacha20poly1305::Nonce::from_slice(&encrypted.nonce);

        // Reconstruct ciphertext with tag
        let mut ciphertext_with_tag = encrypted.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&encrypted.tag);

        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag.as_slice())
            .map_err(|e| anyhow::anyhow!("ChaCha decryption failed: {:?}", e))?;

        Ok(plaintext)
    }

    /// Generate a secure hash
    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Derive key from password using PBKDF2
    pub fn derive_key_from_password(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut key);
        key
    }

    /// Generate a secure random key
    pub fn generate_random_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    /// Securely wipe sensitive data
    pub fn secure_wipe(data: &mut [u8]) {
        data.zeroize();
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create crypto engine")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let crypto = CryptoEngine::new().unwrap();
        let message = b"Hello, Wolf Prowler!";

        let signature = crypto.sign(message).unwrap();
        let verified = crypto.verify(message, &signature).unwrap();

        assert!(verified);

        // Verify with wrong message fails
        let wrong_message = b"Wrong message";
        let verified_wrong = crypto.verify(wrong_message, &signature).unwrap();
        assert!(!verified_wrong);
    }

    #[test]
    fn test_encryption() {
        let crypto = CryptoEngine::new().unwrap();
        let plaintext = b"Secret wolf pack message";
        let key = CryptoEngine::generate_random_key();

        let encrypted = crypto.encrypt_aes(plaintext, &key).unwrap();
        let decrypted = crypto.decrypt_aes(&encrypted, &key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_key_exchange() {
        let alice = CryptoEngine::new().unwrap();
        let bob = CryptoEngine::new().unwrap();

        let alice_shared = alice.key_exchange(&bob.exchange_public_key()).unwrap();
        let bob_shared = bob.key_exchange(&alice.exchange_public_key()).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }
}
