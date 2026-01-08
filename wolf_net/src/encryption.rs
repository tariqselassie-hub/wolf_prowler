//! Message Encryption Layer for Wolf Net
//!
//! This module provides application-layer encryption for network messages using:
//! - AES-256-GCM for payload encryption (via wolf_den)
//! - X25519 for Diffie-Hellman key exchange
//! - Counter-based nonce management to prevent reuse
//!
//! ## Security Architecture
//!
//! 1. **Key Exchange**: Each peer pair establishes a shared secret using X25519 ECDH
//! 2. **Session Keys**: Shared secret is used to derive AES-256 keys via HKDF
//! 3. **Nonce Management**: Counter-based nonces ensure uniqueness per message
//! 4. **Forward Secrecy**: Session keys can be rotated periodically

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use wolf_den::symmetric::{Aes256GcmCipher, Cipher};
use wolf_den::{CryptoEngine, SecurityLevel};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Size of the nonce for AES-256-GCM (96 bits / 12 bytes)
const NONCE_SIZE: usize = 12;

/// Maximum nonce counter value before key rotation is required
const MAX_NONCE_COUNTER: u64 = u64::MAX - 1000;

/// Encrypted message envelope containing ciphertext and metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The encrypted payload
    pub ciphertext: Vec<u8>,
    /// Nonce used for this encryption (12 bytes)
    pub nonce: Vec<u8>,
    /// Sender's Ed25519 public key for signature verification
    pub sender_ed25519_public_key: Vec<u8>,
    /// Sender's X25519 public key for key exchange
    pub sender_x25519_public_key: Vec<u8>,
    /// Signature of the sender's public key
    pub signature: Vec<u8>,
    /// Protocol version for future compatibility
    pub version: u8,
}

/// Session key information for a peer
#[derive(Clone)]
struct SessionKey {
    /// The symmetric encryption key
    key: Vec<u8>,
    /// Nonce counter for this session
    nonce_counter: u64,
    /// Timestamp of key creation for rotation
    created_at: std::time::Instant,
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        // Securely zero out the key when dropped
        self.key.zeroize();
    }
}

/// Message encryption manager
pub struct MessageEncryption {
    /// The cryptographic engine
    crypto_engine: Arc<CryptoEngine>,
    /// AES-256-GCM cipher instance
    cipher: Arc<Aes256GcmCipher>,
    /// Session keys per peer (peer_id -> session_key)
    session_keys: Arc<RwLock<HashMap<String, SessionKey>>>,
    /// X25519 secret key for ECDH
    x25519_secret: StaticSecret,
    /// Security level (reserved for future use)
    #[allow(dead_code)]
    security_level: SecurityLevel,
}

impl MessageEncryption {
    /// Create a new message encryption manager
    pub fn new(security_level: SecurityLevel) -> Result<Self> {
        let crypto_engine = Arc::new(CryptoEngine::new(security_level)?);
        let cipher = Arc::new(
            Aes256GcmCipher::new(security_level).context("Failed to create AES-256-GCM cipher")?,
        );
        let x25519_secret = StaticSecret::random_from_rng(rand::thread_rng());

        Ok(Self {
            crypto_engine,
            cipher,
            session_keys: Arc::new(RwLock::new(HashMap::new())),
            x25519_secret,
            security_level,
        })
    }

    /// Get our public key for key exchange
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.x25519_secret)
    }

    /// Derive a session key from a shared secret using HKDF
    fn derive_session_key(&self, shared_secret: &[u8]) -> Result<Vec<u8>> {
        self.crypto_engine
            .derive_key(shared_secret, b"wolf-prowler-session-key-v1", 32)
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Get or create a session key for a peer
    async fn get_or_create_session_key(
        &self,
        peer_id: &str,
        peer_public_key: &PublicKey,
    ) -> Result<SessionKey> {
        let mut sessions = self.session_keys.write().await;

        // Check if we already have a valid session key
        if let Some(session) = sessions.get(peer_id) {
            // Check if key needs rotation (older than 1 hour or counter too high)
            let age = session.created_at.elapsed();
            if age.as_secs() < 3600 && session.nonce_counter < MAX_NONCE_COUNTER {
                return Ok(session.clone());
            }
        }

        // Create new session key via ECDH
        let shared_secret = self.x25519_secret.diffie_hellman(peer_public_key);
        let key = self.derive_session_key(shared_secret.as_bytes())?;

        let session = SessionKey {
            key,
            nonce_counter: 0,
            created_at: std::time::Instant::now(),
        };

        sessions.insert(peer_id.to_string(), session.clone());
        Ok(session)
    }

    /// Generate a nonce from a counter
    fn generate_nonce(counter: u64) -> Vec<u8> {
        let mut nonce = vec![0u8; NONCE_SIZE];
        // Use counter as the first 8 bytes, rest is zero
        nonce[0..8].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    /// Encrypt a message for a specific peer
    pub async fn encrypt(
        &self,
        plaintext: &[u8],
        peer_id: &str,
        peer_public_key: &PublicKey,
    ) -> Result<EncryptedMessage> {
        // Get or create session key
        let mut session = self
            .get_or_create_session_key(peer_id, peer_public_key)
            .await?;

        // Generate nonce from counter
        let nonce = Self::generate_nonce(session.nonce_counter);

        // Increment counter
        session.nonce_counter += 1;

        // Update session in map
        {
            let mut sessions = self.session_keys.write().await;
            sessions.insert(peer_id.to_string(), session.clone());
        }

        // Encrypt the message
        let ciphertext = self
            .cipher
            .encrypt(plaintext, &session.key, &nonce)
            .context("Failed to encrypt message")?;

        let x25519_public_key_bytes = self.public_key().to_bytes();
        let ed25519_public_key = self.crypto_engine.get_public_key();
        let ed25519_public_key_bytes = ed25519_public_key.to_bytes();
        let signature = self
            .crypto_engine
            .sign_message(&x25519_public_key_bytes);

        Ok(EncryptedMessage {
            ciphertext,
            nonce,
            sender_ed25519_public_key: ed25519_public_key_bytes.to_vec(),
            sender_x25519_public_key: x25519_public_key_bytes.to_vec(),
            signature: signature.to_bytes().to_vec(),
            version: 1,
        })
    }

    /// Decrypt a message from a specific peer
    pub async fn decrypt(&self, encrypted: &EncryptedMessage, peer_id: &str) -> Result<Vec<u8>> {
        // Validate version
        if encrypted.version != 1 {
            anyhow::bail!("Unsupported encryption version: {}", encrypted.version);
        }

        // Parse sender's Ed25519 public key for verification
        let peer_ed25519_public_key_bytes: [u8; 32] = encrypted
            .sender_ed25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid sender Ed25519 public key length"))?;
        let peer_ed25519_public_key =
            ed25519_dalek::VerifyingKey::from_bytes(&peer_ed25519_public_key_bytes)
                .map_err(|_| anyhow::anyhow!("Invalid sender Ed25519 public key"))?;

        // Parse sender's X25519 public key for ECDH
        let peer_x25519_public_key_bytes: [u8; 32] = encrypted
            .sender_x25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid sender X25519 public key length"))?;
        let peer_x25519_public_key = PublicKey::from(peer_x25519_public_key_bytes);

        // Verify signature
        let signature_bytes: [u8; 64] = encrypted
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        self.crypto_engine
            .verify_signature(
                &encrypted.sender_x25519_public_key,
                &signature,
                &peer_ed25519_public_key,
            )?;

        // Get or create session key
        let session = self
            .get_or_create_session_key(peer_id, &peer_x25519_public_key)
            .await?;

        // Decrypt the message
        let plaintext = self
            .cipher
            .decrypt(&encrypted.ciphertext, &session.key, &encrypted.nonce)
            .context("Failed to decrypt message")?;

        Ok(plaintext)
    }

    /// Clear session key for a peer (e.g., when peer disconnects)
    pub async fn clear_session(&self, peer_id: &str) {
        let mut sessions = self.session_keys.write().await;
        sessions.remove(peer_id);
    }

    /// Get statistics about active sessions
    pub async fn session_count(&self) -> usize {
        let sessions = self.session_keys.read().await;
        sessions.len()
    }
}

impl Default for MessageEncryption {
    fn default() -> Self {
        Self::new(SecurityLevel::Standard).expect("Failed to create MessageEncryption")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let alice = MessageEncryption::new(SecurityLevel::Standard).unwrap();
        let bob = MessageEncryption::new(SecurityLevel::Standard).unwrap();

        let plaintext = b"Hello, Bob! This is a secret message.";
        let peer_id = "bob";

        // Alice encrypts for Bob
        let encrypted = alice
            .encrypt(plaintext, peer_id, &bob.public_key())
            .await
            .unwrap();

        // Bob decrypts from Alice
        let decrypted = bob.decrypt(&encrypted, "alice").await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_multiple_messages_same_session() {
        let alice = MessageEncryption::new(SecurityLevel::Standard).unwrap();
        let bob = MessageEncryption::new(SecurityLevel::Standard).unwrap();

        // Send multiple messages
        for i in 0..10 {
            let plaintext = format!("Message {}", i);

            let encrypted = alice
                .encrypt(plaintext.as_bytes(), "bob", &bob.public_key())
                .await
                .unwrap();

            let decrypted = bob.decrypt(&encrypted, "alice").await.unwrap();

            assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
        }
    }

    #[tokio::test]
    async fn test_session_management() {
        let encryption = MessageEncryption::new(SecurityLevel::Standard).unwrap();

        assert_eq!(encryption.session_count().await, 0);

        // Create a peer
        let peer = MessageEncryption::new(SecurityLevel::Standard).unwrap();

        // Encrypt a message (creates session)
        let _ = encryption
            .encrypt(b"test", "peer1", &peer.public_key())
            .await
            .unwrap();

        assert_eq!(encryption.session_count().await, 1);

        // Clear session
        encryption.clear_session("peer1").await;
        assert_eq!(encryption.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_nonce_generation() {
        let nonce1 = MessageEncryption::generate_nonce(0);
        let nonce2 = MessageEncryption::generate_nonce(1);
        let nonce3 = MessageEncryption::generate_nonce(1000);

        assert_eq!(nonce1.len(), NONCE_SIZE);
        assert_eq!(nonce2.len(), NONCE_SIZE);
        assert_eq!(nonce3.len(), NONCE_SIZE);

        // Nonces should be different
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
    }

    #[tokio::test]
    async fn test_invalid_version() {
        let alice = MessageEncryption::new(SecurityLevel::Standard).unwrap();
        let bob = MessageEncryption::new(SecurityLevel::Standard).unwrap();

        let mut encrypted = alice
            .encrypt(b"test", "bob", &bob.public_key())
            .await
            .unwrap();

        // Corrupt version
        encrypted.version = 99;

        let result = bob.decrypt(&encrypted, "alice").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported encryption version"));
    }
}
