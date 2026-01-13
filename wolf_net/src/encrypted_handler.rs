//! Encrypted Message Handler for Wolf Net
//!
//! This module provides a higher-level API for sending and receiving encrypted messages
//! over the Wolf Prowler network. It wraps the protocol layer and handles encryption/decryption
//! with proper peer context.

use crate::encryption::{EncryptedMessage, MessageEncryption};
use crate::protocol::{WolfRequest, WolfResponse};
use anyhow::{Context, Result};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use x25519_dalek::PublicKey;

/// Wrapper for encrypted protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptedProtocolMessage {
    /// Plaintext key exchange (not encrypted)
    KeyExchange {
        /// The public key for X25519 key exchange.
        public_key: Vec<u8>,
    },
    /// Encrypted request
    EncryptedRequest(EncryptedMessage),
    /// Encrypted response
    EncryptedResponse(EncryptedMessage),
}

/// Handler for encrypted messaging
pub struct EncryptedMessageHandler {
    /// Encryption manager
    encryption: Arc<MessageEncryption>,
    /// Peer public keys (peer_id -> public_key)
    peer_keys: Arc<RwLock<HashMap<String, PublicKey>>>,
    /// Whether to enforce encryption
    enforce_encryption: bool,
}

impl EncryptedMessageHandler {
    /// Create a new encrypted message handler
    pub fn new(encryption: Arc<MessageEncryption>) -> Self {
        Self {
            encryption,
            peer_keys: Arc::new(RwLock::new(HashMap::new())),
            enforce_encryption: true,
        }
    }

    /// Create a new handler with optional encryption enforcement
    pub fn with_enforcement(encryption: Arc<MessageEncryption>, enforce: bool) -> Self {
        Self {
            encryption,
            peer_keys: Arc::new(RwLock::new(HashMap::new())),
            enforce_encryption: enforce,
        }
    }

    /// Get our public key for key exchange
    pub fn public_key(&self) -> PublicKey {
        self.encryption.public_key()
    }

    /// Register a peer's public key
    pub async fn register_peer_key(&self, peer_id: &PeerId, public_key: PublicKey) {
        let mut keys = self.peer_keys.write().await;
        keys.insert(peer_id.to_string(), public_key);
    }

    /// Get a peer's public key
    pub async fn get_peer_key(&self, peer_id: &PeerId) -> Option<PublicKey> {
        let keys = self.peer_keys.read().await;
        keys.get(&peer_id.to_string()).copied()
    }

    /// Remove a peer's key (e.g., on disconnect)
    pub async fn remove_peer_key(&self, peer_id: &PeerId) {
        {
            let mut keys = self.peer_keys.write().await;
            keys.remove(&peer_id.to_string());
        }
        // Also clear encryption session
        self.encryption.clear_session(&peer_id.to_string()).await;
    }

    /// Encrypt a request for a specific peer
    pub async fn encrypt_request(
        &self,
        peer_id: &PeerId,
        request: &WolfRequest,
    ) -> Result<EncryptedMessage> {
        // Get peer's public key
        let peer_key = self
            .get_peer_key(peer_id)
            .await
            .context("Peer public key not found - perform key exchange first")?;

        // Serialize the request
        let plaintext = serde_json::to_vec(request).context("Failed to serialize request")?;

        // Encrypt
        let encrypted = self
            .encryption
            .encrypt(&plaintext, &peer_id.to_string(), &peer_key)
            .await
            .context("Failed to encrypt request")?;

        Ok(encrypted)
    }

    /// Decrypt a request from a specific peer
    pub async fn decrypt_request(
        &self,
        peer_id: &PeerId,
        encrypted: &EncryptedMessage,
    ) -> Result<WolfRequest> {
        // Decrypt
        let plaintext = self
            .encryption
            .decrypt(encrypted, &peer_id.to_string())
            .await
            .context("Failed to decrypt request")?;

        // Deserialize
        let request = serde_json::from_slice(&plaintext)
            .context("Failed to deserialize decrypted request")?;

        Ok(request)
    }

    /// Encrypt a response for a specific peer
    pub async fn encrypt_response(
        &self,
        peer_id: &PeerId,
        response: &WolfResponse,
    ) -> Result<EncryptedMessage> {
        // Get peer's public key
        let peer_key = self
            .get_peer_key(peer_id)
            .await
            .context("Peer public key not found - perform key exchange first")?;

        // Serialize the response
        let plaintext = serde_json::to_vec(response).context("Failed to serialize response")?;

        // Encrypt
        let encrypted = self
            .encryption
            .encrypt(&plaintext, &peer_id.to_string(), &peer_key)
            .await
            .context("Failed to encrypt response")?;

        Ok(encrypted)
    }

    /// Decrypt a response from a specific peer
    pub async fn decrypt_response(
        &self,
        peer_id: &PeerId,
        encrypted: &EncryptedMessage,
    ) -> Result<WolfResponse> {
        // Decrypt
        let plaintext = self
            .encryption
            .decrypt(encrypted, &peer_id.to_string())
            .await
            .context("Failed to decrypt response")?;

        // Deserialize
        let response = serde_json::from_slice(&plaintext)
            .context("Failed to deserialize decrypted response")?;

        Ok(response)
    }

    /// Check if encryption is enforced
    pub const fn is_encryption_enforced(&self) -> bool {
        self.enforce_encryption
    }

    /// Get the number of registered peer keys
    pub async fn peer_key_count(&self) -> usize {
        let keys = self.peer_keys.read().await;
        keys.len()
    }

    /// Get encryption session count
    pub async fn session_count(&self) -> usize {
        self.encryption.session_count().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handler_creation() {
        let encryption =
            Arc::new(MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap());
        let handler = EncryptedMessageHandler::new(encryption);

        assert!(handler.is_encryption_enforced());
        assert_eq!(handler.peer_key_count().await, 0);
    }

    #[tokio::test]
    async fn test_peer_key_registration() {
        let encryption =
            Arc::new(MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap());
        let handler = EncryptedMessageHandler::new(encryption);

        let peer_id = PeerId::random();
        let peer_encryption = MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap();
        let peer_pubkey = peer_encryption.public_key();

        handler.register_peer_key(&peer_id, peer_pubkey).await;

        assert_eq!(handler.peer_key_count().await, 1);
        assert!(handler.get_peer_key(&peer_id).await.is_some());
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_request() {
        let alice_encryption =
            Arc::new(MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap());
        let alice_handler = EncryptedMessageHandler::new(alice_encryption);

        let bob_encryption =
            Arc::new(MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap());
        let bob_handler = EncryptedMessageHandler::new(bob_encryption);

        let alice_peer_id = PeerId::random();
        let bob_peer_id = PeerId::random();

        // Exchange keys
        alice_handler
            .register_peer_key(&bob_peer_id, bob_handler.public_key())
            .await;
        bob_handler
            .register_peer_key(&alice_peer_id, alice_handler.public_key())
            .await;

        // Alice encrypts a request for Bob
        let request = WolfRequest::Ping;
        let encrypted = alice_handler
            .encrypt_request(&bob_peer_id, &request)
            .await
            .unwrap();

        // Bob decrypts the request from Alice
        let decrypted = bob_handler
            .decrypt_request(&alice_peer_id, &encrypted)
            .await
            .unwrap();

        assert_eq!(request, decrypted);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_response() {
        let alice_encryption =
            Arc::new(MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap());
        let alice_handler = EncryptedMessageHandler::new(alice_encryption);

        let bob_encryption =
            Arc::new(MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap());
        let bob_handler = EncryptedMessageHandler::new(bob_encryption);

        let alice_peer_id = PeerId::random();
        let bob_peer_id = PeerId::random();

        // Exchange keys
        alice_handler
            .register_peer_key(&bob_peer_id, bob_handler.public_key())
            .await;
        bob_handler
            .register_peer_key(&alice_peer_id, alice_handler.public_key())
            .await;

        // Bob encrypts a response for Alice
        let response = WolfResponse::Pong;
        let encrypted = bob_handler
            .encrypt_response(&alice_peer_id, &response)
            .await
            .unwrap();

        // Alice decrypts the response from Bob
        let decrypted = alice_handler
            .decrypt_response(&bob_peer_id, &encrypted)
            .await
            .unwrap();

        assert_eq!(response, decrypted);
    }

    #[tokio::test]
    async fn test_remove_peer_key() {
        let encryption =
            Arc::new(MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap());
        let handler = EncryptedMessageHandler::new(encryption);

        let peer_id = PeerId::random();
        let peer_encryption = MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap();
        let peer_pubkey = peer_encryption.public_key();

        handler.register_peer_key(&peer_id, peer_pubkey).await;
        assert_eq!(handler.peer_key_count().await, 1);

        handler.remove_peer_key(&peer_id).await;
        assert_eq!(handler.peer_key_count().await, 0);
        assert!(handler.get_peer_key(&peer_id).await.is_none());
    }

    #[tokio::test]
    async fn test_encryption_without_key_exchange() {
        let encryption =
            Arc::new(MessageEncryption::new(wolf_den::SecurityLevel::Standard).unwrap());
        let handler = EncryptedMessageHandler::new(encryption);

        let peer_id = PeerId::random();
        let request = WolfRequest::Ping;

        // Should fail because no key exchange happened
        let result = handler.encrypt_request(&peer_id, &request).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Peer public key not found"));
    }
}
