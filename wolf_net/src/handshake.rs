//! Secure Handshake Logic for Wolf Prowler
//!
//! This module implements the ECDH (Elliptic Curve Diffie-Hellman) key exchange
//! using X25519 to establish shared secrets between peers.

use crate::message::{Message, MessageType};
use crate::peer::{PeerId, PeerInfo};
use anyhow::{anyhow, Result};
use chrono::Utc;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey, StaticSecret};

/// Manages secure handshake and key exchange operations.
///
/// It tracks pending handshakes (where this node is the initiator) and
/// handles the derivation of shared secrets upon receiving public keys.
#[derive(Clone)]
pub struct HandshakeManager {
    /// Pending handshakes where we initiated and are waiting for a response.
    /// Maps Target `PeerId` -> Our Ephemeral Private Key
    pending_handshakes: Arc<Mutex<HashMap<PeerId, StaticSecret>>>,
}

impl Default for HandshakeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeManager {
    /// Create a new `HandshakeManager`
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_handshakes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Initiates a handshake with a target peer.
    ///
    /// Generates an ephemeral keypair, stores the private key, and returns
    /// a `KeyExchange` message containing the public key to be sent to the target.
    ///
    /// # Errors
    /// Returns an error if the pending handshakes map cannot be locked.
    pub fn initiate_handshake(
        &self,
        local_peer_id: PeerId,
        target_peer_id: PeerId,
    ) -> Result<Message> {
        // 1. Generate ephemeral X25519 keypair
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        // 2. Store the private key to derive the shared secret later upon response
        self.pending_handshakes
            .lock()
            .map_err(|_| anyhow!("Failed to lock pending handshakes"))?
            .insert(target_peer_id.clone(), secret);

        // 3. Create KeyExchange message
        let public_hex = hex::encode(public.as_bytes());
        let msg_type = MessageType::KeyExchange {
            public_key: public_hex,
            key_type: "x25519".to_string(),
            timestamp: Utc::now(),
        };

        tracing::debug!("Initiating handshake with {}", target_peer_id);
        Ok(Message::to_peer(local_peer_id, target_peer_id, msg_type))
    }

    /// Processes an incoming `KeyExchange` message.
    ///
    /// # Errors
    /// Returns an error if the public key cannot be decoded or if its length is invalid, or if the pending handshakes map cannot be locked.
    pub fn handle_handshake(
        &self,
        local_peer_id: PeerId,
        sender_peer_id: PeerId,
        public_key_hex: &str,
        peer_info: &mut PeerInfo,
    ) -> Result<Option<Message>> {
        // 1. Decode the received public key
        let peer_public_bytes = hex::decode(public_key_hex)
            .map_err(|e| anyhow!("Failed to decode public key hex: {e}"))?;

        if peer_public_bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid public key length (expected 32 bytes for X25519)"
            ));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&peer_public_bytes);
        let peer_public = PublicKey::from(arr);

        // 2. Check if we have a pending handshake for this peer (meaning we are the Initiator)
        let mut pending = self
            .pending_handshakes
            .lock()
            .map_err(|_| anyhow!("Failed to lock pending handshakes"))?;

        if let Some(my_secret) = pending.remove(&sender_peer_id) {
            // CASE A: We initiated, this is the response.
            let shared_secret = my_secret.diffie_hellman(&peer_public);

            peer_info.set_session_secret(shared_secret.as_bytes().to_vec());
            peer_info.update_trust_score(peer_info.trust_score() + 0.1);

            tracing::info!(
                "🔐 Secure session established with {} (Initiator)",
                sender_peer_id
            );
            Ok(None)
        } else {
            // CASE B: We are the responder.
            let my_secret = StaticSecret::random_from_rng(OsRng);
            let my_public = PublicKey::from(&my_secret);

            let shared_secret = my_secret.diffie_hellman(&peer_public);
            peer_info.set_session_secret(shared_secret.as_bytes().to_vec());

            tracing::info!(
                "🔐 Secure session established with {} (Responder)",
                sender_peer_id
            );

            let my_public_hex = hex::encode(my_public.as_bytes());
            let msg_type = MessageType::KeyExchange {
                public_key: my_public_hex,
                key_type: "x25519".to_string(),
                timestamp: Utc::now(),
            };

            Ok(Some(Message::to_peer(
                local_peer_id,
                sender_peer_id,
                msg_type,
            )))
        }
    }
}
