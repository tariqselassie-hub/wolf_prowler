//! Message handling for Wolf Prowler
//!
//! This module defines message types, protocols, and handling.

use crate::peer::PeerId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wrapper for MessageType that implements Hash and Eq
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageTypeKey(String);

impl From<&MessageType> for MessageTypeKey {
    fn from(msg_type: &MessageType) -> Self {
        // Use a string representation for hashing
        Self(format!("{:?}", msg_type))
    }
}

/// Message types supported by Wolf Prowler
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MessageType {
    /// Simple chat message
    Chat { content: String },
    /// Data transfer
    Data {
        data: Vec<u8>,
        format: String,
        checksum: Option<String>,
        encrypted: bool,
    },
    /// Control command
    Control {
        command: String,
        parameters: std::collections::HashMap<String, String>,
        requires_auth: bool,
    },
    /// Peer discovery
    Discovery,
    /// Heartbeat/ping
    Heartbeat,
    /// Authentication challenge
    AuthChallenge {
        challenge: Vec<u8>,
        algorithm: String,
    },
    /// Authentication response
    AuthResponse {
        response: Vec<u8>,
        signature: String,
    },
    /// Key exchange
    KeyExchange {
        public_key: String,
        key_type: String,
        timestamp: DateTime<Utc>,
    },
    /// Reputation feedback
    Reputation {
        score: f64,
        feedback: String,
        target_peer: PeerId,
    },
    /// Network metrics
    Metrics {
        node_id: PeerId,
        metrics: std::collections::HashMap<String, f64>,
    },
    /// Network information
    NetworkInfo {
        known_peers: Vec<PeerId>,
        network_size: usize,
    },
}

/// Message priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl Default for MessagePriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Network message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Unique message identifier
    pub id: String,
    /// Sender peer ID
    pub from: PeerId,
    /// Target peer ID (None for broadcast)
    pub to: Option<PeerId>,
    /// Message type and content
    pub message_type: MessageType,
    /// Message timestamp
    pub timestamp: DateTime<Utc>,
    /// Digital signature (for authentication)
    pub signature: Option<String>,
    /// Encryption key ID (if encrypted)
    pub encryption_key_id: Option<String>,
    /// Protocol version
    pub version: String,
    /// Time to live
    pub ttl: Option<chrono::Duration>,
    /// Message priority
    pub priority: MessagePriority,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Message routing path
    pub routing_path: Vec<PeerId>,
}

impl Message {
    /// Create a new message
    pub fn new(from: PeerId, message_type: MessageType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to: None,
            message_type,
            timestamp: Utc::now(),
            signature: None,
            encryption_key_id: None,
            version: "1.0".to_string(),
            ttl: Some(chrono::Duration::minutes(5)),
            priority: MessagePriority::default(),
            metadata: std::collections::HashMap::new(),
            routing_path: Vec::new(),
        }
    }

    /// Create a message for a specific target
    pub fn to_peer(from: PeerId, to: PeerId, message_type: MessageType) -> Self {
        let mut msg = Self::new(from, message_type);
        msg.to = Some(to);
        msg
    }

    /// Create a broadcast message
    pub fn broadcast(from: PeerId, message_type: MessageType) -> Self {
        Self::new(from, message_type)
    }

    /// Set message priority
    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set TTL
    pub fn with_ttl(mut self, ttl: chrono::Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Add routing hop
    pub fn add_routing_hop(&mut self, peer_id: PeerId) {
        self.routing_path.push(peer_id);
    }

    /// Check if message is expired
    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl {
            Utc::now() > self.timestamp + ttl
        } else {
            false
        }
    }

    /// Check if message is for local peer
    pub fn is_for_local(&self, local_peer_id: &PeerId) -> bool {
        match &self.to {
            Some(target) => target == local_peer_id,
            None => true, // Broadcast
        }
    }

    /// Get message size estimate (in bytes)
    pub fn size_estimate(&self) -> usize {
        // Rough estimate based on serialization
        serde_json::to_string(self).map(|s| s.len()).unwrap_or(1024)
    }

    /// Create a simple chat message
    pub fn chat(from: PeerId, content: String) -> Self {
        Self::new(from, MessageType::Chat { content })
    }

    /// Create a heartbeat message
    pub fn heartbeat(from: PeerId) -> Self {
        Self::new(from, MessageType::Heartbeat)
    }

    /// Create a discovery message
    pub fn discovery(from: PeerId) -> Self {
        Self::new(from, MessageType::Discovery)
    }
}

/// Message handler for processing incoming and outgoing messages
pub struct MessageHandler {
    /// Handler configuration
    config: MessageConfig,
    /// Message queue for outgoing messages
    outgoing_queue: tokio::sync::mpsc::UnboundedSender<Message>,
    /// Message callbacks
    callbacks: std::collections::HashMap<MessageTypeKey, Vec<MessageCallback>>,
}

/// Configuration for message handling
#[derive(Debug, Clone)]
pub struct MessageConfig {
    /// Maximum message size (in bytes)
    pub max_message_size: usize,
    /// Message queue size
    pub queue_size: usize,
    /// Default TTL for messages
    pub default_ttl: chrono::Duration,
    /// Enable message signing
    pub enable_signing: bool,
    /// Enable message encryption
    pub enable_encryption: bool,
}

impl Default for MessageConfig {
    fn default() -> Self {
        Self {
            max_message_size: 10 * 1024 * 1024, // 10MB
            queue_size: 1000,
            default_ttl: chrono::Duration::minutes(5),
            enable_signing: true,
            enable_encryption: false,
        }
    }
}

/// Message callback function type
pub type MessageCallback = Box<dyn Fn(&Message) -> anyhow::Result<()> + Send + Sync>;

impl MessageHandler {
    /// Create new message handler
    pub fn new(config: MessageConfig) -> anyhow::Result<Self> {
        let (outgoing_queue, _) = tokio::sync::mpsc::unbounded_channel();

        Ok(Self {
            config,
            outgoing_queue,
            callbacks: std::collections::HashMap::new(),
        })
    }

    /// Start the message handler
    pub async fn start(&mut self) -> anyhow::Result<()> {
        tracing::info!("📨 Message handler started");
        Ok(())
    }

    /// Stop the message handler
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        tracing::info!("📨 Message handler stopped");
        Ok(())
    }

    /// Send a message
    pub async fn send_message(&self, message: Message) -> anyhow::Result<()> {
        if message.size_estimate() > self.config.max_message_size {
            return Err(anyhow::anyhow!(
                "Message too large: {} bytes",
                message.size_estimate()
            ));
        }

        self.outgoing_queue.send(message)?;
        Ok(())
    }

    /// Register a callback for a message type
    pub fn register_callback(&mut self, message_type: MessageType, callback: MessageCallback) {
        self.callbacks
            .entry((&message_type).into())
            .or_insert_with(Vec::new)
            .push(callback);
    }

    /// Process an incoming message
    pub async fn process_message(&self, message: Message) -> anyhow::Result<()> {
        // Check if message is expired
        if message.is_expired() {
            tracing::warn!("Expired message received: {}", message.id);
            return Ok(());
        }

        // Find and execute callbacks
        if let Some(callbacks) = self.callbacks.get(&(&message.message_type).into()) {
            for callback in callbacks {
                if let Err(e) = callback(&message) {
                    tracing::error!("Message callback error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Get outgoing message receiver
    pub fn outgoing_receiver(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<Message>> {
        // Note: This is a simplified approach. In practice, you'd need a different design
        // to get the receiver since the sender is consumed.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let peer_id = crate::peer::PeerId::random();
        let message = Message::chat(peer_id.clone(), "Hello".to_string());

        assert_eq!(message.from, peer_id);
        assert!(matches!(message.message_type, MessageType::Chat { .. }));
        assert!(message.to.is_none()); // Broadcast by default
    }

    #[tokio::test]
    async fn test_message_expiration() {
        let peer_id = crate::peer::PeerId::random();
        let mut message = Message::chat(peer_id, "Test".to_string());

        // Message should not be expired initially
        assert!(!message.is_expired());

        // Set a very short TTL
        message.ttl = Some(chrono::Duration::milliseconds(1));
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Message should be expired now
        assert!(message.is_expired());
    }
}
