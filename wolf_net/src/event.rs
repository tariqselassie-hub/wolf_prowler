//! Event handling for Wolf Prowler
//!
//! This module defines network events and event handling mechanisms.

use crate::message::Message;
use crate::peer::{PeerId, PeerInfo};
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// Security event severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    /// Low severity - informational or minor policy deviation.
    Low,
    /// Medium severity - requires monitoring.
    Medium,
    /// High severity - potential threat detected.
    High,
    /// Critical severity - immediate response required.
    Critical,
}

/// Security event type
#[derive(Debug, Clone)]
pub enum SecurityEventType {
    /// Authentication related event.
    Authentication,
    /// Authorization related event.
    Authorization,
    /// Encryption/Decryption related event.
    Encryption,
    /// General network security event.
    Network,
    /// Violation of defined security policies.
    PolicyViolation,
    /// Other custom security event.
    Other(String),
}

/// Security event
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    /// Unique identifier for the event.
    pub id: String,
    /// Timestamp when the event occurred.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The type of security event.
    pub event_type: SecurityEventType,
    /// Severity level of the event.
    pub severity: SecuritySeverity,
    /// Detailed description of the event.
    pub description: String,
    /// Optional identifier of the peer involved.
    pub peer_id: Option<String>,
}

impl SecurityEvent {
    /// Creates a new `SecurityEvent` with the specified type, severity, and description.
    pub fn new(
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        description: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type,
            severity,
            description,
            peer_id: None,
        }
    }

    /// Associates a peer identifier with the security event.
    pub fn with_peer(mut self, peer_id: String) -> Self {
        self.peer_id = Some(peer_id);
        self
    }
}

/// Network events that can occur in Wolf Prowler
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new peer has connected to the node.
    PeerConnected { 
        /// ID of the connected peer.
        peer_id: PeerId, 
        /// Network address of the peer.
        address: String 
    },
    /// A peer has disconnected from the node.
    PeerDisconnected { 
        /// ID of the disconnected peer.
        peer_id: PeerId, 
        /// Reason for disconnection.
        reason: String 
    },
    /// A message has been received from a peer.
    MessageReceived { 
        /// ID of the sender.
        from: PeerId, 
        /// The message content.
        message: Message 
    },
    /// A message has been successfully sent to a peer.
    MessageSent { 
        /// ID of the recipient.
        to: PeerId, 
        /// Identification of the sent message.
        message_id: String 
    },
    /// A new peer has been discovered.
    PeerDiscovered { 
        /// Information about the discovered peer.
        peer_info: PeerInfo 
    },
    /// A previously known peer has expired (e.g., from DHT).
    PeerExpired { 
        /// ID of the expired peer.
        peer_id: PeerId 
    },
    /// An error occurred during connection.
    ConnectionError { 
        /// ID of the peer involved.
        peer_id: PeerId, 
        /// Error description.
        error: String 
    },
    /// Low-level swarm event.
    SwarmEvent {
        /// The type of swarm event.
        event_type: SwarmEventType,
        /// Additional details about the event.
        details: HashMap<String, String>,
    },
    /// Application-specific custom event.
    Custom {
        /// The type of custom event.
        event_type: String,
        /// Associated event data.
        data: HashMap<String, String>,
    },
    /// A security-related event.
    Security(SecurityEvent),
}

/// Swarm event types
#[derive(Debug, Clone)]
pub enum SwarmEventType {
    /// Node started listening on a new address.
    ListeningStarted,
    /// Node stopped listening on an address.
    ListeningStopped,
    /// An incoming connection was established.
    IncomingConnection,
    /// An outgoing connection was established.
    OutgoingConnection,
    /// Kademlia bootstrap process started.
    BootstrapStarted,
    /// Kademlia bootstrap process completed.
    BootstrapCompleted,
    /// Peer discovery process started.
    DiscoveryStarted,
    /// Peer discovery process completed.
    DiscoveryCompleted,
}

/// Event handler for processing network events
pub struct EventHandler {
    /// Event callbacks
    callbacks: HashMap<String, Vec<EventCallback>>,
    /// Event queue for processing
    event_queue: tokio::sync::mpsc::UnboundedSender<NetworkEvent>,
    /// Statistics
    stats: EventHandlerStats,
}

/// Event callback function type
pub type EventCallback = Box<dyn Fn(&NetworkEvent) -> anyhow::Result<()> + Send + Sync>;

/// Event handler statistics
#[derive(Debug, Clone, Default)]
pub struct EventHandlerStats {
    /// Total number of events successfully processed.
    pub events_processed: u64,
    /// Total number of events that failed during processing.
    pub events_failed: u64,
    /// Number of registered event callbacks.
    pub callbacks_registered: usize,
    /// Total number of events currently in the queue.
    pub events_queued: u64,
}

impl EventHandler {
    /// Creates a new `EventHandler` instance.
    pub fn new() -> Self {
        let (event_queue, _) = tokio::sync::mpsc::unbounded_channel();

        Self {
            callbacks: HashMap::new(),
            event_queue,
            stats: EventHandlerStats::default(),
        }
    }

    /// Registers a callback function for a specific event type.
    pub fn register_callback(&mut self, event_type: &str, callback: EventCallback) {
        self.callbacks
            .entry(event_type.to_string())
            .or_insert_with(Vec::new)
            .push(callback);
        self.stats.callbacks_registered += 1;

        debug!("Registered callback for event type: {}", event_type);
    }

    /// Emits a network event to the processing queue.
    pub fn emit(&mut self, event: NetworkEvent) -> anyhow::Result<()> {
        let event_type = self.get_event_type(&event);

        // Add to queue for async processing
        self.event_queue.send(event)?;
        self.stats.events_queued += 1;

        debug!("Emitted event: {}", event_type);
        Ok(())
    }

    /// Processes a network event immediately by executing all registered callbacks.
    pub fn process_event(&mut self, event: &NetworkEvent) -> anyhow::Result<()> {
        let event_type = self.get_event_type(event);

        // Find and execute callbacks
        if let Some(callbacks) = self.callbacks.get(&event_type) {
            for callback in callbacks {
                if let Err(e) = callback(event) {
                    error!("Event callback error for {}: {}", event_type, e);
                    self.stats.events_failed += 1;
                } else {
                    self.stats.events_processed += 1;
                }
            }
        }

        Ok(())
    }

    /// Starts the event handler loop.
    pub fn start(&mut self) -> anyhow::Result<()> {
        info!("📡 Event handler started");
        Ok(())
    }

    /// Gracefully stops the event handler.
    pub fn stop(&mut self) -> anyhow::Result<()> {
        info!("📡 Event handler stopped");
        Ok(())
    }

    /// Returns the current statistics of the event handler.
    pub fn stats(&self) -> &EventHandlerStats {
        &self.stats
    }

    /// Get event type string for an event
    fn get_event_type(&self, event: &NetworkEvent) -> String {
        match event {
            NetworkEvent::PeerConnected { .. } => "peer_connected".to_string(),
            NetworkEvent::PeerDisconnected { .. } => "peer_disconnected".to_string(),
            NetworkEvent::MessageReceived { .. } => "message_received".to_string(),
            NetworkEvent::MessageSent { .. } => "message_sent".to_string(),
            NetworkEvent::PeerDiscovered { .. } => "peer_discovered".to_string(),
            NetworkEvent::PeerExpired { .. } => "peer_expired".to_string(),
            NetworkEvent::ConnectionError { .. } => "connection_error".to_string(),
            NetworkEvent::SwarmEvent { event_type, .. } => {
                format!("swarm_{:?}", event_type).to_lowercase()
            }
            NetworkEvent::Custom { event_type, .. } => event_type.clone(),
            NetworkEvent::Security(_) => "security_event".to_string(),
        }
    }

    /// Helper to create a `PeerConnected` network event.
    pub fn peer_connected(peer_id: PeerId, address: String) -> NetworkEvent {
        NetworkEvent::PeerConnected { peer_id, address }
    }

    /// Helper to create a `PeerDisconnected` network event.
    pub fn peer_disconnected(peer_id: PeerId, reason: String) -> NetworkEvent {
        NetworkEvent::PeerDisconnected { peer_id, reason }
    }

    /// Helper to create a `MessageReceived` network event.
    pub fn message_received(from: PeerId, message: Message) -> NetworkEvent {
        NetworkEvent::MessageReceived { from, message }
    }

    /// Helper to create a `MessageSent` network event.
    pub fn message_sent(to: PeerId, message_id: String) -> NetworkEvent {
        NetworkEvent::MessageSent { to, message_id }
    }

    /// Helper to create a `PeerDiscovered` network event.
    pub fn peer_discovered(peer_info: PeerInfo) -> NetworkEvent {
        NetworkEvent::PeerDiscovered { peer_info }
    }

    /// Helper to create a `ConnectionError` network event.
    pub fn connection_error(peer_id: PeerId, error: String) -> NetworkEvent {
        NetworkEvent::ConnectionError { peer_id, error }
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Event logger for debugging and monitoring
pub struct EventLogger {
    log_level: tracing::Level,
}

impl EventLogger {
    /// Creates a new `EventLogger` with the specified log level.
    pub fn new(log_level: tracing::Level) -> Self {
        Self { log_level }
    }

    /// Creates a callback for logging events to the system log.
    pub fn create_callback(&self) -> EventCallback {
        let log_level = self.log_level;
        Box::new(move |event: &NetworkEvent| -> anyhow::Result<()> {
            match log_level {
                tracing::Level::DEBUG => debug!("Event: {:?}", event),
                tracing::Level::INFO => info!("Event: {:?}", event),
                tracing::Level::WARN => warn!("Event: {:?}", event),
                tracing::Level::ERROR => error!("Event: {:?}", event),
                _ => info!("Event: {:?}", event),
            }
            Ok(())
        })
    }
}

impl Default for EventLogger {
    fn default() -> Self {
        Self::new(tracing::Level::INFO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let peer_id = PeerId::random();
        let event = EventHandler::peer_connected(peer_id.clone(), "127.0.0.1:8080".to_string());

        match event {
            NetworkEvent::PeerConnected {
                peer_id: event_peer_id,
                address,
            } => {
                assert_eq!(event_peer_id, peer_id);
                assert_eq!(address, "127.0.0.1:8080");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_event_handler() {
        let mut handler = EventHandler::new();

        // Register a callback
        let callback_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        handler.register_callback(
            "peer_connected",
            Box::new(move |_| {
                callback_called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }),
        );

        // Emit and process event
        let peer_id = PeerId::random();
        let event = EventHandler::peer_connected(peer_id, "127.0.0.1:8080".to_string());

        handler.process_event(&event).unwrap();

        // Check if callback was called
        assert!(callback_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_event_logger() {
        let logger = EventLogger::new(tracing::Level::DEBUG);
        let callback = logger.create_callback();

        let peer_id = PeerId::random();
        let event = EventHandler::peer_connected(peer_id, "127.0.0.1:8080".to_string());

        // This should not panic
        callback(&event).unwrap();
    }
}
