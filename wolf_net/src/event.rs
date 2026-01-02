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
    Low,
    Medium,
    High,
    Critical,
}

/// Security event type
#[derive(Debug, Clone)]
pub enum SecurityEventType {
    Authentication,
    Authorization,
    Encryption,
    Network,
    PolicyViolation,
    Other(String),
}

/// Security event
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub peer_id: Option<String>,
}

impl SecurityEvent {
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

    pub fn with_peer(mut self, peer_id: String) -> Self {
        self.peer_id = Some(peer_id);
        self
    }
}

/// Network events that can occur in Wolf Prowler
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// Peer connected
    PeerConnected { peer_id: PeerId, address: String },
    /// Peer disconnected
    PeerDisconnected { peer_id: PeerId, reason: String },
    /// Message received
    MessageReceived { from: PeerId, message: Message },
    /// Message sent
    MessageSent { to: PeerId, message_id: String },
    /// Peer discovered
    PeerDiscovered { peer_info: PeerInfo },
    /// Peer expired
    PeerExpired { peer_id: PeerId },
    /// Connection error
    ConnectionError { peer_id: PeerId, error: String },
    /// Swarm event
    SwarmEvent {
        event_type: SwarmEventType,
        details: HashMap<String, String>,
    },
    /// Custom event
    Custom {
        event_type: String,
        data: HashMap<String, String>,
    },
    /// Security event
    Security(SecurityEvent),
}

/// Swarm event types
#[derive(Debug, Clone)]
pub enum SwarmEventType {
    ListeningStarted,
    ListeningStopped,
    IncomingConnection,
    OutgoingConnection,
    BootstrapStarted,
    BootstrapCompleted,
    DiscoveryStarted,
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
    pub events_processed: u64,
    pub events_failed: u64,
    pub callbacks_registered: usize,
    pub events_queued: u64,
}

impl EventHandler {
    /// Create new event handler
    pub fn new() -> Self {
        let (event_queue, _) = tokio::sync::mpsc::unbounded_channel();

        Self {
            callbacks: HashMap::new(),
            event_queue,
            stats: EventHandlerStats::default(),
        }
    }

    /// Register a callback for an event type
    pub fn register_callback(&mut self, event_type: &str, callback: EventCallback) {
        self.callbacks
            .entry(event_type.to_string())
            .or_insert_with(Vec::new)
            .push(callback);
        self.stats.callbacks_registered += 1;

        debug!("Registered callback for event type: {}", event_type);
    }

    /// Emit an event
    pub fn emit(&mut self, event: NetworkEvent) -> anyhow::Result<()> {
        let event_type = self.get_event_type(&event);

        // Add to queue for async processing
        self.event_queue.send(event)?;
        self.stats.events_queued += 1;

        debug!("Emitted event: {}", event_type);
        Ok(())
    }

    /// Process an event synchronously
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

    /// Start the event handler
    pub async fn start(&mut self) -> anyhow::Result<()> {
        info!("📡 Event handler started");
        Ok(())
    }

    /// Stop the event handler
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        info!("📡 Event handler stopped");
        Ok(())
    }

    /// Get event statistics
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

    /// Create a peer connected event
    pub fn peer_connected(peer_id: PeerId, address: String) -> NetworkEvent {
        NetworkEvent::PeerConnected { peer_id, address }
    }

    /// Create a peer disconnected event
    pub fn peer_disconnected(peer_id: PeerId, reason: String) -> NetworkEvent {
        NetworkEvent::PeerDisconnected { peer_id, reason }
    }

    /// Create a message received event
    pub fn message_received(from: PeerId, message: Message) -> NetworkEvent {
        NetworkEvent::MessageReceived { from, message }
    }

    /// Create a message sent event
    pub fn message_sent(to: PeerId, message_id: String) -> NetworkEvent {
        NetworkEvent::MessageSent { to, message_id }
    }

    /// Create a peer discovered event
    pub fn peer_discovered(peer_info: PeerInfo) -> NetworkEvent {
        NetworkEvent::PeerDiscovered { peer_info }
    }

    /// Create a connection error event
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
    /// Create new event logger
    pub fn new(log_level: tracing::Level) -> Self {
        Self { log_level }
    }

    /// Create callback for event logging
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
