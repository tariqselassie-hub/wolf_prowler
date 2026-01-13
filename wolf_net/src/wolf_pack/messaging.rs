//! Message protocols and routing for Wolf Prowler

use anyhow::Result;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use serde::{Deserialize, Serialize};
use std::io;

/// Wolf message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WolfMessage {
    /// Handshake message
    Handshake {
        /// Protocol version
        version: String,
        /// ID of sender
        peer_id: String,
        /// Public key of sender
        public_key: Vec<u8>,
        /// Timestamp of handshake
        timestamp: u64,
    },
    /// Pack coordination message
    PackCoordination {
        /// Pack ID
        pack_id: String,
        /// Action required
        action: PackAction,
        /// Specific data payload
        payload: Vec<u8>,
        /// Authorization signature
        signature: Vec<u8>,
    },
    /// Security alert
    SecurityAlert {
        /// Type of alert
        alert_type: String,
        /// Severity level
        severity: String,
        /// Description of threat
        description: String,
        /// Peer reporting the alert
        source_peer: String,
        /// Timestamp
        timestamp: u64,
    },
    /// Howl communication
    Howl {
        /// Urgency frequency (fake metric for now)
        frequency: f32,
        /// Pattern of the howl
        pattern: HowlPattern,
        /// Encoded message
        message: Option<Vec<u8>>,
        /// Territory context
        territory: Option<String>,
    },
    /// Territory claim
    TerritoryClaim {
        /// ID of territory
        territory_id: String,
        /// Boundary definitions
        boundaries: Vec<String>,
        /// Claim strength or expiration
        strength: u32,
        /// Timestamp
        timestamp: u64,
    },
    /// Heartbeat
    Heartbeat {
        /// Sender ID
        peer_id: String,
        /// Current status
        status: PeerStatus,
        /// Performance metrics
        metrics: PeerMetrics,
        /// Timestamp
        timestamp: u64,
    },
}

/// Pack actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackAction {
    /// Join a pack
    Join {
        /// ID of pack to join
        pack_id: String,
    },
    /// Leave a pack
    Leave {
        /// ID of pack to leave
        pack_id: String,
    },
    /// General coordination
    Coordinate {
        /// Operation identifier
        operation: String,
    },
    /// Raise alert
    Alert {
        /// Threat level
        threat_level: u8,
    },
    /// Initiate hunt
    Hunt {
        /// Target ID
        target_id: String,
    },
    /// Hunter verification phase
    Stalk {
        /// Target IP
        target_ip: String,
    },
    /// Active neutralization command
    Strike {
        /// Target IP
        target_ip: String,
    },
}

/// Howl patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HowlPattern {
    /// Alert Howl
    Alert {
        /// Urgency level
        urgency: u8,
        /// Whether it's restricted to pack members
        pack_only: bool,
    },
    /// Specific warning about a detected threat (Scent phase)
    Warning {
        /// Detected IP
        target_ip: String,
        /// Evidence summary
        evidence: String,
    },
    /// Coordination Howl
    Coordination {
        /// Pack ID
        pack_id: String,
        /// Operation
        operation: String,
    },
    /// Territory Howl
    Territory {
        /// Territory ID
        territory_id: String,
        /// Claim action
        action: String,
    },
    /// Social Howl
    Social {
        /// Greeting or message
        greeting: String,
        /// Pack ID context
        pack_id: Option<String>,
    },
    /// Hunt Howl
    Hunt {
        /// Target ID
        target_id: String,
        /// Strategy plan
        strategy: String,
    },
}

/// Peer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Fully active
    Active,
    /// Idle / Standing by
    Idle,
    /// Engaged in hunt
    Hunting,
    /// Defending territory
    Guarding,
    /// Maintenance / Rebooting
    Resting,
}

/// Peer metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMetrics {
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Memory usage percentage
    pub memory_usage: f32,
    /// Average network latency in ms
    pub network_latency: u32,
    /// Number of active connections
    pub connection_count: u32,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
}

/// Wolf response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WolfResponse {
    /// Acknowledgment
    Ack {
        /// ID of message being acknowledged
        message_id: String,
        /// Status string
        status: String,
        /// Timestamp
        timestamp: u64,
    },
    /// Handshake response
    HandshakeResponse {
        /// Protocol version
        version: String,
        /// Responder ID
        peer_id: String,
        /// Responder Public Key
        public_key: Vec<u8>,
        /// Accepted or rejected
        accepted: bool,
        /// Rejection reason
        reason: Option<String>,
    },
    /// Pack coordination response
    PackCoordinationResponse {
        /// Pack ID
        pack_id: String,
        /// Action being responded to
        action: PackAction,
        /// Result of action
        result: String,
        /// Data payload
        payload: Option<Vec<u8>>,
    },
    /// Security alert response
    SecurityAlertResponse {
        /// Alert ID
        alert_id: String,
        /// Action taken
        action_taken: String,
        /// Status
        status: String,
    },
    /// Howl response
    HowlResponse {
        /// Pattern context
        pattern: HowlPattern,
        /// Response string
        response: String,
        /// Whether pack was joined
        pack_joined: bool,
    },
    /// Territory response
    TerritoryResponse {
        /// Territory ID
        territory_id: String,
        /// Action context
        action: String,
        /// Result string
        result: String,
        /// Conflicting claims
        conflicts: Vec<String>,
    },
    /// Error response
    Error {
        /// Error code
        code: String,
        /// Error message
        message: String,
        /// Additional details
        details: Option<String>,
    },
}

/// Codec for Wolf message protocol
#[derive(Debug, Clone, Default)]
pub struct WolfCodec;

#[async_trait]
impl Codec for WolfCodec {
    type Protocol = &'static str;
    type Request = WolfMessage;
    type Response = WolfResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;

        // First 4 bytes indicate message length
        if buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Message too short",
            ));
        }

        let len = u32::from_be_bytes([
            *buf.first().unwrap_or(&0),
            *buf.get(1).unwrap_or(&0),
            *buf.get(2).unwrap_or(&0),
            *buf.get(3).unwrap_or(&0),
        ]) as usize;
        if buf.len() < 4usize.saturating_add(len) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Incomplete message",
            ));
        }

        let message_data = buf
            .get(4..4usize.saturating_add(len))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid message bounds"))?;
        serde_json::from_slice(message_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;

        if buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Response too short",
            ));
        }

        let len = u32::from_be_bytes([
            *buf.first().unwrap_or(&0),
            *buf.get(1).unwrap_or(&0),
            *buf.get(2).unwrap_or(&0),
            *buf.get(3).unwrap_or(&0),
        ]) as usize;
        if buf.len() < 4usize.saturating_add(len) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Incomplete response",
            ));
        }

        let response_data = buf
            .get(4..4usize.saturating_add(len))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid response bounds"))?;
        serde_json::from_slice(response_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let message_data =
            serde_json::to_vec(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let len = u32::try_from(message_data.len())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(&message_data).await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let response_data =
            serde_json::to_vec(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let len = u32::try_from(response_data.len())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(&response_data).await?;
        io.close().await?;

        Ok(())
    }
}

/// Message router for handling different message types
pub struct MessageRouter {
    handlers: std::collections::HashMap<String, Box<dyn MessageHandler + Send + Sync>>,
}

/// Trait for message handlers
pub trait MessageHandler {
    /// Process the incoming message
    ///
    /// # Errors
    /// Returns an error if handling fails.
    fn handle_message(&self, message: &WolfMessage) -> Result<WolfResponse>;
    /// Check if this handler can process the message type
    fn can_handle(&self, message: &WolfMessage) -> bool;
}

impl MessageRouter {
    /// Create a new message router
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: std::collections::HashMap::new(),
        }
    }

    /// Register a message handler
    pub fn register_handler(
        &mut self,
        message_type: &str,
        handler: Box<dyn MessageHandler + Send + Sync>,
    ) {
        self.handlers.insert(message_type.to_string(), handler);
    }

    /// Route a message to the appropriate handler
    ///
    /// # Errors
    /// Returns an error if no handler is registered or the handler fails.
    #[allow(clippy::option_if_let_else)]
    pub fn route_message(&self, message: &WolfMessage) -> Result<WolfResponse> {
        let message_type = Self::get_message_type(message);

        if let Some(handler) = self.handlers.get(&message_type) {
            if handler.can_handle(message) {
                handler.handle_message(message)
            } else {
                Ok(WolfResponse::Error {
                    code: "CANNOT_HANDLE".to_string(),
                    message: "Handler cannot process this message".to_string(),
                    details: None,
                })
            }
        } else {
            Ok(WolfResponse::Error {
                code: "NO_HANDLER".to_string(),
                message: format!("No handler registered for message type: {message_type}"),
                details: None,
            })
        }
    }

    /// Get message type string
    fn get_message_type(message: &WolfMessage) -> String {
        match message {
            WolfMessage::Handshake { .. } => "handshake".to_string(),
            WolfMessage::PackCoordination { .. } => "pack_coordination".to_string(),
            WolfMessage::SecurityAlert { .. } => "security_alert".to_string(),
            WolfMessage::Howl { .. } => "howl".to_string(),
            WolfMessage::TerritoryClaim { .. } => "territory_claim".to_string(),
            WolfMessage::Heartbeat { .. } => "heartbeat".to_string(),
        }
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Default message handler
pub struct DefaultMessageHandler;

impl MessageHandler for DefaultMessageHandler {
    fn handle_message(&self, message: &WolfMessage) -> Result<WolfResponse> {
        match message {
            WolfMessage::Handshake {
                peer_id: _peer_id, ..
            } => Ok(WolfResponse::HandshakeResponse {
                version: "1.0".to_string(),
                peer_id: "local_peer".to_string(),
                public_key: vec![],
                accepted: true,
                reason: None,
            }),
            WolfMessage::Heartbeat {
                peer_id: _peer_id, ..
            } => Ok(WolfResponse::Ack {
                message_id: uuid::Uuid::new_v4().to_string(),
                status: "received".to_string(),
                timestamp: chrono::Utc::now().timestamp().try_into().unwrap_or(0),
            }),
            _ => Ok(WolfResponse::Error {
                code: "NOT_IMPLEMENTED".to_string(),
                message: "Message type not implemented".to_string(),
                details: None,
            }),
        }
    }

    fn can_handle(&self, _message: &WolfMessage) -> bool {
        true // Default handler can handle all messages
    }
}
