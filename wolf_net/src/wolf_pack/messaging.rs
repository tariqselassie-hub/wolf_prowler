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
        version: String,
        peer_id: String,
        public_key: Vec<u8>,
        timestamp: u64,
    },
    /// Pack coordination message
    PackCoordination {
        pack_id: String,
        action: PackAction,
        payload: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Security alert
    SecurityAlert {
        alert_type: String,
        severity: String,
        description: String,
        source_peer: String,
        timestamp: u64,
    },
    /// Howl communication
    Howl {
        frequency: f32,
        pattern: HowlPattern,
        message: Option<Vec<u8>>,
        territory: Option<String>,
    },
    /// Territory claim
    TerritoryClaim {
        territory_id: String,
        boundaries: Vec<String>,
        strength: u32,
        timestamp: u64,
    },
    /// Heartbeat
    Heartbeat {
        peer_id: String,
        status: PeerStatus,
        metrics: PeerMetrics,
        timestamp: u64,
    },
}

/// Pack actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackAction {
    Join {
        pack_id: String,
    },
    Leave {
        pack_id: String,
    },
    Coordinate {
        operation: String,
    },
    Alert {
        threat_level: u8,
    },
    Hunt {
        target_id: String,
    },
    /// Hunter verification phase
    Stalk {
        target_ip: String,
    },
    /// Active neutralization command
    Strike {
        target_ip: String,
    },
}

/// Howl patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HowlPattern {
    Alert {
        urgency: u8,
        pack_only: bool,
    },
    /// Specific warning about a detected threat (Scent phase)
    Warning {
        target_ip: String,
        evidence: String,
    },
    Coordination {
        pack_id: String,
        operation: String,
    },
    Territory {
        territory_id: String,
        action: String,
    },
    Social {
        greeting: String,
        pack_id: Option<String>,
    },
    Hunt {
        target_id: String,
        strategy: String,
    },
}

/// Peer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerStatus {
    Active,
    Idle,
    Hunting,
    Guarding,
    Resting,
}

/// Peer metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMetrics {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub network_latency: u32,
    pub connection_count: u32,
    pub messages_sent: u64,
    pub messages_received: u64,
}

/// Wolf response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WolfResponse {
    /// Acknowledgment
    Ack {
        message_id: String,
        status: String,
        timestamp: u64,
    },
    /// Handshake response
    HandshakeResponse {
        version: String,
        peer_id: String,
        public_key: Vec<u8>,
        accepted: bool,
        reason: Option<String>,
    },
    /// Pack coordination response
    PackCoordinationResponse {
        pack_id: String,
        action: PackAction,
        result: String,
        payload: Option<Vec<u8>>,
    },
    /// Security alert response
    SecurityAlertResponse {
        alert_id: String,
        action_taken: String,
        status: String,
    },
    /// Howl response
    HowlResponse {
        pattern: HowlPattern,
        response: String,
        pack_joined: bool,
    },
    /// Territory response
    TerritoryResponse {
        territory_id: String,
        action: String,
        result: String,
        conflicts: Vec<String>,
    },
    /// Error response
    Error {
        code: String,
        message: String,
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

        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Incomplete message",
            ));
        }

        let message_data = &buf[4..4 + len];
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

        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Incomplete response",
            ));
        }

        let response_data = &buf[4..4 + len];
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

        let len = message_data.len() as u32;
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

        let len = response_data.len() as u32;
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
    fn handle_message(&self, message: &WolfMessage) -> Result<WolfResponse>;
    fn can_handle(&self, message: &WolfMessage) -> bool;
}

impl MessageRouter {
    /// Create a new message router
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
    pub fn route_message(&self, message: &WolfMessage) -> Result<WolfResponse> {
        let message_type = self.get_message_type(message);

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
                message: format!("No handler registered for message type: {}", message_type),
                details: None,
            })
        }
    }

    /// Get message type string
    fn get_message_type(&self, message: &WolfMessage) -> String {
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
                timestamp: chrono::Utc::now().timestamp() as u64,
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
