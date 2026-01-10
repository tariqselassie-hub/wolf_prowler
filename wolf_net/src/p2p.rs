//! P2P Network Behavior and Protocol Implementation for Wolf Prowler

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{gossipsub, identify, mdns, request_response, swarm::NetworkBehaviour};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::time::Duration;

/// Alias for the libp2p PeerId type to avoid naming conflicts.
pub type Libp2pPeerId = libp2p::PeerId;

/// Message priority for routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
/// Priority levels for messages, influencing routing and handling.
pub enum MessagePriority {
    /// Low priority messages.
    Low = 0,
    /// Medium priority messages.
    Medium = 1,
    /// High priority messages.
    High = 2,
    /// Critical priority messages requiring immediate attention.
    Critical = 3,
}

impl MessagePriority {
    /// Converts the message priority to a gossipsub topic name.
    pub fn to_topic_name(&self) -> String {
        match self {
            Self::Low => "wolf-prowler-low".to_string(),
            Self::Medium => "wolf-prowler-medium".to_string(),
            Self::High => "wolf-prowler-high".to_string(),
            Self::Critical => "wolf-prowler-critical".to_string(),
        }
    }
}

/// Events produced by the `WolfNetBehavior`.
#[derive(Debug)]
pub enum WolfNetBehaviorEvent {
    /// Event from the gossipsub behaviour.
    Gossipsub(gossipsub::Event),
    /// Event from the mDNS behaviour.
    Mdns(mdns::Event),
    /// Event from the identify behaviour.
    Identify(identify::Event),
    /// Event from the request/response behaviour.
    RequestResponse(request_response::Event<crate::protocol::WolfRequest, crate::protocol::WolfResponse>),
}

impl From<gossipsub::Event> for WolfNetBehaviorEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(event)
    }
}

impl From<mdns::Event> for WolfNetBehaviorEvent {
    fn from(event: mdns::Event) -> Self {
        Self::Mdns(event)
    }
}

impl From<identify::Event> for WolfNetBehaviorEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<request_response::Event<crate::protocol::WolfRequest, crate::protocol::WolfResponse>> for WolfNetBehaviorEvent {
    fn from(event: request_response::Event<crate::protocol::WolfRequest, crate::protocol::WolfResponse>) -> Self {
        Self::RequestResponse(event)
    }
}

/// The core network behavior for Wolf Prowler
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "WolfNetBehaviorEvent")]
/// Core network behavior for Wolf Prowler, combining gossipsub, mDNS discovery, identify, and request/response.
pub struct WolfNetBehavior {
    /// Gossipsub behaviour for pub/sub messaging.
    pub gossipsub: gossipsub::Behaviour,
    /// mDNS discovery behaviour for local peer discovery.
    pub mdns: mdns::tokio::Behaviour,
    /// Identify protocol behaviour for peer information exchange.
    pub identify: identify::Behaviour,
    /// Request/Response behaviour using the Wolf protocol codec.
    pub request_response: request_response::Behaviour<crate::protocol::WolfCodec>,
}

/// Returns an optimized gossipsub configuration
#[must_use]
pub fn optimized_gossipsub_config() -> gossipsub::Config {
    gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(|message: &gossipsub::Message| {
            let mut hasher = Sha256::new();
            hasher.update(&message.data);
            gossipsub::MessageId::from(hasher.finalize().to_vec())
        })
        .duplicate_cache_time(Duration::from_secs(60))
        .max_transmit_size(1_048_576) // 1MB
        .build()
        .expect("Valid config")
}

/// Protocol definition for Wolf Prowler Request-Response
#[derive(Debug, Clone)]
/// Protocol identifier for the Wolf Prowler request/response communication.
pub struct WolfNetProtocol;

impl AsRef<str> for WolfNetProtocol {
    fn as_ref(&self) -> &'static str {
        "/wolf-prowler/req-resp/1.0.0"
    }
}

/// Codec for encoding/decoding network messages
#[derive(Clone)]
/// Codec for encoding and decoding Wolf Prowler network messages.
pub struct WolfNetCodec;

/// Generic request wrapper (legacy, consider using crate::protocol::WolfRequest)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WolfNetRequest(pub Vec<u8>);

/// Generic response wrapper (legacy, consider using crate::protocol::WolfResponse)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WolfNetResponse(pub Vec<u8>);

#[async_trait]
impl request_response::Codec for WolfNetCodec {
    type Protocol = WolfNetProtocol;
    type Request = WolfNetRequest;
    type Response = WolfNetResponse;

    async fn read_request<T>(
        &mut self,
        _: &WolfNetProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io).await?;
        Ok(WolfNetRequest(vec))
    }

    async fn read_response<T>(
        &mut self,
        _: &WolfNetProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io).await?;
        Ok(WolfNetResponse(vec))
    }

    async fn write_request<T>(
        &mut self,
        _: &WolfNetProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, &req.0).await
    }

    async fn write_response<T>(
        &mut self,
        _: &WolfNetProtocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, &res.0).await
    }
}

/// Helper to read length-prefixed data
async fn read_length_prefixed<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 10_485_760 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Message too large",
        ));
    }

    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Helper to write length-prefixed data
async fn write_length_prefixed<T>(io: &mut T, data: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let len = data.len() as u32;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(data).await?;
    Ok(())
}
