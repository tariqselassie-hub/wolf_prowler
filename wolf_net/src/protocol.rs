use crate::encryption::EncryptedMessage;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use serde::{Deserialize, Serialize};
use std::io;

/// Enum representing requests in the Wolf protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Requests for the Wolf protocol.
pub enum WolfRequest {
    /// Initiates a key exchange, providing the public key.
    KeyExchange {
        /// The public key for the exchange.
        public_key: Vec<u8>
    },
    /// Sends an encrypted message using the Wolf encryption scheme.
    Encrypted(EncryptedMessage),
    /// Simple ping request to check liveness.
    Ping,
    /// Echo request that returns the provided string.
    Echo(String),
}

/// Enum representing responses in the Wolf protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Responses for the Wolf protocol.
pub enum WolfResponse {
    /// Acknowledges a key exchange, returning the peer's public key.
    KeyExchangeAck {
        /// The public key received from the peer.
        public_key: Vec<u8>
    },
    /// Sends an encrypted response.
    Encrypted(EncryptedMessage),
    /// Pong response for ping.
    Pong,
    /// Echo response returning the string.
    Echo(String),
    /// Error response with description.
    Error(String),
}

#[derive(Debug, Clone)]
/// Protocol identifier for the Wolf request/response communication.
pub struct WolfProtocol;

impl AsRef<str> for WolfProtocol {
    fn as_ref(&self) -> &str {
        "/wolf-pack/req/1.0.0"
    }
}

#[derive(Clone, Default)]
/// Codec implementation for the Wolf protocol.
pub struct WolfCodec;

#[async_trait]
impl Codec for WolfCodec {
    type Protocol = WolfProtocol;
    type Request = WolfRequest;
    type Response = WolfResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let data = read_length_prefixed(io).await?;
        serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let data = read_length_prefixed(io).await?;
        serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
        let data =
            serde_json::to_vec(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_length_prefixed(io, &data).await
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
        let data =
            serde_json::to_vec(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_length_prefixed(io, &data).await
    }
}

async fn read_length_prefixed<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_length_prefixed<T>(io: &mut T, data: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let len = data.len() as u32;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(data).await?;
    Ok(())
}
