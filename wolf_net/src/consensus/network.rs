//! Raft Network Bridge
//!
//! Handles transmission of Raft protocol messages over libp2p.

use prost::Message;
use raft::prelude::Message as RaftMessage;
use serde::{Deserialize, Serialize};

/// Wrapper for Raft messages to be sent over the wire
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftNetworkMessage {
    /// Source node (numeric ID)
    pub from: u64,
    /// Target node (numeric ID, 0 for broadcast)
    pub to: u64,
    /// Serialized Raft message (using protobuf/prost via raft crate)
    pub data: Vec<u8>,
}

impl RaftNetworkMessage {
    /// Create a new network message from a Raft message
    ///
    /// # Errors
    /// Returns an error if encoding the Raft message fails.
    pub fn new(from: u64, to: u64, msg: &RaftMessage) -> Result<Self, prost::EncodeError> {
        let mut data = Vec::new();
        msg.encode(&mut data)?;

        Ok(Self { from, to, data })
    }

    /// Decode the inner Raft message
    ///
    /// # Errors
    /// Returns an error if decoding the Raft message fails.
    pub fn decode(&self) -> Result<RaftMessage, prost::DecodeError> {
        RaftMessage::decode(&self.data[..])
    }
}
