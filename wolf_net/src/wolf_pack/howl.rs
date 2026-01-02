//! Howl messaging system for Wolf Pack coordination.

use crate::peer::PeerId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

/// Priority level of a Howl message
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HowlPriority {
    Info = 0,
    Warning = 1,
    Alert = 2, // Highest priority (e.g. KillOrder)
}

/// The payload content of a Howl message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HowlPayload {
    /// A Scout reporting a threat
    WarningHowl { target_ip: String, evidence: String },
    /// An Alpha or Beta requesting a hunt
    HuntRequest {
        hunt_id: String,
        target_ip: String,
        /// Minimum role required to join
        min_role: crate::wolf_pack::state::WolfRole,
    },
    /// A Hunter reporting their findings
    HuntReport {
        hunt_id: String,
        hunter: PeerId,
        confirmed: bool,
    },
    /// An Alpha commanding a node neutralization
    KillOrder {
        target_ip: String,
        reason: String,
        /// ID of the hunt that lead to this order
        hunt_id: String,
    },
    /// Updates about territory ownership or status
    TerritoryUpdate {
        region_cidr: String,
        owner: PeerId,
        status: String,
    },
    /// A Candidate requesting votes to become Alpha
    ElectionRequest {
        term: u64,
        candidate_id: PeerId,
        last_log_index: u64,
        prestige: u32,
    },
    /// A node casting a vote
    ElectionVote {
        term: u64,
        voter_id: PeerId,
        granted: bool,
    },
    /// Periodic heartbeat from the Alpha to maintain authority
    AlphaHeartbeat { term: u64, leader_id: PeerId },
}

/// The envelope for all P2P gossip messages in the Wolf Pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HowlMessage {
    /// Unique ID of the message
    pub id: Uuid,
    /// When the message was created
    pub timestamp: SystemTime,
    /// The node sending the message
    pub sender: PeerId,
    /// Cryptographic signature of the payload (to be implemented with wolf_den)
    pub signature: Vec<u8>,
    /// Priority level for processing
    pub priority: HowlPriority,
    /// The actual content
    pub payload: HowlPayload,
}

impl HowlMessage {
    pub fn new(sender: PeerId, priority: HowlPriority, payload: HowlPayload) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            sender,
            signature: Vec::new(), // Signature must be applied by the key holder
            priority,
            payload,
        }
    }

    /// Serializes the message for network transmission
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!("Serialization error: {}", e))
    }

    /// Deserializes a message from network bytes
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!("Deserialization error: {}", e))
    }
}
