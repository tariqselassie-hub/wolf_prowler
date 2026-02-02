//! Howl messaging system for Wolf Pack coordination.

use crate::peer::PeerId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

/// Priority level of a Howl message
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HowlPriority {
    /// Informational message
    Info = 0,
    /// Warning message
    Warning = 1,
    /// Critical alert (Highest priority)
    Alert = 2,
}

/// The payload content of a Howl message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HowlPayload {
    /// A Scout reporting a threat
    WarningHowl {
        /// Detected target IP
        target_ip: String,
        /// Evidence string
        evidence: String,
    },
    /// An Alpha or Beta requesting a hunt
    HuntRequest {
        /// Unique hunt ID
        hunt_id: String,
        /// Target IP
        target_ip: String,
        /// Minimum role required to join
        min_role: crate::wolf_pack::state::WolfRole,
    },
    /// A Hunter reporting their findings
    HuntReport {
        /// Hunt ID being reported on
        hunt_id: String,
        /// Peer ID of hunter
        hunter: PeerId,
        /// Whether threat was confirmed
        confirmed: bool,
    },
    /// An Alpha commanding a node neutralization
    KillOrder {
        /// Target IP to neutralize
        target_ip: String,
        /// Justification for kill order
        reason: String,
        /// ID of the hunt that lead to this order
        hunt_id: String,
    },
    /// Updates about territory ownership or status
    TerritoryUpdate {
        /// CIDR range of territory
        region_cidr: String,
        /// Owner Peer ID
        owner: PeerId,
        /// Status of territory
        status: String,
    },
    /// A Candidate requesting votes to become Alpha
    ElectionRequest {
        /// Election term
        term: u64,
        /// Candidate Peer ID
        candidate_id: PeerId,
        /// Last log index (Raft)
        last_log_index: u64,
        /// Candidate prestige
        prestige: u32,
    },
    /// A node casting a vote
    ElectionVote {
        /// Election term
        term: u64,
        /// Voter Peer ID
        voter_id: PeerId,
        /// Vote granted
        granted: bool,
    },
    /// Periodic heartbeat from the Alpha to maintain authority
    AlphaHeartbeat {
        /// Current term
        term: u64,
        /// Leader Peer ID
        leader_id: PeerId,
    },
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
    /// Cryptographic signature of the payload (to be implemented with `wolf_den`)
    pub signature: Vec<u8>,
    /// Priority level for processing
    pub priority: HowlPriority,
    /// The actual content
    pub payload: HowlPayload,
}

impl HowlMessage {
    /// Create a new `HowlMessage`
    #[must_use]
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
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
    }

    /// Deserializes a message from network bytes
    ///
    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!("Deserialization error: {e}"))
    }
}
