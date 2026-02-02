use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use libp2p::PeerId;
use super::hierarchy::PackRank;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerritoryAccess {
    pub peer_id: PeerId,
    pub territory_name: String,
    pub timestamp: DateTime<Utc>,
    pub access_granted: bool,
    pub reason: String,
    pub duration_seconds: Option<u64>,
    pub pack_rank: PackRank,
}

// Removing Default impl as PeerId doesn't implement Default cleanly or we'd need a placeholder
