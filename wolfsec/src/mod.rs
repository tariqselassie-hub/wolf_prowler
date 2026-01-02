use crate::discovery::{DiscoveryConfig, DiscoveryService};
use crate::peer::{PeerId, PeerInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub mod hierarchy;
pub mod territory;

/// Represents the rank of a node in the Wolf Pack hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WolfRank {
    /// The leader of the pack. Coordinates all high-level decisions.
    Alpha,
    /// Second in command. Handles distribution and redundancy.
    Beta,
    /// Third command tier.
    Gamma,
    /// Standard workers. Execute tasks handling data.
    Delta,
    /// New or untrusted nodes. Limited access.
    Omega,
}

impl Default for WolfRank {
    fn default() -> Self {
        WolfRank::Omega
    }
}

pub mod wolf_pack;

/// Represents a single member of the pack (a node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackMember {
    pub peer_id: PeerId,
    pub rank: WolfRank,
    pub trust_score: f64,
}

impl PackMember {
    pub fn new(peer_id: PeerId, rank: WolfRank) -> Self {
        Self {
            peer_id,
            rank,
            trust_score: 50.0, // Start neutral
        }
    }
}

/// Manages the hierarchy and state of the Wolf Pack.
pub struct WolfPack {
    /// The discovery service to get the list of peers.
    discovery: Arc<DiscoveryService>,
    /// All members of the pack, indexed by Peer ID.
    members: HashMap<PeerId, PackMember>,
    /// Name of this pack (cluster).
    pub pack_name: String,
}

impl WolfPack {
    pub fn new(pack_name: String, discovery_config: DiscoveryConfig) -> anyhow::Result<Self> {
        let discovery = Arc::new(DiscoveryService::new(discovery_config)?);
        Ok(Self {
            discovery,
            members: HashMap::new(),
            pack_name,
        })
    }

    /// Starts the background services.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        self.discovery.start().await?;
        Ok(())
    }

    /// Adds or updates a member in the pack.
    pub async fn update_member(&mut self, peer_id: PeerId, rank: Option<WolfRank>) {
        let trust_score = self.get_peer_trust_score(&peer_id).await;

        if let Some(member) = self.members.get_mut(&peer_id) {
            if let Some(r) = rank {
                member.rank = r;
            }
            member.trust_score = trust_score;
        } else {
            let member = PackMember {
                peer_id: peer_id.clone(),
                rank: rank.unwrap_or_default(),
                trust_score,
            };
            self.members.insert(peer_id.clone(), member);
        }
    }

    /// Get the trust score for a peer.
    async fn get_peer_trust_score(&self, peer_id: &PeerId) -> f64 {
        if let Some(peer_info) = self.discovery.get_peer(peer_id).await {
            peer_info.trust_score()
        } else {
            0.0
        }
    }

    /// Returns a list of all Alphas (should ideally be one).
    pub fn get_alphas(&self) -> Vec<&PackMember> {
        self.members
            .values()
            .filter(|m| m.rank == WolfRank::Alpha)
            .collect()
    }
}
