use crate::discovery::{DiscoveryConfig, DiscoveryService};
use crate::peer::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod coordinator;
pub mod election;
pub mod error;
pub mod howl;
pub mod messaging;
pub mod state;
pub mod state_machine;

pub use state::WolfRole;

pub type WolfRank = WolfRole;

pub use election::ElectionManager;

pub mod hierarchy {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WolfCommunicationRules {
        pub allow_inter_pack_comms: bool,
    }

    impl Default for WolfCommunicationRules {
        fn default() -> Self {
            Self {
                allow_inter_pack_comms: true,
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct WolfDenConfig {
        pub pack_name: String,
    }

    pub type PackRank = super::WolfRank;
}

pub mod territory {
    use super::hierarchy::PackRank;
    use crate::peer::PeerId;
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};

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
}

/// Represents a single member of the pack (a node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackMember {
    pub peer_id: PeerId,
    pub rank: WolfRole,
    pub trust_score: f64,
}

impl PackMember {
    pub fn new(peer_id: PeerId, rank: WolfRole) -> Self {
        Self {
            peer_id,
            rank,
            trust_score: 50.0, // Start neutral
        }
    }
}

/// Manages the hierarchy and state of the Wolf Pack.
#[derive(Clone, Serialize, Deserialize)]
pub struct WolfPack {
    /// The discovery service to get the list of peers.
    #[serde(skip)]
    discovery: Option<Arc<Mutex<DiscoveryService>>>,
    /// All members of the pack, indexed by Peer ID.
    pub members: HashMap<PeerId, PackMember>,
    /// Name of this pack (cluster).
    pub pack_name: String,
    /// ID of the Alpha node
    pub alpha_id: Option<PeerId>,
    /// Manages Raft-based Alpha elections
    pub election_manager: Option<ElectionManager>,
}

impl WolfPack {
    pub fn new(pack_name: String, discovery_config: DiscoveryConfig) -> anyhow::Result<Self> {
        let (service, _) = DiscoveryService::new(discovery_config)?;
        let discovery = Arc::new(Mutex::new(service));
        Ok(Self {
            discovery: Some(discovery),
            members: HashMap::new(),
            pack_name,
            alpha_id: None,
            election_manager: None,
        })
    }

    pub fn enable_elections(&mut self, local_peer_id: PeerId, prestige: u32) {
        self.election_manager = Some(ElectionManager::new(local_peer_id, prestige));
    }

    /// Starts the background services.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if let Some(discovery) = &self.discovery {
            let mut discovery = discovery.lock().await;
            discovery.start().await?;
        }
        Ok(())
    }

    /// Adds or updates a member in the pack.
    pub async fn update_member(&mut self, peer_id: PeerId, rank: Option<WolfRank>) {
        let trust_score = self.get_peer_trust_score(&peer_id).await;

        if let Some(member) = self.members.get_mut(&peer_id) {
            if let Some(r) = rank {
                member.rank = r;
                if r == WolfRole::Alpha {
                    self.alpha_id = Some(peer_id.clone());
                }
            }
            member.trust_score = trust_score;
        } else {
            let r = rank.unwrap_or_default();
            if r == WolfRole::Alpha {
                self.alpha_id = Some(peer_id.clone());
            }
            let member = PackMember {
                peer_id: peer_id.clone(),
                rank: r,
                trust_score,
            };
            self.members.insert(peer_id.clone(), member);
        }
    }

    /// Get the trust score for a peer.
    async fn get_peer_trust_score(&self, peer_id: &PeerId) -> f64 {
        if let Some(discovery) = &self.discovery {
            if let Some(peer_info) = discovery.lock().await.get_peer(peer_id).await {
                return peer_info.trust_score();
            }
        }
        0.0 // Default trust if discovery is not available
    }

    /// Returns a list of all Alphas (should ideally be one).
    pub fn get_alphas(&self) -> Vec<&PackMember> {
        self.members
            .values()
            .filter(|m| m.rank == WolfRole::Alpha)
            .collect()
    }
}
