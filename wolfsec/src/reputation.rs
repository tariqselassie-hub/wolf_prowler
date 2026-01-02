//! Peer Reputation Management for WolfSec
//!
//! This module handles the "wolf pack" logic by managing peer reputation and trust scores.

use wolf_net::peer::{PeerId, PeerInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, info};

/// Manages the reputation of peers in the network.
pub struct ReputationManager {
    known_peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    reputation_update_interval: Duration,
    running: bool,
}

impl ReputationManager {
    /// Creates a new `ReputationManager`.
    pub fn new(
        known_peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
        reputation_update_interval: Duration,
    ) -> Self {
        Self {
            known_peers,
            reputation_update_interval,
            running: false,
        }
    }

    /// Starts the reputation manager's background task.
    pub async fn start(&mut self) {
        if self.running {
            return;
        }
        self.running = true;
        info!("🐺 Starting Reputation Manager...");

        let known_peers = self.known_peers.clone();
        let update_interval = self.reputation_update_interval;

        tokio::spawn(async move {
            let mut interval = interval(update_interval);
            loop {
                interval.tick().await;
                debug!("Updating peer reputations...");
                let mut peers = known_peers.write().await;

                for peer_info in peers.values_mut() {
                    // Simple reputation logic:
                    // - Increase score for being online.
                    // - Decrease score for being offline (this is handled by the discovery service).
                    // - A more advanced implementation would consider latency, successful interactions, etc.

                    let current_score = peer_info.trust_score();
                    let new_score = (current_score + 0.01).min(1.0); // Slowly increase score for being present
                    peer_info.update_trust_score(new_score);
                }
                info!("Peer reputations updated.");
            }
        });
    }

    /// Reports a successful interaction with a peer.
    pub async fn report_successful_interaction(&self, peer_id: &PeerId) {
        let mut peers = self.known_peers.write().await;
        if let Some(peer_info) = peers.get_mut(peer_id) {
            let new_score = (peer_info.trust_score() + 0.05).min(1.0);
            peer_info.update_trust_score(new_score);
            debug!("Increased trust score for peer {}", peer_id);
        }
    }

    /// Reports a failed interaction with a peer.
    pub async fn report_failed_interaction(&self, peer_id: &PeerId) {
        let mut peers = self.known_peers.write().await;
        if let Some(peer_info) = peers.get_mut(peer_id) {
            let new_score = (peer_info.trust_score() - 0.1).max(0.0);
            peer_info.update_trust_score(new_score);
            debug!("Decreased trust score for peer {}", peer_id);
        }
    }
}
