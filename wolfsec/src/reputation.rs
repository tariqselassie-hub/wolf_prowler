use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use wolf_net::peer::PeerId;

/// Categories of behavior that contribute to overall reputation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReputationCategory {
    Networking,   // Latency, uptime, connection stability
    Security,     // Threat detection, hunt participation
    Coordination, // Election voting, prestige, pack loyalty
}

/// Classification of a peer based on their reputation score
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustTier {
    HighlyTrusted, // Score > 0.9
    Trusted,       // Score > 0.7
    Neutral,       // Score 0.4 - 0.7
    Suspicious,    // Score 0.2 - 0.4
    Malicious,     // Score < 0.2
}

/// A single event that impacted a peer's reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEvent {
    pub timestamp: DateTime<Utc>,
    pub category: ReputationCategory,
    pub impact: f64,
    pub description: String,
}

/// Comprehensive reputation profile for a network peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    pub peer_id: String,
    pub total_score: f64,
    pub category_scores: HashMap<ReputationCategory, f64>,
    pub last_updated: DateTime<Utc>,
    pub event_history: Vec<ReputationEvent>,
    pub is_permanently_blocked: bool,
}

impl PeerReputation {
    pub fn new(peer_id: String) -> Self {
        let mut category_scores = HashMap::new();
        category_scores.insert(ReputationCategory::Networking, 0.5);
        category_scores.insert(ReputationCategory::Security, 0.5);
        category_scores.insert(ReputationCategory::Coordination, 0.5);

        Self {
            peer_id,
            total_score: 0.5,
            category_scores,
            last_updated: Utc::now(),
            event_history: Vec::new(),
            is_permanently_blocked: false,
        }
    }

    pub fn tier(&self) -> TrustTier {
        match self.total_score {
            s if s >= 0.9 => TrustTier::HighlyTrusted,
            s if s >= 0.7 => TrustTier::Trusted,
            s if s >= 0.4 => TrustTier::Neutral,
            s if s >= 0.2 => TrustTier::Suspicious,
            _ => TrustTier::Malicious,
        }
    }
}

/// Configuration for the reputation system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    pub decay_rate: f64,            // Amount to decay per interval
    pub decay_interval_secs: u64,   // How often to apply decay
    pub event_history_limit: usize, // Max events to store per peer
    pub auto_block_threshold: f64,  // Score below which a peer is auto-blocked
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            decay_rate: 0.01,
            decay_interval_secs: 3600, // Hourly
            event_history_limit: 50,
            auto_block_threshold: 0.15,
        }
    }
}

/// The core reputation engine
#[derive(Debug, Clone)]
pub struct ReputationSystem {
    peers: Arc<RwLock<HashMap<String, PeerReputation>>>,
    config: ReputationConfig,
}

impl ReputationSystem {
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Records a behavioral event for a peer and updates their score
    pub async fn report_event(
        &self,
        peer_id: &str,
        category: ReputationCategory,
        impact: f64,
        description: String,
    ) {
        let mut peers = self.peers.write().await;
        let entry = peers
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerReputation::new(peer_id.to_string()));

        if entry.is_permanently_blocked {
            return;
        }

        // Update category score
        let cat_score = entry.category_scores.entry(category).or_insert(0.5);
        *cat_score = (*cat_score + impact).clamp(0.0, 1.0);

        // Recalculate total score (weighted average)
        entry.total_score = entry.category_scores.values().sum::<f64>() / 3.0;
        entry.last_updated = Utc::now();

        // Record event
        entry.event_history.push(ReputationEvent {
            timestamp: Utc::now(),
            category,
            impact,
            description: description.clone(),
        });

        // Prune history
        if entry.event_history.len() > self.config.event_history_limit {
            entry.event_history.remove(0);
        }

        // Check for auto-block
        if entry.total_score < self.config.auto_block_threshold {
            warn!(
                "🚨 Peer {} dropped below auto-block threshold ({:.2})",
                peer_id, entry.total_score
            );
            entry.is_permanently_blocked = true;
        }

        debug!(
            "Updated reputation for {}: score={:.2}, category={:?}",
            peer_id, entry.total_score, category
        );
    }

    /// Applies temporal decay to all peers
    /// Positive scores decay toward neutral (0.5), negative scores also trend toward neutral
    pub async fn apply_decay(&self) {
        let mut peers = self.peers.write().await;
        let decay = self.config.decay_rate;

        for entry in peers.values_mut() {
            if entry.is_permanently_blocked {
                continue;
            }

            for score in entry.category_scores.values_mut() {
                if *score > 0.5 {
                    *score = (*score - decay).max(0.5);
                } else if *score < 0.5 {
                    *score = (*score + decay).min(0.5);
                }
            }
            entry.total_score = entry.category_scores.values().sum::<f64>() / 3.0;
        }
        debug!("Applied reputation decay to {} peers", peers.len());
    }

    /// Returns the current reputation profile for a peer
    pub async fn get_reputation(&self, peer_id: &str) -> Option<PeerReputation> {
        let peers = self.peers.read().await;
        peers.get(peer_id).cloned()
    }

    /// Retrieves the reputation score for a specific peer.
    pub async fn get_peer_reputation(&self, peer_id: &str) -> f64 {
        let peers = self.peers.read().await;
        peers.get(peer_id).map(|p| p.total_score).unwrap_or(0.5)
    }

    /// Returns the total number of peers tracked
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Calculates the average reputation score across the network
    pub async fn average_reputation(&self) -> f64 {
        let peers = self.peers.read().await;
        if peers.is_empty() {
            return 0.5;
        }
        peers.values().map(|p| p.total_score).sum::<f64>() / peers.len() as f64
    }

    /// Exports all reputation data for persistence
    pub async fn export_state(&self) -> HashMap<String, PeerReputation> {
        let peers = self.peers.read().await;
        peers.clone()
    }

    /// Imports reputation data (e.g., from database on startup)
    pub async fn import_state(&self, state: HashMap<String, PeerReputation>) {
        let mut peers = self.peers.write().await;
        *peers = state;
        info!("Imported reputation state for {} peers", peers.len());
    }

    /// Returns a list of recent reputation trends for visualization
    pub async fn get_trends(&self) -> Vec<f64> {
        // In a real implementation, this would pull from a time-series buffer.
        // For now, we return a simulated trend line.
        vec![0.45, 0.48, 0.52, 0.51, 0.55, 0.54, 0.60]
    }

    // Additional methods for API compatibility
    pub async fn trusted_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.values().filter(|p| p.total_score >= 0.7).count()
    }

    pub async fn suspicious_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.total_score < 0.4 && p.total_score >= 0.2)
            .count()
    }

    pub async fn active_peer_count(&self) -> usize {
        self.peer_count().await
    }

    pub async fn get_peer_message_count(&self, _peer_id: &str) -> usize {
        0 // Placeholder
    }

    pub async fn get_peer_threat_count(&self, _peer_id: &str) -> usize {
        0 // Placeholder
    }

    pub async fn get_peer_last_seen(&self, _peer_id: &str) -> Option<DateTime<Utc>> {
        Some(Utc::now())
    }

    pub async fn get_peer_last_updated(&self, _peer_id: &str) -> Option<DateTime<Utc>> {
        Some(Utc::now())
    }

    pub async fn is_peer_connected(&self, _peer_id: &str) -> bool {
        false // Placeholder
    }

    pub async fn get_pack_members(&self) -> Vec<String> {
        Vec::new() // Placeholder
    }

    pub async fn get_role_count(&self, _role: &str) -> usize {
        0 // Placeholder
    }

    pub async fn get_total_prestige(&self) -> i32 {
        0 // Placeholder
    }

    pub async fn get_average_prestige(&self) -> f64 {
        0.0 // Placeholder
    }

    pub async fn get_prestige_gained_today(&self) -> i32 {
        0 // Placeholder
    }

    pub async fn get_prestige_decayed_today(&self) -> i32 {
        0 // Placeholder
    }

    pub async fn get_admin_actions(&self) -> Vec<String> {
        Vec::new() // Placeholder
    }
}

#[async_trait]
impl wolf_net::swarm::ReputationReporter for ReputationSystem {
    async fn report_event(&self, peer_id: &str, category: &str, impact: f64, description: String) {
        let cat = match category {
            "Networking" => ReputationCategory::Networking,
            "Security" => ReputationCategory::Security,
            "Coordination" => ReputationCategory::Coordination,
            _ => {
                debug!(
                    "Unknown reputation category: {}, defaulting to Networking",
                    category
                );
                ReputationCategory::Networking
            }
        };
        self.report_event(peer_id, cat, impact, description).await;
    }
}

/// Helper to start the background decay task
pub fn start_reputation_decay_task(system: Arc<ReputationSystem>) {
    let interval_secs = system.config.decay_interval_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            system.apply_decay().await;
        }
    });
}
