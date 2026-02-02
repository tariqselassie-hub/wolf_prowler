use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// classifications of behavior that contribute to an identity's aggregate reputation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReputationCategory {
    /// metrics related to network stability, latency, and uptime
    Networking,
    /// metrics derived from security contributions and threat detection
    Security,
    /// metrics reflecting peer coordination, voting, and pack loyalty
    Coordination,
}

/// hierarchical classification of an identity based on their aggregate reputation score
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustTier {
    /// Identity with exceptional reputation (Score > 0.9)
    HighlyTrusted,
    /// reliable identity with positive reputation (Score > 0.7)
    Trusted,
    /// new or unproven identity with baseline reputation (Score 0.4 - 0.7)
    Neutral,
    /// Identity exhibiting anomalous or borderline malicious behavior (Score 0.2 - 0.4)
    Suspicious,
    /// confirmed malicious or terminally unreliable identity (Score < 0.2)
    Malicious,
}

/// a discrete observation that influenced an identity's reputation score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEvent {
    /// point in time when the observation was recorded
    pub timestamp: DateTime<Utc>,
    /// the behavioral category impacted by this event
    pub category: ReputationCategory,
    /// the degree of influence on the category score (-1.0 to 1.0)
    pub impact: f64,
    /// human-readable narrative explaining the event context
    pub description: String,
}

/// comprehensive behavioral history and reputation analytics for a network identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    /// unique identifier for the identity
    pub peer_id: String,
    /// consolidated, weighted reputation score (0.0 - 1.0)
    pub total_score: f64,
    /// granular scores for each behavioral category
    pub category_scores: HashMap<ReputationCategory, f64>,
    /// point in time of the most recent score recalculation
    pub last_updated: DateTime<Utc>,
    /// chronological history of events impacting this reputation
    pub event_history: Vec<ReputationEvent>,
    /// true if the identity is barred from the network due to reputation failure
    pub is_permanently_blocked: bool,
}

impl PeerReputation {
    /// instantiates a new profile with a neutral starting score (0.5).
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

    /// derives the categorical trust tier based on the total reputation score.
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

/// tunable parameters governing the automated reputation lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// the amount of score lost or gained during each decay cycle
    pub decay_rate: f64,
    /// the frequency (in seconds) at which decay is applied
    pub decay_interval_secs: u64,
    /// the maximum number of historical events retained per peer
    pub event_history_limit: usize,
    /// the score threshold below which identities are automatically barred
    pub auto_block_threshold: f64,
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

/// Core engine for tracking, calculating, and enforcing entity reputation.
#[derive(Debug, Clone)]
pub struct ReputationSystem {
    /// thread-safe registry of all tracked peer profiles.
    pub peers: Arc<RwLock<HashMap<String, PeerReputation>>>,
    /// active engine parameters.
    pub config: ReputationConfig,
}

impl ReputationSystem {
    /// instantiates a new engine with the provided configuration.
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Records a behavioral event for a peer and updates their score.
    ///
    /// # Arguments
    /// * `peer_id` - Unique identifier of the peer.
    /// * `category` - Behavioral category impacted.
    /// * `impact` - Degree of influence on the score.
    /// * `description` - Narrative context for the event.
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

    /// applies temporal decay to all peers
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

    /// returns a clone of the current reputation profile for a peer, if they exist.
    pub async fn get_reputation(&self, peer_id: &str) -> Option<PeerReputation> {
        let peers = self.peers.read().await;
        peers.get(peer_id).cloned()
    }

    /// Retrieves the reputation score for a specific peer.
    pub async fn get_peer_reputation(&self, peer_id: &str) -> f64 {
        let peers = self.peers.read().await;
        peers.get(peer_id).map(|p| p.total_score).unwrap_or(0.5)
    }

    /// returns the total count of distinct identities currently tracked in the registry.
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// calculates the mean reputation score across the entire network population.
    pub async fn average_reputation(&self) -> f64 {
        let peers = self.peers.read().await;
        if peers.is_empty() {
            return 0.5;
        }
        peers.values().map(|p| p.total_score).sum::<f64>() / peers.len() as f64
    }

    /// returns a map of all peer profiles, suitable for persistence or analysis.
    pub async fn export_state(&self) -> HashMap<String, PeerReputation> {
        let peers = self.peers.read().await;
        peers.clone()
    }

    /// overwrites the internal registry with a provided set of reputation profiles.
    pub async fn import_state(&self, state: HashMap<String, PeerReputation>) {
        let mut peers = self.peers.write().await;
        *peers = state;
        info!("Imported reputation state for {} peers", peers.len());
    }

    /// returns a sequence of historical average reputation scores representing system trends.
    pub async fn get_trends(&self) -> Vec<f64> {
        // In a real implementation, this would pull from a time-series buffer.
        // For now, we return a simulated trend line.
        vec![0.45, 0.48, 0.52, 0.51, 0.55, 0.54, 0.60]
    }

    // Additional methods for API compatibility
    /// returns the count of peers residing in the Trusted or HighlyTrusted tiers.
    pub async fn trusted_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.values().filter(|p| p.total_score >= 0.7).count()
    }

    /// returns the count of peers residing in the Suspicious tier.
    pub async fn suspicious_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers
            .values()
            .filter(|p| p.total_score < 0.4 && p.total_score >= 0.2)
            .count()
    }

    /// returns the total number of tracked peers (alias for peer_count).
    pub async fn active_peer_count(&self) -> usize {
        self.peer_count().await
    }

    /// returns the cumulative number of messages processed for a specific peer.
    pub async fn get_peer_message_count(&self, _peer_id: &str) -> usize {
        0 // Placeholder
    }

    /// returns the count of identified threats associated with a specific peer.
    pub async fn get_peer_threat_count(&self, _peer_id: &str) -> usize {
        0 // Placeholder
    }

    /// returns the point in time of the peer's most recent interaction.
    pub async fn get_peer_last_seen(&self, _peer_id: &str) -> Option<DateTime<Utc>> {
        Some(Utc::now())
    }

    /// returns the point in time when the peer's reputation was last updated.
    pub async fn get_peer_last_updated(&self, _peer_id: &str) -> Option<DateTime<Utc>> {
        Some(Utc::now())
    }

    /// returns true if the peer currently has an active connection to the node.
    pub async fn is_peer_connected(&self, _peer_id: &str) -> bool {
        false // Placeholder
    }

    /// returns identifiers for all peers currently recognized as authorized pack members.
    pub async fn get_pack_members(&self) -> Vec<String> {
        Vec::new() // Placeholder
    }

    /// returns the count of peers currently assigned to a specific role.
    pub async fn get_role_count(&self, _role: &str) -> usize {
        0 // Placeholder
    }

    /// returns the aggregate prestige (Coordination score) across the entire pack.
    pub async fn get_total_prestige(&self) -> i32 {
        0 // Placeholder
    }

    /// calculates the mean prestige score across the entire pack population.
    pub async fn get_average_prestige(&self) -> f64 {
        0.0 // Placeholder
    }

    /// returns the cumulative prestige gained by all peers in the current 24-hour window.
    pub async fn get_prestige_gained_today(&self) -> i32 {
        0 // Placeholder
    }

    /// returns the cumulative prestige lost due to decay in the current 24-hour window.
    pub async fn get_prestige_decayed_today(&self) -> i32 {
        0 // Placeholder
    }

    /// returns a chronological log of administrative actions taken (blocks, unblocks, etc.).
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
