//! Simple metrics calculation for Wolf Net
//!
//! Provides helpers for updating peer metrics and calculating health scores.

use crate::peer::{EntityInfo, PeerId};
use std::collections::HashMap;

/// Update metrics for a peer
pub fn update_peer_metrics<S: std::hash::BuildHasher>(
    registry: &mut HashMap<PeerId, EntityInfo, S>,
    peer_id: &PeerId,
    update_fn: impl FnOnce(&mut EntityInfo),
) {
    if let Some(info) = registry.get_mut(peer_id) {
        update_fn(info);
        info.metrics.update_health();
    }
}

/// Calculate network health score for the entire node (placeholder)
pub fn calculate_network_health<S: std::hash::BuildHasher>(
    registry: &HashMap<PeerId, EntityInfo, S>,
) -> f64 {
    if registry.is_empty() {
        return 1.0;
    }

    let total_health: f64 = registry
        .values()
        .map(|info| info.metrics.health_score)
        .sum();
    #[allow(clippy::cast_precision_loss)]
    let len = registry.len() as f64;
    total_health / len
}
