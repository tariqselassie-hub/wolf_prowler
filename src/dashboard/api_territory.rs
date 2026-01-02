use crate::dashboard::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Territory peer information for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerritoryPeer {
    pub id: String,
    pub address: String,
    pub status: String,
    pub latency_ms: u64,
    pub trust_score: f64,
    pub zone: String, // "alpha", "beta", "omega", "neutral"
    pub position: Position,
    pub capabilities: Vec<String>,
    pub last_seen: String,
    pub is_local: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Serialize)]
pub struct TerritoryResponse {
    pub total_peers: usize,
    pub online_peers: usize,
    pub zones: HashMap<String, usize>,
    pub peers: Vec<TerritoryPeer>,
}

/// API: Get territory peers for visualization
pub async fn api_territory_peers(
    State(state): State<AppState>,
) -> Result<Json<TerritoryResponse>, axum::http::StatusCode> {
    // Get peers from SwarmManager's peer registry
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = wolf_net::SwarmCommand::ListPeers { responder: tx };

    if state
        .swarm_manager
        .command_sender()
        .send(cmd)
        .await
        .is_err()
    {
        return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    let entity_infos = match rx.await {
        Ok(infos) => infos,
        Err(_) => return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
    };

    let mut territory_peers = Vec::new();
    let mut zones: HashMap<String, usize> = HashMap::new();
    let mut online_count = 0;

    for (index, entity_info) in entity_infos.iter().enumerate() {
        let is_online = entity_info.is_online();
        if is_online {
            online_count += 1;
        }

        // Determine zone based on trust score
        let zone = if entity_info.trust_score >= 0.8 {
            "alpha"
        } else if entity_info.trust_score >= 0.5 {
            "beta"
        } else if entity_info.trust_score >= 0.3 {
            "omega"
        } else {
            "neutral"
        };

        *zones.entry(zone.to_string()).or_insert(0) += 1;

        // Calculate position in a circular layout
        let angle = (index as f64 / entity_infos.len() as f64) * 2.0 * std::f64::consts::PI;
        let radius = match zone {
            "alpha" => 30.0,
            "beta" => 50.0,
            "omega" => 70.0,
            _ => 90.0,
        };

        let position = Position {
            x: angle.cos() * radius,
            y: angle.sin() * radius,
        };

        // Get first address or use placeholder
        let address = entity_info
            .addresses
            .first()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        territory_peers.push(TerritoryPeer {
            id: entity_info.entity_id.peer_id.to_string(),
            address,
            status: format!("{:?}", entity_info.status),
            latency_ms: entity_info.metrics.latency_ms,
            trust_score: entity_info.trust_score,
            zone: zone.to_string(),
            position,
            capabilities: entity_info.capabilities.clone(),
            last_seen: entity_info.last_seen.to_rfc3339(),
            is_local: entity_info.addresses.iter().any(|addr| {
                addr.ip().is_loopback()
                    || (addr.ip().is_ipv4() && addr.ip().to_string().starts_with("192.168."))
            }),
        });
    }

    Ok(Json(TerritoryResponse {
        total_peers: territory_peers.len(),
        online_peers: online_count,
        zones,
        peers: territory_peers,
    }))
}
