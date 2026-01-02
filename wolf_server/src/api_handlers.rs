// Additional API handler implementations for wolf_server persistence

use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::header,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

// Historical peer data endpoint
pub async fn get_peers_history(
    State(state): State<AppState>,
    Query(query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        match persistence.get_active_peers().await {
            Ok(peers) => {
                let total = peers.len();
                let peers: Vec<_> = peers
                    .into_iter()
                    .skip(query.offset as usize)
                    .take(query.limit as usize)
                    .collect();

                Json(serde_json::json!({
                    "peers": peers,
                    "total": total,
                    "limit": query.limit,
                    "offset": query.offset,
                }))
            }
            Err(e) => Json(serde_json::json!({
                "error": e.to_string()
            })),
        }
    } else {
        Json(serde_json::json!({
            "error": "Persistence not enabled"
        }))
    }
}

// Peer metrics endpoint
pub async fn get_peer_metrics(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
    Query(query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        // Query peer metrics from database
        let query_result = sqlx::query!(
            r#"
            SELECT * FROM peer_metrics
            WHERE peer_id = $1
            ORDER BY timestamp DESC
            LIMIT $2 OFFSET $3
            "#,
            peer_id,
            query.limit,
            query.offset
        )
        .fetch_all(persistence.pool())
        .await;

        match query_result {
            Ok(metrics) => {
                let mapped_metrics: Vec<_> = metrics
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "peer_id": m.peer_id,
                            "timestamp": m.timestamp,
                            "latency_ms": m.latency_ms,
                            "messages_sent": m.messages_sent,
                            "messages_received": m.messages_received,
                            "health_score": m.health_score,
                        })
                    })
                    .collect();

                Json(serde_json::json!({
                    "peer_id": peer_id,
                    "metrics": mapped_metrics,
                    "count": metrics.len(),
                }))
            }
            Err(e) => Json(serde_json::json!({
                "error": e.to_string()
            })),
        }
    } else {
        Json(serde_json::json!({
            "error": "Persistence not enabled"
        }))
    }
}

// Security alerts history endpoint
pub async fn get_alerts_history(
    State(state): State<AppState>,
    Query(query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        match persistence.get_recent_alerts(query.limit).await {
            Ok(alerts) => Json(serde_json::json!({
                "alerts": alerts,
                "count": alerts.len(),
            })),
            Err(e) => Json(serde_json::json!({
                "error": e.to_string()
            })),
        }
    } else {
        Json(serde_json::json!({
            "error": "Persistence not enabled"
        }))
    }
}

// Audit logs endpoint
pub async fn get_audit_logs(
    State(state): State<AppState>,
    Query(query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        // Query audit logs
        let query_result = sqlx::query!(
            r#"
            SELECT * FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT $1 OFFSET $2
            "#,
            query.limit,
            query.offset
        )
        .fetch_all(persistence.pool())
        .await;

        match query_result {
            Ok(logs) => {
                let mapped_logs: Vec<_> = logs
                    .iter()
                    .map(|l| {
                        serde_json::json!({
                            "id": l.id,
                            "timestamp": l.timestamp,
                            "action": l.action,
                            "actor": l.actor,
                            "resource": l.resource,
                            "resource_type": l.resource_type,
                            "result": l.result,
                            "details": l.details,
                            "ip_address": l.ip_address,
                            "user_agent": l.user_agent,
                        })
                    })
                    .collect();

                Json(serde_json::json!({
                    "logs": mapped_logs,
                    "count": logs.len(),
                }))
            }
            Err(e) => Json(serde_json::json!({
                "error": e.to_string()
            })),
        }
    } else {
        Json(serde_json::json!({
            "error": "Persistence not enabled"
        }))
    }
}

// Metrics timeline endpoint
pub async fn get_metrics_timeline(
    State(state): State<AppState>,
    Query(query): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        let query_result = sqlx::query!(
            r#"
            SELECT 
                timestamp,
                COUNT(DISTINCT peer_id) as peer_count,
                AVG(latency_ms)::FLOAT8 as avg_latency,
                SUM(messages_sent)::BIGINT as total_messages_sent,
                SUM(messages_received)::BIGINT as total_messages_received,
                AVG(health_score)::FLOAT8 as avg_health_score
            FROM peer_metrics
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY timestamp
            ORDER BY timestamp DESC
            LIMIT $1
            "#,
            query.limit
        )
        .fetch_all(persistence.pool())
        .await;

        match query_result {
            Ok(timeline) => {
                let mapped_timeline: Vec<_> = timeline
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "timestamp": t.timestamp,
                            "peer_count": t.peer_count,
                            "avg_latency": t.avg_latency.as_ref().map(|v: &f64| v.to_string().parse::<f64>().unwrap_or(0.0)),
                            "total_messages_sent": t.total_messages_sent.as_ref().map(|v: &i64| v.to_string().parse::<i64>().unwrap_or(0)),
                            "total_messages_received": t.total_messages_received.as_ref().map(|v: &i64| v.to_string().parse::<i64>().unwrap_or(0)),
                            "avg_health_score": t.avg_health_score.as_ref().map(|v: &f64| v.to_string().parse::<f64>().unwrap_or(0.0)),
                        })
                    })
                    .collect();

                Json(serde_json::json!({
                    "timeline": mapped_timeline,
                    "count": timeline.len(),
                }))
            }
            Err(e) => Json(serde_json::json!({
                "error": e.to_string()
            })),
        }
    } else {
        Json(serde_json::json!({
            "error": "Persistence not enabled"
        }))
    }
}

// CSV export for peers
pub async fn export_peers_csv(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(persistence) = &state.persistence {
        match persistence.get_active_peers().await {
            Ok(peers) => {
                let mut csv =
                    String::from("peer_id,service_type,system_type,status,trust_score,last_seen\n");
                for peer in peers {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        peer.peer_id,
                        peer.service_type,
                        peer.system_type,
                        peer.status,
                        peer.trust_score
                            .as_ref()
                            .map(|v| v.to_string().parse::<f64>().unwrap_or(0.0))
                            .unwrap_or(0.0),
                        peer.last_seen.map(|d| d.to_rfc3339()).unwrap_or_default()
                    ));
                }

                (
                    [(header::CONTENT_TYPE, "text/csv")],
                    [(
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"peers.csv\"",
                    )],
                    csv,
                )
            }
            Err(e) => (
                [(header::CONTENT_TYPE, "text/plain")],
                [(header::CONTENT_DISPOSITION, "")],
                format!("Error: {}", e),
            ),
        }
    } else {
        (
            [(header::CONTENT_TYPE, "text/plain")],
            [(header::CONTENT_DISPOSITION, "")],
            "Persistence not enabled".to_string(),
        )
    }
}

// JSON export for peers
pub async fn export_peers_json(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(persistence) = &state.persistence {
        match persistence.get_active_peers().await {
            Ok(peers) => {
                let json = serde_json::to_string_pretty(&peers).unwrap_or_default();
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    [(
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"peers.json\"",
                    )],
                    json,
                )
            }
            Err(e) => (
                [(header::CONTENT_TYPE, "text/plain")],
                [(header::CONTENT_DISPOSITION, "")],
                format!("Error: {}", e),
            ),
        }
    } else {
        (
            [(header::CONTENT_TYPE, "text/plain")],
            [(header::CONTENT_DISPOSITION, "")],
            "Persistence not enabled".to_string(),
        )
    }
}

// CSV export for alerts
pub async fn export_alerts_csv(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(persistence) = &state.persistence {
        match persistence.get_recent_alerts(1000).await {
            Ok(alerts) => {
                let mut csv = String::from("timestamp,severity,status,title,category,source\n");
                for alert in alerts {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        alert.timestamp.unwrap_or_default(),
                        alert.severity,
                        alert.status,
                        alert.title,
                        alert.category,
                        alert.source
                    ));
                }

                (
                    [(header::CONTENT_TYPE, "text/csv")],
                    [(
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"alerts.csv\"",
                    )],
                    csv,
                )
            }
            Err(e) => (
                [(header::CONTENT_TYPE, "text/plain")],
                [(header::CONTENT_DISPOSITION, "")],
                format!("Error: {}", e),
            ),
        }
    } else {
        (
            [(header::CONTENT_TYPE, "text/plain")],
            [(header::CONTENT_DISPOSITION, "")],
            "Persistence not enabled".to_string(),
        )
    }
}

// CSV export for metrics
pub async fn export_metrics_csv(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(persistence) = &state.persistence {
        let query_result = sqlx::query!(
            r#"
            SELECT * FROM peer_metrics
            ORDER BY timestamp DESC
            LIMIT 10000
            "#
        )
        .fetch_all(persistence.pool())
        .await;

        match query_result {
            Ok(metrics) => {
                let mut csv = String::from(
                    "peer_id,timestamp,latency_ms,messages_sent,messages_received,health_score\n",
                );
                for m in metrics {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        m.peer_id,
                        m.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                        m.latency_ms.unwrap_or(0),
                        m.messages_sent.unwrap_or(0),
                        m.messages_received.unwrap_or(0),
                        m.health_score
                            .as_ref()
                            .map(|v: &f32| v.to_string().parse::<f64>().unwrap_or(0.0))
                            .unwrap_or(0.0)
                    ));
                }

                (
                    [(header::CONTENT_TYPE, "text/csv")],
                    [(
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"metrics.csv\"",
                    )],
                    csv,
                )
            }
            Err(e) => (
                [(header::CONTENT_TYPE, "text/plain")],
                [(header::CONTENT_DISPOSITION, "")],
                format!("Error: {}", e),
            ),
        }
    } else {
        (
            [(header::CONTENT_TYPE, "text/plain")],
            [(header::CONTENT_DISPOSITION, "")],
            "Persistence not enabled".to_string(),
        )
    }
}
