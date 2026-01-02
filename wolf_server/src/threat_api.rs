// Threat Intelligence API Handlers

use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Deserialize)]
pub struct ThreatQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    threat_type: Option<String>,
    #[serde(default)]
    severity: Option<String>,
}

fn default_limit() -> i64 {
    100
}

#[derive(Serialize)]
pub struct ThreatStats {
    pub total_threats: i64,
    pub malicious_ips: i64,
    pub vulnerabilities: i64,
    pub intrusion_attempts: i64,
    pub active_threats: i64,
}

/// GET /api/v1/threats/ips - List malicious IPs
pub async fn get_malicious_ips(
    State(state): State<AppState>,
    Query(query): Query<ThreatQuery>,
) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        let mut sql_query = String::from(
            "SELECT * FROM threat_intelligence WHERE threat_type = 'malicious_ip' AND active = true"
        );

        if let Some(severity) = &query.severity {
            sql_query.push_str(&format!(" AND severity = '{}'", severity));
        }

        sql_query.push_str(&format!(" ORDER BY last_seen DESC LIMIT {}", query.limit));

        let query_result = sqlx::query(&sql_query).fetch_all(persistence.pool()).await;

        match query_result {
            Ok(rows) => {
                let threats: Vec<serde_json::Value> = rows.iter().map(|row| {
                    serde_json::json!({
                        "ip": row.try_get::<serde_json::Value, _>("indicators").ok(),
                        "severity": row.try_get::<String, _>("severity").ok(),
                        "first_seen": row.try_get::<chrono::DateTime<chrono::Utc>, _>("first_seen").ok(),
                        "last_seen": row.try_get::<chrono::DateTime<chrono::Utc>, _>("last_seen").ok(),
                        "source": row.try_get::<String, _>("source").ok(),
                        "confidence": row.try_get::<f64, _>("confidence").ok(),
                    })
                }).collect();

                Json(serde_json::json!({
                    "malicious_ips": threats,
                    "count": threats.len(),
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

/// GET /api/v1/threats/cves - List vulnerabilities
pub async fn get_vulnerabilities(
    State(state): State<AppState>,
    Query(query): Query<ThreatQuery>,
) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        let mut sql_query = String::from(
            "SELECT * FROM threat_intelligence WHERE threat_type = 'vulnerability' AND active = true"
        );

        if let Some(severity) = &query.severity {
            sql_query.push_str(&format!(" AND severity = '{}'", severity));
        }

        sql_query.push_str(&format!(" ORDER BY first_seen DESC LIMIT {}", query.limit));

        let query_result = sqlx::query(&sql_query).fetch_all(persistence.pool()).await;

        match query_result {
            Ok(rows) => {
                let cves: Vec<serde_json::Value> = rows.iter().map(|row| {
                    serde_json::json!({
                        "cve_id": row.try_get::<serde_json::Value, _>("indicators").ok(),
                        "severity": row.try_get::<String, _>("severity").ok(),
                        "first_seen": row.try_get::<chrono::DateTime<chrono::Utc>, _>("first_seen").ok(),
                        "source": row.try_get::<String, _>("source").ok(),
                        "confidence": row.try_get::<f64, _>("confidence").ok(),
                        "metadata": row.try_get::<serde_json::Value, _>("metadata").ok(),
                    })
                }).collect();

                Json(serde_json::json!({
                    "vulnerabilities": cves,
                    "count": cves.len(),
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

/// GET /api/v1/threats/active - Active threats
pub async fn get_active_threats(State(state): State<AppState>) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        let query_result = sqlx::query!(
            r#"
            SELECT 
                threat_type,
                severity,
                COUNT(*) as count
            FROM threat_intelligence
            WHERE active = true
            GROUP BY threat_type, severity
            ORDER BY count DESC
            "#
        )
        .fetch_all(persistence.pool())
        .await;

        match query_result {
            Ok(rows) => {
                let threats: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|row| {
                        serde_json::json!({
                            "threat_type": row.threat_type,
                            "severity": row.severity,
                            "count": row.count,
                        })
                    })
                    .collect();

                Json(serde_json::json!({
                    "active_threats": threats,
                    "total": threats.len(),
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

/// GET /api/v1/threats/stats - Threat statistics
pub async fn get_threat_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        let total_result = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM threat_intelligence")
            .fetch_one(persistence.pool())
            .await
            .unwrap_or(0);

        let ips_result = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM threat_intelligence WHERE threat_type = 'malicious_ip'",
        )
        .fetch_one(persistence.pool())
        .await
        .unwrap_or(0);

        let cves_result = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM threat_intelligence WHERE threat_type = 'vulnerability'",
        )
        .fetch_one(persistence.pool())
        .await
        .unwrap_or(0);

        let intrusions_result = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM threat_intelligence WHERE threat_type = 'intrusion_attempt'",
        )
        .fetch_one(persistence.pool())
        .await
        .unwrap_or(0);

        let active_result = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM threat_intelligence WHERE active = true",
        )
        .fetch_one(persistence.pool())
        .await
        .unwrap_or(0);

        Json(serde_json::json!({
            "total_threats": total_result,
            "malicious_ips": ips_result,
            "vulnerabilities": cves_result,
            "intrusion_attempts": intrusions_result,
            "active_threats": active_result,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }))
    } else {
        Json(serde_json::json!({
            "error": "Persistence not enabled"
        }))
    }
}

/// POST /api/v1/threats/block - Block IP manually
pub async fn block_ip_manually(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    if let Some(persistence) = &state.persistence {
        if let Some(ip) = payload.get("ip").and_then(|v| v.as_str()) {
            let reason = payload
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("Manual block");

            let query_result = sqlx::query!(
                r#"
                INSERT INTO threat_intelligence (
                    threat_type, severity, indicators, source, confidence, metadata
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
                "malicious_ip",
                "high",
                serde_json::json!({"ip": ip}),
                "manual",
                1.0,
                serde_json::json!({"reason": reason, "blocked_by": "admin"})
            )
            .execute(persistence.pool())
            .await;

            match query_result {
                Ok(_) => Json(serde_json::json!({
                    "success": true,
                    "message": format!("IP {} blocked successfully", ip),
                })),
                Err(e) => Json(serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                })),
            }
        } else {
            Json(serde_json::json!({
                "success": false,
                "error": "IP address required"
            }))
        }
    } else {
        Json(serde_json::json!({
            "error": "Persistence not enabled"
        }))
    }
}
