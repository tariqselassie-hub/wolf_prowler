//! Wolfsec integration module for threat intelligence persistence
//!
//! This module connects wolfsec security events to the database,
//! automatically saving malicious IPs, vulnerabilities, and threats.

use crate::AppState;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use wolf_prowler::threat_feeds::ThreatFeedManager;

use crate::persistence::{DbSecurityAlert, DbSecurityEvent, PersistenceManager};

/// Start wolfsec event listener that saves events to database
pub async fn start_wolfsec_listener(
    app_state: Arc<AppState>,
    persistence: Arc<PersistenceManager>,
) {
    info!("🛡️ Starting wolfsec threat intelligence listener");

    // Subscribe to security events
    let mut event_rx = app_state.security.lock().await.subscribe_events();

    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    debug!("Received security event: {:?}", event.event_type);

                    // Save security event to database
                    let db_event = DbSecurityEvent {
                        id: None,
                        event_id: None,
                        timestamp: None,
                        event_type: format!("{:?}", event.event_type),
                        severity: format!("{:?}", event.severity),
                        source: Some(format!("{:?}", event.source)),
                        peer_id: event.metadata.get("peer_id").cloned(),
                        description: format!("Security event: {:?}", event.event_type),
                        details: serde_json::to_value(&event).unwrap_or_default(),
                        resolved: Some(false),
                        resolved_at: None,
                        resolved_by: None,
                    };

                    if let Err(e) = persistence.save_security_event(&db_event).await {
                        error!("Failed to save security event: {}", e);
                    } else {
                        debug!(
                            "Saved security event: {:?} from {:?}",
                            event.event_type, event.source
                        );
                    }

                    // If it's a high severity event, create an alert
                    let severity_str = format!("{:?}", event.severity);
                    if severity_str == "High" || severity_str == "Critical" {
                        let escalation = if severity_str == "Critical" { 2 } else { 1 };
                        let alert = DbSecurityAlert {
                            id: None,
                            alert_id: None,
                            timestamp: None,
                            severity: severity_str,
                            status: "active".to_string(),
                            title: format!("{:?} Detected", event.event_type),
                            message: Some(format!(
                                "Security event detected from {:?}",
                                event.source
                            )),
                            category: format!("{:?}", event.event_type),
                            source: format!("{:?}", event.source),
                            escalation_level: Some(escalation),
                            acknowledged_by: None,
                            acknowledged_at: None,
                            resolved_by: None,
                            resolved_at: None,
                            metadata: serde_json::to_value(&event.metadata).unwrap_or_default(),
                        };

                        if let Err(e) = persistence.save_security_alert(&alert).await {
                            error!("Failed to save security alert: {}", e);
                        } else {
                            info!("🚨 Created security alert: {}", alert.title);
                        }
                    }

                    // Handle specific event types
                    match format!("{:?}", event.event_type).as_str() {
                        "malicious_ip_detected" => {
                            handle_malicious_ip(&persistence, &event).await;
                        }
                        "vulnerability_detected" => {
                            handle_vulnerability(&persistence, &event).await;
                        }
                        "intrusion_attempt" => {
                            handle_intrusion_attempt(&persistence, &event).await;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    warn!("Error receiving security event: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    });
}

/// Handle malicious IP detection
async fn handle_malicious_ip(
    persistence: &Arc<PersistenceManager>,
    event: &wolfsec::security::advanced::SecurityEvent,
) {
    if let Some(ip) = event.metadata.get("ip_address") {
        let ip_str = ip.as_str();

        // Save to threat_intelligence table
        let query_result = sqlx::query!(
            r#"
            INSERT INTO threat_intelligence (
                threat_type, severity, indicators, source, confidence, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT DO NOTHING
            "#,
            "malicious_ip",
            format!("{:?}", event.severity),
            serde_json::json!({
                "ip": ip_str,
                "type": "ipv4"
            }),
            format!("{:?}", event.source),
            0.9,
            serde_json::to_value(&event.metadata).unwrap_or_default()
        )
        .execute(persistence.pool())
        .await;

        match query_result {
            Ok(_) => info!("💾 Saved malicious IP to database: {}", ip_str),
            Err(e) => error!("Failed to save malicious IP: {}", e),
        }
    }
}

/// Handle vulnerability detection
async fn handle_vulnerability(
    persistence: &Arc<PersistenceManager>,
    event: &wolfsec::security::advanced::SecurityEvent,
) {
    if let Some(cve) = event.metadata.get("cve_id") {
        let cve_str = cve.as_str();

        let query_result = sqlx::query!(
            r#"
            INSERT INTO threat_intelligence (
                threat_type, severity, indicators, source, confidence, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            "vulnerability",
            format!("{:?}", event.severity),
            serde_json::json!({
                "cve_id": cve_str,
                "description": event.description.clone()
            }),
            format!("{:?}", event.source),
            0.95,
            serde_json::to_value(&event.metadata).unwrap_or_default()
        )
        .execute(persistence.pool())
        .await;

        match query_result {
            Ok(_) => info!("💾 Saved vulnerability to database: {}", cve_str),
            Err(e) => error!("Failed to save vulnerability: {}", e),
        }
    }
}

/// Handle intrusion attempt
async fn handle_intrusion_attempt(
    persistence: &Arc<PersistenceManager>,
    event: &wolfsec::security::advanced::SecurityEvent,
) {
    // Log the intrusion attempt
    let log = crate::persistence::DbSystemLog::new(
        "warn".to_string(),
        format!("Intrusion attempt: {}", event.description),
        Some("wolfsec".to_string()),
    );

    if let Err(e) = persistence.save_system_log(&log).await {
        error!("Failed to save intrusion log: {}", e);
    }

    // If there's an IP, save it as a threat
    if let Some(ip) = event.metadata.get("source_ip") {
        let ip_str = ip.as_str();

        let query_result = sqlx::query!(
            r#"
            INSERT INTO threat_intelligence (
                threat_type, severity, indicators, source, confidence, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            "intrusion_attempt",
            format!("{:?}", event.severity),
            serde_json::json!({
                "ip": ip_str,
                "attack_type": event.event_type.clone()
            }),
            format!("{:?}", event.source),
            0.85,
            serde_json::to_value(&event.metadata).unwrap_or_default()
        )
        .execute(persistence.pool())
        .await;

        match query_result {
            Ok(_) => info!("💾 Saved intrusion attempt from: {}", ip_str),
            Err(e) => error!("Failed to save intrusion attempt: {}", e),
        }
    }
}

/// Start threat feed integration
pub async fn start_threat_feed_integration(
    app_state: crate::AppState,
    _persistence: Arc<PersistenceManager>,
) {
    info!("📡 Starting threat feed integration");
    let manager = ThreatFeedManager::new(app_state.threat_db.clone());
    manager.start_background_updates().await;
}
