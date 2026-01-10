//! Wolfsec integration module for threat intelligence persistence
//!
//! This module connects wolfsec security events to the database,
//! automatically saving malicious IPs, vulnerabilities, and threats.

use crate::api::AppState;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use wolfsec::store::{SecurityAlert, WolfDbThreatRepository};
use wolfsec::{SecurityEvent, SecuritySeverity};

/// Start wolfsec event listener that saves events to database
pub async fn start_wolfsec_listener(app_state: Arc<AppState>) {
    info!("🛡️ Starting wolfsec threat intelligence listener");

    let storage = if let Some(s) = &app_state.persistence {
        s.clone()
    } else {
        warn!("Persistence not enabled, skipping wolfsec listener");
        return;
    };

    let repository = Arc::new(WolfDbThreatRepository::new(storage));

    // Subscribe to security events
    let mut event_rx = {
        let security = app_state.security.read().await;
        security.subscribe_events()
    };
    let repo_clone = repository.clone();

    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    process_security_event(&repo_clone, event).await;
                }
                Err(e) => {
                    warn!("Error receiving security event: {}", e);
                    if let tokio::sync::broadcast::error::RecvError::Closed = e {
                        break;
                    }
                }
            }
        }
    });
}

/// Process a security event and save it to the repository
pub async fn process_security_event(repository: &WolfDbThreatRepository, event: SecurityEvent) {
    debug!("Received security event: {:?}", event.event_type);

    // Map SecurityEvent to SecurityAlert
    let alert = SecurityAlert {
        id: event.id.clone(),
        timestamp: event.timestamp,
        severity: format!("{:?}", event.severity),
        title: format!("{:?}", event.event_type),
        description: event.description.clone(),
        source: event
            .peer_id
            .clone()
            .unwrap_or_else(|| "system".to_string()),
        metadata: event.metadata.clone(),
    };

    if let Err(e) = repository.save_alert(&alert).await {
        error!("Failed to save security alert: {}", e);
    } else {
        debug!("Saved security alert: {} ({})", alert.title, alert.id);
    }

    // Log high severity events
    if matches!(
        event.severity,
        SecuritySeverity::High | SecuritySeverity::Critical
    ) {
        info!("🚨 High severity alert saved: {}", alert.title);
    }
}

/// Start threat feed integration
pub async fn start_threat_feed_integration(_app_state: Arc<AppState>) {
    info!("📡 Threat feed integration placeholder");
    // Logic to be implemented with WolfDbThreatRepository
}

#[cfg(test)]
mod tests {
    use super::*;
    use wolf_db::WolfDbStorage;
    use wolfsec::SecurityEventType;

    #[tokio::test]
    async fn test_security_event_persistence() {
        // Setup temporary DB path with unique name to avoid collisions
        let db_path = std::env::temp_dir().join(format!("wolf_test_db_{}", uuid::Uuid::new_v4()));

        // Initialize storage
        let storage = Arc::new(WolfDbStorage::new(&db_path).expect("Failed to create temp DB"));
        let repository = WolfDbThreatRepository::new(storage);

        // Create a test event
        let event = SecurityEvent {
            id: "test-event-id".to_string(),
            timestamp: chrono::Utc::now(),
            event_type: SecurityEventType::SuspiciousActivity,
            severity: SecuritySeverity::High,
            description: "Integration test event".to_string(),
            peer_id: Some("malicious-peer-1".to_string()),
            metadata: std::collections::HashMap::new(),
        };

        // Process the event (this calls the logic used by the listener)
        process_security_event(&repository, event.clone()).await;

        // Verify it was saved
        let alerts = repository
            .get_recent_alerts(10)
            .await
            .expect("Failed to fetch alerts");

        assert_eq!(alerts.len(), 1, "Should have exactly one alert saved");
        let saved_alert = &alerts[0];

        assert_eq!(saved_alert.id, event.id);
        assert_eq!(saved_alert.description, event.description);
        assert_eq!(saved_alert.source, "malicious-peer-1");
        assert_eq!(saved_alert.severity, "High");

        // Cleanup
        let _ = std::fs::remove_dir_all(db_path);
    }
}
