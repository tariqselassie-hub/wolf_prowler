//! Wolfsec integration module for threat intelligence persistence
//!
//! This module connects wolfsec security events to the database,
//! automatically saving malicious IPs, vulnerabilities, and threats.

use crate::api::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use wolfsec::domain::repositories::AlertRepository;
use wolfsec::infrastructure::persistence::wolf_db_alert_repository::WolfDbAlertRepository;
use wolfsec::observability::alerts::{AlertCategory, AlertSeverity, AlertStatus, SecurityAlert};
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

    let repository: Arc<dyn AlertRepository + Send + Sync> =
        Arc::new(WolfDbAlertRepository::new(storage.clone()));

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
pub async fn process_security_event(
    repository: &Arc<dyn AlertRepository + Send + Sync>,
    event: SecurityEvent,
) {
    debug!("Received security event: {:?}", event.event_type);

    // Map SecurityEvent to SecurityAlert
    let alert = SecurityAlert {
        id: event.id.clone(),
        timestamp: event.timestamp,
        severity: match event.severity {
            SecuritySeverity::Low => AlertSeverity::Low,
            SecuritySeverity::Medium => AlertSeverity::Medium,
            SecuritySeverity::High => AlertSeverity::High,
            SecuritySeverity::Critical => AlertSeverity::Critical,
        },
        status: AlertStatus::Active,
        title: format!("{:?}", event.event_type),
        message: event.description.clone(),
        source: event
            .peer_id
            .clone()
            .unwrap_or_else(|| "system".to_string()),
        category: AlertCategory::Security,
        metadata: event.metadata.clone(),
        escalation_level: 0,
        acknowledged_by: None,
        acknowledged_at: None,
        resolved_by: None,
        resolved_at: None,
    };

    // SecurityAlert is an observability struct.
    // AlertRepository expects a domain entity Alert.
    // For now, let's assume we want to save into the alert manager or similar.
    // Actually, wolfsec_integration seems to want to bridge observability to persistence.
    // I'll need to convert SecurityAlert to domain Alert or vice versa.
    // But since WolfDbAlertRepository.save expects domain Alert, I'll use that.

    use wolfsec::domain::entities::Alert as DomainAlert;
    use wolfsec::domain::entities::AlertCategory as DomainCategory;
    use wolfsec::domain::entities::AlertSeverity as DomainSeverity;

    let domain_alert = DomainAlert::new(
        DomainSeverity::High,
        DomainCategory::System,
        alert.title.clone(),
        alert.message.clone(),
        alert.source.clone(),
        HashMap::new(),
    );

    if let Err(e) = repository.save(&domain_alert).await {
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
    use wolf_db::storage::WolfDbStorage;
    use wolfsec::SecurityEventType;

    #[tokio::test]
    async fn test_security_event_persistence() {
        let db_path = std::env::temp_dir().join(format!("wolf_test_db_{}", uuid::Uuid::new_v4()));
        let storage = Arc::new(RwLock::new(
            WolfDbStorage::open(db_path.to_str().unwrap()).expect("Failed to create temp DB"),
        ));
        let repository: Arc<dyn AlertRepository + Send + Sync> =
            Arc::new(WolfDbAlertRepository::new(storage.clone()));

        let event = SecurityEvent {
            id: "test-event-id".to_string(),
            timestamp: chrono::Utc::now(),
            event_type: SecurityEventType::SuspiciousActivity,
            severity: SecuritySeverity::High,
            description: "Integration test event".to_string(),
            peer_id: Some("malicious-peer-1".to_string()),
            metadata: std::collections::HashMap::new(),
        };

        process_security_event(&repository, event.clone()).await;

        let alerts = repository
            .get_recent_alerts(10)
            .await
            .expect("Failed to fetch alerts");

        assert_eq!(alerts.len(), 1);
        let saved_alert = &alerts[0];
        assert_eq!(saved_alert.description, "Integration test event");

        let _ = std::fs::remove_dir_all(db_path);
    }
}
