use super::{CorrelationResult, ResponseAction, SecurityEvent};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Alert status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AlertStatus {
    Open,
    Acknowledged,
    InProgress,
    Resolved,
    FalsePositive,
}

/// Security alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub alert_id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub trigger_event: Uuid,
    pub related_events: Vec<Uuid>,
    pub correlation_score: f64,
    pub recommended_actions: Vec<ResponseAction>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub assigned_to: Option<String>,
}

/// Wolf Alert Manager
pub struct WolfAlertManager {
    /// Active alerts
    active_alerts: HashMap<Uuid, SecurityAlert>,
    /// Alert deduplication window (minutes)
    dedup_window_minutes: i64,
    /// Alert thresholds
    severity_thresholds: HashMap<String, f64>,
}

impl WolfAlertManager {
    /// Create new alert manager
    pub fn new() -> Result<Self> {
        let mut severity_thresholds = HashMap::new();
        severity_thresholds.insert("correlation_score_critical".to_string(), 0.9);
        severity_thresholds.insert("correlation_score_high".to_string(), 0.7);
        severity_thresholds.insert("correlation_score_medium".to_string(), 0.5);

        Ok(Self {
            active_alerts: HashMap::new(),
            dedup_window_minutes: 30,
            severity_thresholds,
        })
    }

    /// Evaluate alerts for a security event
    pub async fn evaluate_alerts(
        &mut self,
        event: &SecurityEvent,
        correlation: &CorrelationResult,
    ) -> Result<Vec<SecurityAlert>> {
        debug!("🔔 Evaluating alerts for event: {}", event.event_id);

        let mut alerts = Vec::new();

        // Check if we should create an alert based on event severity and correlation
        if self.should_create_alert(event, correlation) {
            // Check for duplicate alerts
            if !self.is_duplicate_alert(event) {
                let alert = self.create_alert(event, correlation).await?;
                self.active_alerts.insert(alert.alert_id, alert.clone());
                alerts.push(alert);
            } else {
                debug!("⏭️ Skipping duplicate alert for event: {}", event.event_id);
            }
        }

        info!("✅ Generated {} new alerts", alerts.len());
        Ok(alerts)
    }

    /// Generate response actions for an alert
    pub async fn generate_response_actions(
        &self,
        alert: &SecurityAlert,
    ) -> Result<Vec<ResponseAction>> {
        debug!(
            "🎯 Generating response actions for alert: {}",
            alert.alert_id
        );

        let mut actions = Vec::new();

        // Base actions on alert severity
        match alert.severity {
            AlertSeverity::Critical => {
                actions.push(ResponseAction::IsolateSystem);
                actions.push(ResponseAction::BlockNetwork);
                actions.push(ResponseAction::SendNotification);
                actions.push(ResponseAction::LogForInvestigation);
            }
            AlertSeverity::High => {
                actions.push(ResponseAction::IncreaseMonitoring);
                actions.push(ResponseAction::RequireMFA);
                actions.push(ResponseAction::SendNotification);
                actions.push(ResponseAction::LogForInvestigation);
            }
            AlertSeverity::Medium => {
                actions.push(ResponseAction::IncreaseMonitoring);
                actions.push(ResponseAction::SendNotification);
                actions.push(ResponseAction::LogForInvestigation);
            }
            AlertSeverity::Low => {
                actions.push(ResponseAction::LogForInvestigation);
            }
        }

        // Add recommended actions from the alert
        actions.extend(alert.recommended_actions.clone());

        // Deduplicate actions
        actions.sort_by_key(|a| format!("{:?}", a));
        actions.dedup();

        info!("✅ Generated {} response actions", actions.len());
        Ok(actions)
    }

    /// Check if an alert should be created
    fn should_create_alert(&self, event: &SecurityEvent, correlation: &CorrelationResult) -> bool {
        // Create alert if:
        // 1. Event severity is high or critical
        // 2. Correlation score exceeds threshold
        // 3. Attack chain detected

        let high_severity = matches!(
            event.severity,
            super::EventSeverity::Alpha | super::EventSeverity::Beta
        );

        let high_correlation = correlation.correlation_score
            >= *self
                .severity_thresholds
                .get("correlation_score_medium")
                .unwrap_or(&0.5);

        let attack_chain = correlation.attack_chain_detected;

        high_severity || high_correlation || attack_chain
    }

    /// Check if this is a duplicate alert
    fn is_duplicate_alert(&self, event: &SecurityEvent) -> bool {
        let cutoff_time = Utc::now() - chrono::Duration::minutes(self.dedup_window_minutes);

        self.active_alerts.values().any(|alert| {
            alert.created_at >= cutoff_time
                && (alert.trigger_event == event.event_id
                    || alert.related_events.contains(&event.event_id))
        })
    }

    /// Create a new alert
    async fn create_alert(
        &self,
        event: &SecurityEvent,
        correlation: &CorrelationResult,
    ) -> Result<SecurityAlert> {
        let severity = self.calculate_alert_severity(event, correlation);
        let recommended_actions = self.recommend_actions(event, correlation);

        let alert = SecurityAlert {
            alert_id: Uuid::new_v4(),
            title: format!("Security Alert: {:?}", event.event_type),
            description: event.description.clone(),
            severity,
            status: AlertStatus::Open,
            trigger_event: event.event_id,
            related_events: correlation.correlated_events.clone(),
            correlation_score: correlation.correlation_score,
            recommended_actions,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            assigned_to: None,
        };

        info!(
            "🚨 Created new alert: {} (Severity: {:?})",
            alert.alert_id, alert.severity
        );

        Ok(alert)
    }

    /// Calculate alert severity
    fn calculate_alert_severity(
        &self,
        event: &SecurityEvent,
        correlation: &CorrelationResult,
    ) -> AlertSeverity {
        // Base severity on event severity
        let mut severity_score = match event.severity {
            super::EventSeverity::Alpha => 4.0,
            super::EventSeverity::Beta => 3.0,
            super::EventSeverity::Hunter => 2.0,
            super::EventSeverity::Scout => 1.0,
            super::EventSeverity::Pup => 0.5,
        };

        // Increase severity based on correlation score
        severity_score += correlation.correlation_score * 2.0;

        // Increase severity if attack chain detected
        if correlation.attack_chain_detected {
            severity_score += 2.0;
        }

        // Map score to severity level
        if severity_score >= 6.0 {
            AlertSeverity::Critical
        } else if severity_score >= 4.0 {
            AlertSeverity::High
        } else if severity_score >= 2.0 {
            AlertSeverity::Medium
        } else {
            AlertSeverity::Low
        }
    }

    /// Recommend response actions
    fn recommend_actions(
        &self,
        event: &SecurityEvent,
        correlation: &CorrelationResult,
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        // Recommend actions based on event type
        match &event.event_type {
            super::SecurityEventType::AuthEvent(_) => {
                actions.push(ResponseAction::RequireMFA);
                actions.push(ResponseAction::IncreaseMonitoring);
            }
            super::SecurityEventType::NetworkEvent(_) => {
                actions.push(ResponseAction::BlockNetwork);
                actions.push(ResponseAction::IncreaseMonitoring);
            }
            super::SecurityEventType::ThreatEvent(_) => {
                actions.push(ResponseAction::IsolateSystem);
                actions.push(ResponseAction::QuarantineSystem);
            }
            _ => {
                actions.push(ResponseAction::LogForInvestigation);
            }
        }

        // Add actions based on attack chain
        if correlation.attack_chain_detected {
            actions.push(ResponseAction::SendNotification);
            actions.push(ResponseAction::IsolateSystem);
        }

        actions
    }

    /// Get active alerts
    pub fn get_active_alerts(&self) -> Vec<&SecurityAlert> {
        self.active_alerts
            .values()
            .filter(|a| a.status != AlertStatus::Resolved && a.status != AlertStatus::FalsePositive)
            .collect()
    }

    /// Update alert status
    pub fn update_alert_status(&mut self, alert_id: &Uuid, status: AlertStatus) -> Result<()> {
        if let Some(alert) = self.active_alerts.get_mut(alert_id) {
            alert.status = status;
            alert.updated_at = Utc::now();
            info!("📝 Updated alert {} status to {:?}", alert_id, status);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Alert not found: {}", alert_id))
        }
    }

    /// Get alert statistics
    pub fn get_statistics(&self) -> AlertStatistics {
        let total_alerts = self.active_alerts.len();
        let open_alerts = self
            .active_alerts
            .values()
            .filter(|a| a.status == AlertStatus::Open)
            .count();
        let critical_alerts = self
            .active_alerts
            .values()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count();

        AlertStatistics {
            total_alerts,
            open_alerts,
            critical_alerts,
        }
    }
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatistics {
    pub total_alerts: usize,
    pub open_alerts: usize,
    pub critical_alerts: usize,
}
