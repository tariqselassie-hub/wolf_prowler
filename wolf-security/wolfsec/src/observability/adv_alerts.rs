//! Security Alerts
//!
//! Real-time security alerts and notification system with wolf-themed approach

#![allow(unused_imports)]
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use super::notifications::{
    DiscordConfig, DiscordSender, EmailConfig, EmailSender, NotificationChannel,
    NotificationEngine, NotificationPriority, NotificationRequest, NotificationResult,
    NotificationTemplate, SlackConfig, SlackSender, WebhookConfig, WebhookSender,
};
use anyhow::{anyhow, Error};

/// Wolf-themed alerts configuration
pub type AlertsConfig = AlertConfig;

/// Wolf-themed alert manager alias
pub type AlertManager = SecurityAlertManager;

/// Retry configuration for notification delivery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries in seconds
    pub initial_delay_secs: u64,
    /// Maximum delay between retries in seconds
    pub max_delay_secs: u64,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_secs: 5,
            max_delay_secs: 300, // 5 minutes
            backoff_multiplier: 2.0,
        }
    }
}

/// Delivery status for notification attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryStatus {
    pub alert_id: String,
    pub channel: String,
    pub attempt_count: u32,
    pub last_attempt: DateTime<Utc>,
    pub success: bool,
    pub error_message: Option<String>,
    pub next_retry: Option<DateTime<Utc>>,
}

impl DeliveryStatus {
    pub fn new(alert_id: String, channel: String) -> Self {
        Self {
            alert_id,
            channel,
            attempt_count: 0,
            last_attempt: Utc::now(),
            success: false,
            error_message: None,
            next_retry: None,
        }
    }

    pub fn record_attempt(
        &mut self,
        success: bool,
        error: Option<String>,
        retry_config: &RetryConfig,
    ) {
        self.attempt_count += 1;
        self.last_attempt = Utc::now();
        self.success = success;
        self.error_message = error;

        if !success && self.attempt_count < retry_config.max_attempts {
            let delay = (retry_config.initial_delay_secs as f64
                * retry_config
                    .backoff_multiplier
                    .powi(self.attempt_count as i32 - 1)) as u64;
            let delay = delay.min(retry_config.max_delay_secs);
            self.next_retry = Some(Utc::now() + chrono::Duration::seconds(delay as i64));
        } else {
            self.next_retry = None;
        }
    }
}

/// Legacy alert configuration (for backward compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alert monitoring
    pub enable_monitoring: bool,
    /// Maximum number of alerts to keep
    pub max_alerts: usize,
    /// Alert retention period in hours
    pub retention_hours: u64,
    /// Enable alert escalation
    pub enable_escalation: bool,
    /// Alert escalation thresholds
    pub escalation_thresholds: EscalationThresholds,
    /// Notification channels
    pub notification_channels: Vec<NotificationChannel>,
    /// Alert filters
    pub alert_filters: Vec<AlertFilter>,
    /// Retry configuration for failed notifications
    pub retry_config: RetryConfig,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enable_monitoring: true,
            max_alerts: 1000,
            retention_hours: 24 * 7, // 1 week
            enable_escalation: true,
            escalation_thresholds: EscalationThresholds::default(),
            notification_channels: vec![NotificationChannel::Log, NotificationChannel::Memory],
            alert_filters: vec![],
            retry_config: RetryConfig::default(),
        }
    }
}

impl AlertConfig {
    /// Validate the alert configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_alerts == 0 {
            return Err("max_alerts must be greater than 0".to_string());
        }
        if self.retention_hours == 0 {
            return Err("retention_hours must be greater than 0".to_string());
        }
        if self.retry_config.max_attempts == 0 {
            return Err("retry_config.max_attempts must be greater than 0".to_string());
        }
        if self.retry_config.initial_delay_secs == 0 {
            return Err("retry_config.initial_delay_secs must be greater than 0".to_string());
        }
        if self.retry_config.backoff_multiplier <= 1.0 {
            return Err("retry_config.backoff_multiplier must be greater than 1.0".to_string());
        }
        Ok(())
    }
}

/// Escalation thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationThresholds {
    /// Critical alerts per hour to trigger escalation
    pub critical_per_hour: u64,
    /// High alerts per hour to trigger escalation
    pub high_per_hour: u64,
    /// Total alerts per hour to trigger escalation
    pub total_per_hour: u64,
}

impl Default for EscalationThresholds {
    fn default() -> Self {
        Self {
            critical_per_hour: 1,
            high_per_hour: 5,
            total_per_hour: 20,
        }
    }
}

// Notification types now imported from super::notifications

/// Alert filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFilter {
    pub filter_type: FilterType,
    pub severity: Option<AlertSeverity>,
    pub source_pattern: Option<String>,
    pub message_pattern: Option<String>,
}

/// Filter type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterType {
    Include,
    Exclude,
}

/// Alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Low => "low",
            AlertSeverity::Medium => "medium",
            AlertSeverity::High => "high",
            AlertSeverity::Critical => "critical",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            AlertSeverity::Low => "#4CAF50",      // Green
            AlertSeverity::Medium => "#FFC107",   // Yellow
            AlertSeverity::High => "#FF9800",     // Orange
            AlertSeverity::Critical => "#F44336", // Red
        }
    }

    pub fn numeric_value(&self) -> u8 {
        match self {
            AlertSeverity::Low => 1,
            AlertSeverity::Medium => 2,
            AlertSeverity::High => 3,
            AlertSeverity::Critical => 4,
        }
    }
}

/// Alert status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    Suppressed,
}

impl AlertStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertStatus::Active => "active",
            AlertStatus::Acknowledged => "acknowledged",
            AlertStatus::Resolved => "resolved",
            AlertStatus::Suppressed => "suppressed",
        }
    }
}

/// Security alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub title: String,
    pub message: String,
    pub source: String,
    pub category: AlertCategory,
    pub metadata: HashMap<String, String>,
    pub escalation_level: u8,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Alert category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCategory {
    Security,
    Performance,
    Network,
    Authentication,
    DataIntegrity,
    System,
    Compliance,
}

impl AlertCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertCategory::Security => "security",
            AlertCategory::Performance => "performance",
            AlertCategory::Network => "network",
            AlertCategory::Authentication => "authentication",
            AlertCategory::DataIntegrity => "data_integrity",
            AlertCategory::System => "system",
            AlertCategory::Compliance => "compliance",
        }
    }
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatistics {
    pub total_alerts: usize,
    pub active_alerts: usize,
    pub critical_alerts: usize,
    pub high_alerts: usize,
    pub medium_alerts: usize,
    pub low_alerts: usize,
    pub alerts_by_category: HashMap<String, usize>,
    pub alerts_by_source: HashMap<String, usize>,
    pub average_resolution_time_minutes: f64,
    pub escalation_rate: f64,
}

/// Alert escalation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEscalation {
    pub alert_id: String,
    pub escalation_level: u8,
    pub escalated_at: DateTime<Utc>,
    pub reason: String,
    pub notified_channels: Vec<String>,
}

/// Security alert manager
pub struct SecurityAlertManager {
    config: AlertConfig,
    alerts: Arc<RwLock<Vec<SecurityAlert>>>,
    escalations: Arc<RwLock<Vec<AlertEscalation>>>,
    is_monitoring: Arc<RwLock<bool>>,
    notification_engine: Arc<NotificationEngine>,
    delivery_status: Arc<RwLock<HashMap<String, Vec<DeliveryStatus>>>>,
}

impl SecurityAlertManager {
    /// Create a new security alert manager
    pub async fn new(config: AlertConfig) -> Result<Self, Error> {
        info!("Initializing security alert manager");

        // Validate configuration
        config
            .validate()
            .map_err(|e| anyhow!("Invalid alert configuration: {}", e))?;

        let notification_engine = Arc::new(NotificationEngine::new());

        // Register senders based on config
        for channel in &config.notification_channels {
            match channel {
                NotificationChannel::Email(c) => {
                    notification_engine
                        .register_sender(Box::new(EmailSender::new(c.clone())))
                        .await;
                }
                NotificationChannel::Slack(c) => {
                    notification_engine
                        .register_sender(Box::new(SlackSender::new(c.clone())))
                        .await;
                }
                NotificationChannel::Discord(c) => {
                    notification_engine
                        .register_sender(Box::new(DiscordSender::new(c.clone())))
                        .await;
                }
                NotificationChannel::Webhook(c) => {
                    notification_engine
                        .register_sender(Box::new(WebhookSender::new(c.clone())))
                        .await;
                }
                _ => {}
            }
        }

        let manager = Self {
            config,
            alerts: Arc::new(RwLock::new(Vec::new())),
            escalations: Arc::new(RwLock::new(Vec::new())),
            is_monitoring: Arc::new(RwLock::new(false)),
            notification_engine,
            delivery_status: Arc::new(RwLock::new(HashMap::new())),
        };

        info!("Security alert manager initialized successfully");
        Ok(manager)
    }

    /// Create a new security alert
    #[instrument(skip(self))]
    pub async fn create_alert(
        &self,
        severity: AlertSeverity,
        title: String,
        message: String,
        source: String,
        category: AlertCategory,
    ) -> Result<String, Error> {
        let alert_id = self.generate_alert_id();

        let alert = SecurityAlert {
            id: alert_id.clone(),
            timestamp: Utc::now(),
            severity,
            status: AlertStatus::Active,
            title,
            message,
            source,
            category,
            metadata: HashMap::new(),
            escalation_level: 0,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved_by: None,
            resolved_at: None,
        };

        // Apply filters
        if !self.should_include_alert(&alert) {
            debug!("Alert filtered out: {}", alert_id);
            return Ok(alert_id);
        }

        // Add alert
        {
            let mut alerts = self.alerts.write().await;
            alerts.push(alert.clone());

            // Sort by severity and timestamp (critical and recent first)
            alerts.sort_by(|a, b| match b.severity.cmp(&a.severity) {
                std::cmp::Ordering::Equal => b.timestamp.cmp(&a.timestamp),
                other => other,
            });

            // Limit number of alerts
            if alerts.len() > self.config.max_alerts {
                alerts.truncate(self.config.max_alerts);
            }
        }

        // Send notifications
        self.send_notifications(&alert).await?;

        // Check for escalation
        if self.config.enable_escalation {
            self.check_escalation(&alert).await?;
        }

        warn!("Security alert created: {} - {}", alert_id, alert.title);
        Ok(alert_id)
    }

    /// Get alert by ID
    #[instrument(skip(self))]
    pub async fn get_alert(&self, alert_id: &str) -> Option<SecurityAlert> {
        let alerts = self.alerts.read().await;
        alerts.iter().find(|a| a.id == alert_id).cloned()
    }

    /// Get all alerts
    #[instrument(skip(self))]
    pub async fn get_all_alerts(&self) -> Vec<SecurityAlert> {
        self.alerts.read().await.clone()
    }

    /// Get alerts by severity
    #[instrument(skip(self))]
    pub async fn get_alerts_by_severity(&self, severity: AlertSeverity) -> Vec<SecurityAlert> {
        let alerts = self.alerts.read().await;
        alerts
            .iter()
            .filter(|a| a.severity == severity)
            .cloned()
            .collect()
    }

    /// Get alerts by status
    #[instrument(skip(self))]
    pub async fn get_alerts_by_status(&self, status: AlertStatus) -> Vec<SecurityAlert> {
        let alerts = self.alerts.read().await;
        alerts
            .iter()
            .filter(|a| a.status == status)
            .cloned()
            .collect()
    }

    /// Get recent alerts
    #[instrument(skip(self))]
    pub async fn get_recent_alerts(&self, limit: usize) -> Vec<SecurityAlert> {
        let alerts = self.alerts.read().await;
        alerts.iter().take(limit).cloned().collect()
    }

    /// Get alerts in time range
    #[instrument(skip(self))]
    pub async fn get_alerts_in_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<SecurityAlert> {
        let alerts = self.alerts.read().await;
        alerts
            .iter()
            .filter(|a| a.timestamp >= start && a.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Acknowledge alert
    #[instrument(skip(self))]
    pub async fn acknowledge_alert(
        &self,
        alert_id: &str,
        acknowledged_by: String,
    ) -> Result<(), Error> {
        let mut alerts = self.alerts.write().await;

        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.status = AlertStatus::Acknowledged;
            alert.acknowledged_by = Some(acknowledged_by.clone());
            alert.acknowledged_at = Some(Utc::now());

            info!("Alert acknowledged: {} by {}", alert_id, acknowledged_by);
            Ok(())
        } else {
            Err(anyhow!("Alert not found: {}", alert_id))
        }
    }

    /// Resolve alert
    #[instrument(skip(self))]
    pub async fn resolve_alert(&self, alert_id: &str, resolved_by: String) -> Result<(), Error> {
        let mut alerts = self.alerts.write().await;

        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.status = AlertStatus::Resolved;
            alert.resolved_by = Some(resolved_by.clone());
            alert.resolved_at = Some(Utc::now());

            info!("Alert resolved: {} by {}", alert_id, resolved_by);
            Ok(())
        } else {
            Err(anyhow!("Alert not found: {}", alert_id))
        }
    }

    /// Suppress alert
    #[instrument(skip(self))]
    pub async fn suppress_alert(&self, alert_id: &str) -> Result<(), Error> {
        let mut alerts = self.alerts.write().await;

        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.status = AlertStatus::Suppressed;

            info!("Alert suppressed: {}", alert_id);
            Ok(())
        } else {
            Err(anyhow!("Alert not found: {}", alert_id))
        }
    }

    /// Get alert statistics
    #[instrument(skip(self))]
    pub async fn get_alert_statistics(&self) -> AlertStatistics {
        let alerts = self.alerts.read().await;

        let total_alerts = alerts.len();
        let active_alerts = alerts
            .iter()
            .filter(|a| a.status == AlertStatus::Active)
            .count();
        let critical_alerts = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count();
        let high_alerts = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::High)
            .count();
        let medium_alerts = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Medium)
            .count();
        let low_alerts = alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Low)
            .count();

        let mut alerts_by_category = HashMap::new();
        let mut alerts_by_source = HashMap::new();

        for alert in alerts.iter() {
            *alerts_by_category
                .entry(alert.category.as_str().to_string())
                .or_insert(0) += 1;
            *alerts_by_source.entry(alert.source.clone()).or_insert(0) += 1;
        }

        // Calculate average resolution time
        let resolved_alerts: Vec<_> = alerts.iter().filter(|a| a.resolved_at.is_some()).collect();

        let average_resolution_time_minutes = if !resolved_alerts.is_empty() {
            let total_minutes: f64 = resolved_alerts
                .iter()
                .map(|a| {
                    a.resolved_at
                        .unwrap()
                        .signed_duration_since(a.timestamp)
                        .num_minutes() as f64
                })
                .sum();
            total_minutes / resolved_alerts.len() as f64
        } else {
            0.0
        };

        // Calculate escalation rate
        let escalations = self.escalations.read().await;
        let escalation_rate = if total_alerts > 0 {
            escalations.len() as f64 / total_alerts as f64 * 100.0
        } else {
            0.0
        };

        AlertStatistics {
            total_alerts,
            active_alerts,
            critical_alerts,
            high_alerts,
            medium_alerts,
            low_alerts,
            alerts_by_category,
            alerts_by_source,
            average_resolution_time_minutes,
            escalation_rate,
        }
    }

    /// Clean up old alerts
    #[instrument(skip(self))]
    pub async fn cleanup_old_alerts(&self) -> Result<usize, Error> {
        let cutoff_time = Utc::now() - chrono::Duration::hours(self.config.retention_hours as i64);

        let mut alerts = self.alerts.write().await;
        let initial_count = alerts.len();

        alerts.retain(|alert| alert.timestamp > cutoff_time);

        let removed_count = initial_count - alerts.len();

        if removed_count > 0 {
            info!("Cleaned up {} old alerts", removed_count);
        }

        Ok(removed_count)
    }

    /// Start alert monitoring
    #[instrument(skip(self))]
    pub async fn start_monitoring(&self) -> Result<(), Error> {
        let mut is_monitoring = self.is_monitoring.write().await;

        if *is_monitoring {
            warn!("Alert monitoring is already running");
            return Ok(());
        }

        *is_monitoring = true;
        info!("Starting alert monitoring");

        let config = self.config.clone();
        let alerts = Arc::clone(&self.alerts);
        let is_monitoring = Arc::clone(&self.is_monitoring);

        tokio::spawn(async move {
            while *is_monitoring.read().await {
                // Clean up old alerts
                if let Err(e) = Self::perform_cleanup(&alerts, &config).await {
                    error!("Failed to cleanup old alerts: {}", e);
                }

                // Check for escalation conditions
                if config.enable_escalation {
                    if let Err(e) = Self::check_escalation_conditions(&alerts, &config).await {
                        error!("Failed to check escalation conditions: {}", e);
                    }
                }

                // Wait for next check
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await; // Check every minute
            }
        });

        Ok(())
    }

    /// Stop alert monitoring
    #[instrument(skip(self))]
    pub async fn stop_monitoring(&self) -> Result<(), Error> {
        let mut is_monitoring = self.is_monitoring.write().await;

        if !*is_monitoring {
            warn!("Alert monitoring is not running");
            return Ok(());
        }

        *is_monitoring = false;
        info!("Stopping alert monitoring");
        Ok(())
    }

    /// Generate unique alert ID
    fn generate_alert_id(&self) -> String {
        use uuid::Uuid;
        format!("alert-{}", Uuid::new_v4())
    }

    /// Check if alert should be included based on filters
    fn should_include_alert(&self, alert: &SecurityAlert) -> bool {
        for filter in &self.config.alert_filters {
            match filter.filter_type {
                FilterType::Exclude => {
                    if let Some(severity) = &filter.severity {
                        if alert.severity == *severity {
                            return false;
                        }
                    }
                    if let Some(source_pattern) = &filter.source_pattern {
                        if alert.source.contains(source_pattern) {
                            return false;
                        }
                    }
                    if let Some(message_pattern) = &filter.message_pattern {
                        if alert.message.contains(message_pattern) {
                            return false;
                        }
                    }
                }
                FilterType::Include => {
                    // For include filters, all conditions must match
                    let mut matches = true;

                    if let Some(severity) = &filter.severity {
                        matches &= alert.severity == *severity;
                    }
                    if let Some(source_pattern) = &filter.source_pattern {
                        matches &= alert.source.contains(source_pattern);
                    }
                    if let Some(message_pattern) = &filter.message_pattern {
                        matches &= alert.message.contains(message_pattern);
                    }

                    if !matches {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Send notifications for alert with retry logic and delivery tracking
    async fn send_notifications(&self, alert: &SecurityAlert) -> Result<(), Error> {
        let mut data = HashMap::new();
        data.insert("title".to_string(), alert.title.clone());
        data.insert("severity".to_string(), alert.severity.as_str().to_string());
        data.insert("category".to_string(), alert.category.as_str().to_string());
        data.insert("source".to_string(), alert.source.clone());
        data.insert("message".to_string(), alert.message.clone());
        data.insert("timestamp".to_string(), alert.timestamp.to_rfc3339());
        data.insert("alert_id".to_string(), alert.id.clone());

        let mut details = String::new();
        for (k, v) in &alert.metadata {
            details.push_str(&format!("{}: {}\n", k, v));
        }
        data.insert(
            "details".to_string(),
            if details.is_empty() {
                "None".to_string()
            } else {
                details
            },
        );

        let template = NotificationTemplate::default_alert();
        let (title, message) = template.render(&data);

        let priority = match alert.severity {
            AlertSeverity::Critical => NotificationPriority::Critical,
            AlertSeverity::High => NotificationPriority::High,
            AlertSeverity::Medium => NotificationPriority::Medium,
            AlertSeverity::Low => NotificationPriority::Low,
        };

        let request = NotificationRequest {
            title,
            message,
            priority,
            metadata: data, // Use the same data as metadata
            channels: vec![],
        };

        // Send notifications with retry logic
        let results = self.send_with_retry(request).await;

        // Track delivery status
        let mut delivery_status = self.delivery_status.write().await;
        let alert_statuses = delivery_status
            .entry(alert.id.clone())
            .or_insert_with(Vec::new);

        for result in results {
            let status = DeliveryStatus::new(alert.id.clone(), result.channel.clone());
            alert_statuses.push(status);

            if result.success {
                info!(
                    "Notification delivered successfully to channel: {:?}",
                    result.channel
                );
            } else {
                warn!(
                    "Notification failed for channel {:?}: {:?}",
                    result.channel, result.error
                );
            }
        }

        Ok(())
    }

    /// Send notification with retry logic
    async fn send_with_retry(&self, request: NotificationRequest) -> Vec<NotificationResult> {
        let mut results = Vec::new();
        let mut attempt = 0;

        loop {
            attempt += 1;
            let current_results = self
                .notification_engine
                .send_notification(request.clone())
                .await;

            // Check if all notifications succeeded
            let all_success = current_results.iter().all(|r| r.success);

            if all_success || attempt >= self.config.retry_config.max_attempts {
                results.extend(current_results);
                break;
            }

            // Calculate delay for next retry
            let delay = (self.config.retry_config.initial_delay_secs as f64
                * self
                    .config
                    .retry_config
                    .backoff_multiplier
                    .powi(attempt as i32 - 1)) as u64;
            let delay = delay.min(self.config.retry_config.max_delay_secs);

            warn!(
                "Notification attempt {} failed, retrying in {} seconds",
                attempt, delay
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
        }

        results
    }

    /// Get delivery status for an alert
    pub async fn get_delivery_status(&self, alert_id: &str) -> Vec<DeliveryStatus> {
        let delivery_status = self.delivery_status.read().await;
        delivery_status.get(alert_id).cloned().unwrap_or_default()
    }

    /// Get delivery statistics
    pub async fn get_delivery_stats(&self) -> HashMap<String, serde_json::Value> {
        let delivery_status = self.delivery_status.read().await;
        let mut stats = HashMap::new();

        let total_alerts = delivery_status.len();
        let mut total_attempts = 0;
        let mut successful_deliveries = 0;
        let mut failed_deliveries = 0;

        for statuses in delivery_status.values() {
            for status in statuses {
                total_attempts += status.attempt_count;
                if status.success {
                    successful_deliveries += 1;
                } else {
                    failed_deliveries += 1;
                }
            }
        }

        stats.insert("total_alerts".to_string(), total_alerts.into());
        stats.insert("total_attempts".to_string(), total_attempts.into());
        stats.insert(
            "successful_deliveries".to_string(),
            successful_deliveries.into(),
        );
        stats.insert("failed_deliveries".to_string(), failed_deliveries.into());
        stats.insert(
            "success_rate".to_string(),
            if total_attempts > 0 {
                (successful_deliveries as f64 / total_attempts as f64).into()
            } else {
                0.0.into()
            },
        );

        stats
    }

    /// Check for escalation
    async fn check_escalation(&self, alert: &SecurityAlert) -> Result<(), Error> {
        let alerts = self.alerts.read().await;
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);

        let recent_alerts: Vec<_> = alerts
            .iter()
            .filter(|a| a.timestamp >= one_hour_ago)
            .collect();

        let critical_count = recent_alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count() as u64;
        let high_count = recent_alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::High)
            .count() as u64;
        let total_count = recent_alerts.len() as u64;

        if critical_count >= self.config.escalation_thresholds.critical_per_hour
            || high_count >= self.config.escalation_thresholds.high_per_hour
            || total_count >= self.config.escalation_thresholds.total_per_hour
        {
            self.escalate_alert(alert, "Threshold exceeded").await?;
        }

        Ok(())
    }

    /// Escalate alert
    async fn escalate_alert(&self, alert: &SecurityAlert, reason: &str) -> Result<(), Error> {
        let mut alerts = self.alerts.write().await;

        if let Some(alert_mut) = alerts.iter_mut().find(|a| a.id == alert.id) {
            alert_mut.escalation_level += 1;

            let escalation = AlertEscalation {
                alert_id: alert.id.clone(),
                escalation_level: alert_mut.escalation_level,
                escalated_at: Utc::now(),
                reason: reason.to_string(),
                notified_channels: self
                    .config
                    .notification_channels
                    .iter()
                    .map(|c| format!("{:?}", c))
                    .collect(),
            };

            let mut escalations = self.escalations.write().await;
            escalations.push(escalation);

            warn!(
                "Alert escalated: {} to level {} - {}",
                alert.id, alert_mut.escalation_level, reason
            );
        }

        Ok(())
    }

    /// Perform cleanup
    async fn perform_cleanup(
        alerts: &Arc<RwLock<Vec<SecurityAlert>>>,
        config: &AlertConfig,
    ) -> Result<(), Error> {
        let cutoff_time = Utc::now() - chrono::Duration::hours(config.retention_hours as i64);

        let mut alerts_vec = alerts.write().await;
        let initial_count = alerts_vec.len();

        alerts_vec.retain(|alert| alert.timestamp > cutoff_time);

        let removed_count = initial_count - alerts_vec.len();

        if removed_count > 0 {
            debug!("Cleaned up {} old alerts", removed_count);
        }

        Ok(())
    }

    /// Check escalation conditions
    async fn check_escalation_conditions(
        alerts: &Arc<RwLock<Vec<SecurityAlert>>>,
        config: &AlertConfig,
    ) -> Result<(), Error> {
        let alerts_vec = alerts.read().await;
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);

        let recent_alerts: Vec<_> = alerts_vec
            .iter()
            .filter(|a| a.timestamp >= one_hour_ago)
            .collect();

        let critical_count = recent_alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count() as u64;
        let high_count = recent_alerts
            .iter()
            .filter(|a| a.severity == AlertSeverity::High)
            .count() as u64;
        let total_count = recent_alerts.len() as u64;

        if critical_count >= config.escalation_thresholds.critical_per_hour
            || high_count >= config.escalation_thresholds.high_per_hour
            || total_count >= config.escalation_thresholds.total_per_hour
        {
            warn!(
                "Escalation conditions met: {} critical, {} high, {} total alerts in last hour",
                critical_count, high_count, total_count
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert!(config.enable_monitoring);
        assert_eq!(config.max_alerts, 1000);
        assert!(config.enable_escalation);
    }

    #[test]
    fn test_alert_severity() {
        assert_eq!(AlertSeverity::Low.as_str(), "low");
        assert_eq!(AlertSeverity::Critical.color_code(), "#F44336");
        assert_eq!(AlertSeverity::High.numeric_value(), 3);
        assert!(AlertSeverity::Critical > AlertSeverity::High);
    }

    #[tokio::test]
    async fn test_security_alert_manager_creation() {
        let config = AlertConfig::default();
        let manager = SecurityAlertManager::new(config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_alert_creation() {
        let manager = SecurityAlertManager::new(AlertConfig::default())
            .await
            .unwrap();

        let alert_id = manager
            .create_alert(
                AlertSeverity::High,
                "Test Alert".to_string(),
                "This is a test alert".to_string(),
                "test_source".to_string(),
                AlertCategory::Security,
            )
            .await
            .unwrap();

        assert!(!alert_id.is_empty());

        let alert = manager.get_alert(&alert_id).await;
        assert!(alert.is_some());

        let alert = alert.unwrap();
        assert_eq!(alert.severity, AlertSeverity::High);
        assert_eq!(alert.title, "Test Alert");
        assert_eq!(alert.status, AlertStatus::Active);
    }

    #[tokio::test]
    async fn test_alert_acknowledgment() {
        let manager = SecurityAlertManager::new(AlertConfig::default())
            .await
            .unwrap();

        let alert_id = manager
            .create_alert(
                AlertSeverity::Medium,
                "Test Alert".to_string(),
                "This is a test alert".to_string(),
                "test_source".to_string(),
                AlertCategory::Security,
            )
            .await
            .unwrap();

        let result = manager
            .acknowledge_alert(&alert_id, "test_user".to_string())
            .await;
        assert!(result.is_ok());

        let alert = manager.get_alert(&alert_id).await.unwrap();
        assert_eq!(alert.status, AlertStatus::Acknowledged);
        assert_eq!(alert.acknowledged_by.as_ref().unwrap(), "test_user");
    }

    #[tokio::test]
    async fn test_alert_resolution() {
        let manager = SecurityAlertManager::new(AlertConfig::default())
            .await
            .unwrap();

        let alert_id = manager
            .create_alert(
                AlertSeverity::Low,
                "Test Alert".to_string(),
                "This is a test alert".to_string(),
                "test_source".to_string(),
                AlertCategory::Security,
            )
            .await
            .unwrap();

        let result = manager
            .resolve_alert(&alert_id, "test_user".to_string())
            .await;
        assert!(result.is_ok());

        let alert = manager.get_alert(&alert_id).await.unwrap();
        assert_eq!(alert.status, AlertStatus::Resolved);
        assert_eq!(alert.resolved_by.as_ref().unwrap(), "test_user");
    }

    #[tokio::test]
    async fn test_alert_statistics() {
        let manager = SecurityAlertManager::new(AlertConfig::default())
            .await
            .unwrap();

        // Create some test alerts
        for i in 0..5 {
            manager
                .create_alert(
                    if i < 2 {
                        AlertSeverity::High
                    } else {
                        AlertSeverity::Low
                    },
                    format!("Alert {}", i),
                    format!("Message {}", i),
                    "test_source".to_string(),
                    AlertCategory::Security,
                )
                .await
                .unwrap();
        }

        let stats = manager.get_alert_statistics().await;
        assert_eq!(stats.total_alerts, 5);
        assert_eq!(stats.high_alerts, 2);
        assert_eq!(stats.low_alerts, 3);
        assert_eq!(stats.active_alerts, 5);
    }

    #[tokio::test]
    async fn test_alert_monitoring_lifecycle() {
        let manager = SecurityAlertManager::new(AlertConfig::default())
            .await
            .unwrap();

        // Start monitoring
        let start_result = manager.start_monitoring().await;
        assert!(start_result.is_ok());

        // Give it a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Stop monitoring
        let stop_result = manager.stop_monitoring().await;
        assert!(stop_result.is_ok());
    }

    #[tokio::test]
    async fn test_alert_cleanup() {
        let mut config = AlertConfig::default();
        config.retention_hours = 1;

        let manager = SecurityAlertManager::new(config).await.unwrap();

        // Create an alert
        manager
            .create_alert(
                AlertSeverity::Low,
                "Test Alert".to_string(),
                "This is a test alert".to_string(),
                "test_source".to_string(),
                AlertCategory::Security,
            )
            .await
            .unwrap();

        // Manually expire the alert
        {
            let mut alerts = manager.alerts.write().await;
            if let Some(alert) = alerts.first_mut() {
                alert.timestamp = Utc::now() - chrono::Duration::hours(2);
            }
        }

        // Wait a moment and cleanup
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let removed_count = manager.cleanup_old_alerts().await.unwrap();

        assert!(removed_count > 0);
    }
}
