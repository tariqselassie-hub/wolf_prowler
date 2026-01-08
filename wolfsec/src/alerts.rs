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

use anyhow::Error;

// Import wolf-themed configurations
use crate::wolf_pack::hierarchy::WolfCommunicationRules;

// Email dependencies
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};

/// Wolf-themed alerts configuration
pub type AlertsConfig = WolfCommunicationRules;

/// Wolf-themed alert manager alias
pub type AlertManager = SecurityAlertManager;

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
        }
    }
}

/// Thresholds governing the automated escalation of alert priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationThresholds {
    /// Critical alerts per hour to trigger escalation.
    pub critical_per_hour: u64,
    /// High alerts per hour to trigger escalation.
    pub high_per_hour: u64,
    /// Total alerts per hour to trigger escalation.
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

/// Notification channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    Log,
    Memory,
    Email(EmailConfig),
    Webhook(WebhookConfig),
    Slack(SlackConfig),
    Discord(DiscordConfig),
}

/// Technical parameters for traditional email relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// Hostname or IP of the SMTP server.
    pub smtp_server: String,
    /// Port number (typically 587 or 465).
    pub smtp_port: u16,
    /// Credentials for SMTP authentication.
    pub username: String,
    /// Password or app-specific token.
    pub password: String,
    /// Evaluated `From` address for the generated email.
    pub from_address: String,
    /// List of primary recipients.
    pub to_addresses: Vec<String>,
}

/// Parameters for outgoing HTTP webhook notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Absolute URL of the receiving endpoint.
    pub url: String,
    /// HTTP verb to use (typically POST).
    pub method: String,
    /// Optional dictionary of HTTP headers.
    pub headers: HashMap<String, String>,
    /// Maximum time to wait for a server response.
    pub timeout_secs: u64,
}

/// Parameters for Slack platform integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    /// Inbound webhook URL for the targeted workspace.
    pub webhook_url: String,
    /// Slack channel name or ID (e.g., "#security-alerts").
    pub channel: String,
    /// Display name for the posting bot.
    pub username: String,
}

/// Parameters for Discord platform integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    /// Webhook URL for the targeted Discord channel.
    pub webhook_url: String,
    /// Display name for the posting bot.
    pub username: String,
}

/// Criteria for including or omitting alerts from notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFilter {
    /// Whether this filter should include or exclude matches.
    pub filter_type: FilterType,
    /// Optional severity level to match.
    pub severity: Option<AlertSeverity>,
    /// Optional glob or substring pattern for the alert source.
    pub source_pattern: Option<String>,
    /// Optional glob or substring pattern for the alert message.
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

/// A formalized security alert record including lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    /// Unique identifier for the alert.
    pub id: String,
    /// Precision point in time when the alert was generated.
    pub timestamp: DateTime<Utc>,
    /// Relative priority of the alert.
    pub severity: AlertSeverity,
    /// Current state in the alert lifecycle.
    pub status: AlertStatus,
    /// human-readable short title.
    pub title: String,
    /// Comprehensive narrative of the security event.
    pub message: String,
    /// Identifier of the component that emitted the alert.
    pub source: String,
    /// Functional categorization of the alert.
    pub category: AlertCategory,
    /// Technical key-value pairs for advanced analysis.
    pub metadata: HashMap<String, String>,
    /// How many times this alert has been escalated (0-255).
    pub escalation_level: u8,
    /// Identity of the operator who acknowledged the alert.
    pub acknowledged_by: Option<String>,
    /// Point in time when acknowledgment occurred.
    pub acknowledged_at: Option<DateTime<Utc>>,
    /// Identity of the operator who resolved the alert.
    pub resolved_by: Option<String>,
    /// Point in time when resolution occurred.
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

/// Consolidated telemetry and performance data for the alerting system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatistics {
    /// Total alerts ever recorded.
    pub total_alerts: usize,
    /// Number of alerts currently in the `Active` state.
    pub active_alerts: usize,
    /// Number of currently active `Critical` severity alerts.
    pub critical_alerts: usize,
    /// Number of currently active `High` severity alerts.
    pub high_alerts: usize,
    /// Number of currently active `Medium` severity alerts.
    pub medium_alerts: usize,
    /// Number of currently active `Low` severity alerts.
    pub low_alerts: usize,
    /// Distribution of alerts across categories.
    pub alerts_by_category: HashMap<String, usize>,
    /// Distribution of alerts across reporting sources.
    pub alerts_by_source: HashMap<String, usize>,
    /// Mean time (in minutes) between alert creation and resolution.
    pub average_resolution_time_minutes: f64,
    /// Percentage of alerts that required automated or manual escalation.
    pub escalation_rate: f64,
}

/// A record of an automated or manual alert priority increase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEscalation {
    /// Identifier of the alert being escalated.
    pub alert_id: String,
    /// The specific level the alert was increased to.
    pub escalation_level: u8,
    /// Point in time when escalation occurred.
    pub escalated_at: DateTime<Utc>,
    /// Technical or logical reason for the escalation.
    pub reason: String,
    /// List of channels notified as a result of this escalation.
    pub notified_channels: Vec<String>,
}

/// Security alert manager
pub struct SecurityAlertManager {
    config: AlertConfig,
    alerts: Arc<RwLock<Vec<SecurityAlert>>>,
    escalations: Arc<RwLock<Vec<AlertEscalation>>>,
    is_monitoring: Arc<RwLock<bool>>,
}

impl SecurityAlertManager {
    /// Create a new security alert manager
    pub async fn new(config: AlertConfig) -> Result<Self, Error> {
        info!("Initializing security alert manager");

        let manager = Self {
            config: config.clone(),
            alerts: Arc::new(RwLock::new(Vec::new())),
            escalations: Arc::new(RwLock::new(Vec::new())),
            is_monitoring: Arc::new(RwLock::new(false)),
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
            Err(anyhow::anyhow!("Alert not found: {}", alert_id))
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
            Err(anyhow::anyhow!("Alert not found: {}", alert_id))
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
            Err(anyhow::anyhow!("Alert not found: {}", alert_id))
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

    /// Send notifications for alert
    async fn send_notifications(&self, alert: &SecurityAlert) -> Result<(), Error> {
        for channel in &self.config.notification_channels {
            match channel {
                NotificationChannel::Log => {
                    self.send_log_notification(alert).await?;
                }
                NotificationChannel::Memory => {
                    // Already stored in memory
                }
                NotificationChannel::Email(config) => {
                    self.send_email_notification(alert, config).await?;
                }
                NotificationChannel::Webhook(config) => {
                    self.send_webhook_notification(alert, config).await?;
                }
                NotificationChannel::Slack(config) => {
                    self.send_slack_notification(alert, config).await?;
                }
                NotificationChannel::Discord(config) => {
                    self.send_discord_notification(alert, config).await?;
                }
            }
        }
        Ok(())
    }

    /// Send log notification
    async fn send_log_notification(&self, alert: &SecurityAlert) -> Result<(), Error> {
        match alert.severity {
            AlertSeverity::Critical => error!("ALERT: [{}] {}", alert.title, alert.message),
            AlertSeverity::High => warn!("ALERT: [{}] {}", alert.title, alert.message),
            AlertSeverity::Medium => info!("ALERT: [{}] {}", alert.title, alert.message),
            AlertSeverity::Low => debug!("ALERT: [{}] {}", alert.title, alert.message),
        }
        Ok(())
    }

    /// Send email notification
    async fn send_email_notification(
        &self,
        alert: &SecurityAlert,
        config: &EmailConfig,
    ) -> Result<(), Error> {
        info!("Sending email notification via {}", config.smtp_server);

        for to_address in &config.to_addresses {
            let email = Message::builder()
                .from(
                    config
                        .from_address
                        .parse()
                        .map_err(|e| anyhow::anyhow!("Invalid from address: {}", e))?,
                )
                .to(to_address
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid to address: {}", e))?)
                .subject(format!(
                    "⚠️ Wolf Prowler Security Alert: [{}] {}",
                    alert.severity.as_str().to_uppercase(),
                    alert.title
                ))
                .body(format!(
                    "Wolf Prowler Security Alert\n\n\
                     Title: {}\n\
                     Severity: {}\n\
                     Category: {}\n\
                     Source: {}\n\
                     Time: {}\n\n\
                     Message:\n{}\n\n\
                     --\n\
                     Wolf Prowler Security System",
                    alert.title,
                    alert.severity.as_str().to_uppercase(),
                    alert.category.as_str(),
                    alert.source,
                    alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    alert.message
                ))
                .map_err(|e| anyhow::anyhow!("Failed to build email: {}", e))?;

            let creds = Credentials::new(config.username.clone(), config.password.clone());

            // Determine if TLS or STARTTLS is needed. For now, we assume STARTTLS on standard ports or implicit on 465.
            // Simplified implementation: Rely on lettre's auto-detection or use relay without custom TLS config for now.
            // Note: In production, explicit TLS configuration might be required.

            let mailer: AsyncSmtpTransport<Tokio1Executor> =
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_server)
                    .map_err(|e| anyhow::anyhow!("Invalid SMTP server: {}", e))?
                    .port(config.smtp_port)
                    .credentials(creds)
                    .build();

            match mailer.send(email).await {
                Ok(_) => info!("Email notification sent to {}", to_address),
                Err(e) => error!("Failed to send email to {}: {}", to_address, e),
            }
        }

        Ok(())
    }

    /// Send webhook notification
    async fn send_webhook_notification(
        &self,
        alert: &SecurityAlert,
        config: &WebhookConfig,
    ) -> Result<(), Error> {
        let payload = serde_json::json!({
            "alert": alert,
            "timestamp": Utc::now(),
        });

        info!("Sending webhook notification to {}", config.url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build http client: {}", e))?;

        let mut request = match config.method.to_uppercase().as_str() {
            "POST" => client.post(&config.url),
            "PUT" => client.put(&config.url),
            _ => client.post(&config.url), // Default to POST
        };

        // Add headers
        for (key, value) in &config.headers {
            request = request.header(key, value);
        }

        let response = request
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send webhook request: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!("Webhook request failed with status {}: {}", status, text);
            return Err(anyhow::anyhow!("Webhook failed: {}", status));
        }

        info!("Webhook notification sent successfully");
        Ok(())
    }

    /// Send Slack notification
    async fn send_slack_notification(
        &self,
        alert: &SecurityAlert,
        config: &SlackConfig,
    ) -> Result<(), Error> {
        let payload = serde_json::json!({
            "channel": config.channel,
            "username": config.username,
            "text": format!("🚨 Security Alert: [{}] {}", alert.title, alert.message),
            "attachments": [{
                "color": alert.severity.color_code(),
                "fields": [
                    {"title": "Severity", "value": alert.severity.as_str(), "short": true},
                    {"title": "Source", "value": &alert.source, "short": true},
                    {"title": "Category", "value": alert.category.as_str(), "short": true},
                    {"title": "Time", "value": alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(), "short": true}
                ]
            }]
        });

        info!("Sending Slack notification to channel {}", config.channel);

        let client = reqwest::Client::new();
        let response = client
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send Slack notification: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!("Slack notification failed with status {}: {}", status, text);
            return Err(anyhow::anyhow!("Slack notification failed: {}", status));
        }

        info!("Slack notification sent successfully");
        Ok(())
    }

    /// Send Discord notification
    async fn send_discord_notification(
        &self,
        alert: &SecurityAlert,
        config: &DiscordConfig,
    ) -> Result<(), Error> {
        let payload = serde_json::json!({
            "username": config.username,
            "content": format!("🚨 Security Alert: [{}] {}", alert.title, alert.message),
            "embeds": [{
                "title": alert.title.clone(),
                "description": alert.message.clone(),
                "color": match alert.severity {
                    AlertSeverity::Critical => 0xFF0000,
                    AlertSeverity::High => 0xFF8800,
                    AlertSeverity::Medium => 0xFFFF00,
                    AlertSeverity::Low => 0x00FF00,
                },
                "fields": [
                    {"name": "Severity", "value": alert.severity.as_str(), "inline": true},
                    {"name": "Source", "value": &alert.source, "inline": true},
                    {"name": "Category", "value": alert.category.as_str(), "inline": true},
                ],
                "timestamp": alert.timestamp.to_rfc3339(),
            }]
        });

        info!("Sending Discord notification");

        let client = reqwest::Client::new();
        let response = client
            .post(&config.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send Discord notification: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            error!(
                "Discord notification failed with status {}: {}",
                status, text
            );
            return Err(anyhow::anyhow!("Discord notification failed: {}", status));
        }

        info!("Discord notification sent successfully");
        Ok(())
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
        config.retention_hours = 0; // Immediate cleanup

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

        // Wait a moment and cleanup
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let removed_count = manager.cleanup_old_alerts().await.unwrap();

        assert!(removed_count > 0);
    }
}
