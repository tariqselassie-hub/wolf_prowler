//! Notification Engine for Wolf Prowler Security Alerting
//!
//! Provides a unified interface for sending notifications across various channels
//! with retry logic, templates, and delivery tracking.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info, warn};

pub mod discord;
pub mod email;
pub mod engine;
pub mod slack;
pub mod templates;
pub mod webhook;

pub use discord::DiscordSender;
pub use email::EmailSender;
pub use engine::{NotificationEngine, NotificationRequest};
pub use slack::SlackSender;
pub use templates::NotificationTemplate;
pub use webhook::WebhookSender;

/// Notification priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NotificationPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Notification channel selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    Log,
    Memory,
    Email(EmailConfig),
    Webhook(WebhookConfig),
    Slack(SlackConfig),
    Discord(DiscordConfig),
}

/// Notification metadata
pub type NotificationMetadata = HashMap<String, String>;

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub to_addresses: Vec<String>,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub timeout_secs: u64,
}

/// Slack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    pub channel: String,
    pub username: String,
}

/// Discord configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    pub webhook_url: String,
    pub username: String,
}

/// Trait for all notification senders
#[async_trait]
pub trait NotificationSender: Send + Sync {
    /// Send a notification
    async fn send(&self, title: &str, message: &str, metadata: &NotificationMetadata)
        -> Result<()>;

    /// Get the sender name
    fn name(&self) -> &str;
}

/// Notification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationResult {
    pub success: bool,
    pub channel: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub error: Option<String>,
    pub retry_count: u32,
}
