//! SaaS Hub Reporting Service
//!
//! This service allows headless agents to report health, metrics, and security alerts
//! back to the central SaaS Hub.

use crate::core::AppSettings;
// use crate::dashboard::state::SystemMetricsData;

#[derive(Debug, Default, Clone)]
pub struct SystemMetricsData {
    pub current_cpu_usage: f32,
    pub current_memory_usage: u64,
}
use crate::utils::metrics_simple::SystemEvent;
use anyhow::Result;
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub struct ReportingService {
    settings: Arc<RwLock<AppSettings>>,
    metrics: Arc<RwLock<SystemMetricsData>>,
    client: Client,
    auth_token: Arc<RwLock<Option<String>>>,
    event_queue: Arc<RwLock<Vec<SystemEvent>>>,
}

impl ReportingService {
    pub fn new(
        settings: Arc<RwLock<AppSettings>>,
        metrics: Arc<RwLock<SystemMetricsData>>,
    ) -> Self {
        Self {
            settings,
            metrics,
            client: Client::new(),
            auth_token: Arc::new(RwLock::new(None)),
            event_queue: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Starts the background reporting loop
    pub async fn start(self: Arc<Self>) {
        info!("📡 Starting SaaS Hub Reporting Service...");

        // Initial login
        if let Err(e) = self.login().await {
            error!("❌ Initial Hub login failed: {}", e);
        }

        let mut telemetry_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        let mut batch_interval = tokio::time::interval(tokio::time::Duration::from_secs(10));

        loop {
            tokio::select! {
                _ = telemetry_interval.tick() => {
                    if let Err(e) = self.report_telemetry().await {
                        error!("❌ Hub Telemetry Error: {}", e);
                    }
                }
                _ = batch_interval.tick() => {
                    if let Err(e) = self.flush_events().await {
                        error!("❌ Hub Event Flush Error: {}", e);
                    }
                }
            }
        }
    }

    /// Authenticate with the Hub to get a JWT
    async fn login(&self) -> Result<()> {
        let (hub_url, org_key) = {
            let s = self.settings.read().await;
            (s.hub_url.clone(), s.org_key.clone())
        };

        if let (Some(url), Some(key)) = (hub_url, org_key) {
            let endpoint = format!("{}/api/v1/agent/login", url);
            let response = self
                .client
                .post(&endpoint)
                .json(&json!({ "org_key": key }))
                .send()
                .await?;

            let status = response.status();
            if status.is_success() {
                let res_data: serde_json::Value = response.json().await?;
                if let Some(token) = res_data.get("token").and_then(|t| t.as_str()) {
                    let mut auth = self.auth_token.write().await;
                    *auth = Some(token.to_string());
                    info!("✓ Successfully authenticated with Hub, JWT acquired.");
                    return Ok(());
                }
            }
            return Err(anyhow::anyhow!("Hub login failed: {}", status));
        }
        Ok(())
    }

    /// Collects and sends telemetry data to the Hub
    async fn report_telemetry(&self) -> Result<()> {
        let (hub_url, org_key) = {
            let s = self.settings.read().await;
            (s.hub_url.clone(), s.org_key.clone())
        };

        if let (Some(url), Some(key)) = (hub_url, org_key) {
            let metrics_data = self.metrics.read().await;

            let payload = json!({
                "org_key": key,
                "timestamp": chrono::Utc::now(),
                "node_metrics": {
                    "cpu": metrics_data.current_cpu_usage,
                    "memory": metrics_data.current_memory_usage,
                },
                "agent_status": "online"
            });

            let endpoint = format!("{}/api/v1/agent/report", url);
            let token = self.auth_token.read().await.clone();

            let mut request = self.client.post(&endpoint).json(&payload);
            if let Some(t) = token {
                request = request.bearer_auth(t);
            } else {
                request = request.header("X-Org-Key", key);
            }

            let response = request.send().await?;

            if response.status().is_success() {
                info!("✓ Telemetry sent to Hub: {}", url);
            } else {
                warn!(
                    "⚠️ Hub rejected telemetry: {} (Status: {})",
                    url,
                    response.status()
                );
            }
        } else {
            // Silently skip if not configured for SaaS Hub
        }

        Ok(())
    }

    /// Reports a high-severity security event immediately
    pub async fn report_security_event(&self, event: &SystemEvent) -> Result<()> {
        let mut queue = self.event_queue.write().await;
        queue.push(event.clone());

        if queue.len() >= 10 {
            drop(queue);
            let _ = self.flush_events().await;
        }

        Ok(())
    }

    /// Sends batched security events to the Hub
    async fn flush_events(&self) -> Result<()> {
        let events = {
            let mut queue = self.event_queue.write().await;
            if queue.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *queue)
        };

        let (hub_url, org_key) = {
            let s = self.settings.read().await;
            (s.hub_url.clone(), s.org_key.clone())
        };

        if let (Some(url), Some(key)) = (hub_url, org_key) {
            let endpoint = format!("{}/api/v1/agent/alert", url);
            let token = self.auth_token.read().await.clone();

            let payload = json!({
                "events": events
            });

            let mut request = self.client.post(&endpoint).json(&payload);
            if let Some(t) = token {
                request = request.bearer_auth(t);
            } else {
                request = request.header("X-Org-Key", key);
            }

            let response = request.send().await?;

            if response.status() == StatusCode::UNAUTHORIZED {
                // Token might be expired, try to relogin
                if let Ok(()) = self.login().await {
                    // Retry once with new token
                    let token = self.auth_token.read().await.clone();
                    let mut request = self.client.post(&endpoint).json(&payload);
                    if let Some(t) = token {
                        request = request.bearer_auth(t);
                    }
                    let _ = request.send().await?;
                }
            }

            if response.status().is_success() {
                info!("✓ Flushed {} events to Hub", events.len());
            } else {
                warn!("⚠️ Failed to flush events to Hub: {}", response.status());
            }
        }

        Ok(())
    }
}
