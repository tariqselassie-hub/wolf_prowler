use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Represents a security or network event to be reported to the SaaS Hub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Type of the telemetry event (e.g., "error", "metric")
    pub event_type: String,
    /// JSON payload containing event-specific data
    pub payload: serde_json::Value,
    /// Unix timestamp (milliseconds) when the event was generated
    pub timestamp: i64,
}

/// Manages the batching and transmission of telemetry and alerts to the Central Hub.
pub struct ReportingService {
    /// HTTP client for external communication with the Hub
    client: reqwest::Client,
    /// Base URL for the Central Hub API
    hub_url: String,
    /// Organization ID for multi-tenant scoping
    org_id: String,
    /// Secure storage for the JWT authentication token
    auth_token: Arc<RwLock<Option<String>>>,
    /// Channel for buffering telemetry events before batching
    event_queue: mpsc::Receiver<TelemetryEvent>,
    /// Maximum number of events to batch before transmission
    batch_size: usize,
    /// Time interval for periodic flushing of the queue
    flush_interval_ms: u64,
}

impl ReportingService {
    /// Creates a new `ReportingService` instance.
    ///
    /// # Arguments
    /// * `hub_url` - Base URL of the SaaS hub API.
    /// * `org_id` - Organization identifier for multi‑tenant routing.
    /// * `event_queue` - Receiver channel for incoming telemetry events.
    /// * `auth_token` - Shared token storage for authentication.
    #[must_use]
    pub fn new(
        hub_url: String,
        org_id: String,
        event_queue: mpsc::Receiver<TelemetryEvent>,
        auth_token: Arc<RwLock<Option<String>>>, // Accept shared token
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            hub_url,
            org_id,
            event_queue,
            auth_token, // Use the provided shared token
            batch_size: 100,
            flush_interval_ms: 5000,
        }
    }

    /// Runs the reporting service event loop, batching telemetry events and sending them to the hub.
    pub async fn run(&mut self) {
        info!("📊 ReportingService started (Hub: {})", self.hub_url);
        let mut batch = Vec::new();
        let mut interval = tokio::time::interval(Duration::from_millis(self.flush_interval_ms));

        loop {
            tokio::select! {
                Some(event) = self.event_queue.recv() => {
                    batch.push(event);
                    if batch.len() >= self.batch_size {
                        let _ = self.flush_batch(&mut batch).await;
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        let _ = self.flush_batch(&mut batch).await;
                    }
                }
            }
        }
    }

    async fn flush_batch(&self, batch: &mut Vec<TelemetryEvent>) -> Result<()> {
        let events = std::mem::take(batch);
        let token_lock = self.auth_token.read().await;

        if let Some(token) = token_lock.as_ref() {
            let hub_url = &self.hub_url;
            let url = format!("{hub_url}/api/v1/telemetry/batch");
            let res = self
                .client
                .post(&url)
                .bearer_auth(token)
                .header("X-Org-ID", &self.org_id)
                .json(&events)
                .send()
                .await;

            match res {
                Ok(resp) if resp.status().is_success() => {
                    debug!("Successfully reported {} events to Hub", events.len());
                }
                Ok(resp) => {
                    error!(
                        "Failed to report telemetry: Hub returned status {}",
                        resp.status()
                    );
                }
                Err(e) => {
                    error!("Network error reporting telemetry: {}", e);
                }
            }
        }
        Ok(())
    }
}
