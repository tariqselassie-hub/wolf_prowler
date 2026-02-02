use super::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A request to send a notification
#[derive(Debug, Clone)]
pub struct NotificationRequest {
    pub title: String,
    pub message: String,
    pub priority: NotificationPriority,
    pub metadata: NotificationMetadata,
    pub channels: Vec<String>, // Names of senders to use, or empty for all enabled
}

/// The main notification engine
pub struct NotificationEngine {
    senders: Arc<RwLock<HashMap<String, Box<dyn NotificationSender>>>>,
    history: Arc<RwLock<Vec<NotificationResult>>>,
    max_retries: u32,
    retry_delay: Duration,
}

impl NotificationEngine {
    /// Create a new notification engine
    pub fn new() -> Self {
        Self {
            senders: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
        }
    }

    /// Register a notification sender
    pub async fn register_sender(&self, sender: Box<dyn NotificationSender>) {
        let name = sender.name().to_string();
        self.senders.write().await.insert(name, sender);
    }

    /// Send a notification through multiple channels with retry logic
    pub async fn send_notification(&self, request: NotificationRequest) -> Vec<NotificationResult> {
        let mut results = Vec::new();
        let senders = self.senders.read().await;

        let target_senders: Vec<_> = if request.channels.is_empty() {
            senders.values().collect()
        } else {
            request
                .channels
                .iter()
                .filter_map(|name| senders.get(name))
                .collect()
        };

        if target_senders.is_empty() {
            warn!(
                "No notification senders available for request: {}",
                request.title
            );
        }

        for sender in target_senders {
            let result = self.send_with_retry(sender.as_ref(), &request).await;
            results.push(result.clone());
            self.history.write().await.push(result);
        }

        results
    }

    /// Get notification history
    pub async fn get_history(&self) -> Vec<NotificationResult> {
        self.history.read().await.clone()
    }

    async fn send_with_retry(
        &self,
        sender: &dyn NotificationSender,
        request: &NotificationRequest,
    ) -> NotificationResult {
        let mut retry_count = 0;
        let mut last_error = None;

        while retry_count <= self.max_retries {
            if retry_count > 0 {
                tokio::time::sleep(self.retry_delay * retry_count).await;
                debug!(
                    "Retrying notification '{}' via {} (attempt {})",
                    request.title,
                    sender.name(),
                    retry_count
                );
            }

            match sender
                .send(&request.title, &request.message, &request.metadata)
                .await
            {
                Ok(_) => {
                    info!(
                        "Successfully sent notification '{}' via {}",
                        request.title,
                        sender.name()
                    );
                    return NotificationResult {
                        success: true,
                        channel: sender.name().to_string(),
                        timestamp: chrono::Utc::now(),
                        error: None,
                        retry_count,
                    };
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                    error!(
                        "Failed to send notification '{}' via {}: {}",
                        request.title,
                        sender.name(),
                        e
                    );
                    retry_count += 1;
                }
            }
        }

        NotificationResult {
            success: false,
            channel: sender.name().to_string(),
            timestamp: chrono::Utc::now(),
            error: last_error,
            retry_count: self.max_retries,
        }
    }
}

impl Default for NotificationEngine {
    fn default() -> Self {
        Self::new()
    }
}
