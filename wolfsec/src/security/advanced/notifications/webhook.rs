use super::*;

pub struct WebhookSender {
    config: WebhookConfig,
}

impl WebhookSender {
    pub fn new(config: WebhookConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NotificationSender for WebhookSender {
    async fn send(&self, title: &str, message: &str, metadata: &NotificationMetadata) -> Result<()> {
        let payload = serde_json::json!({
            "alert": {
                "title": title,
                "message": message,
                "timestamp": chrono::Utc::now(),
                "metadata": metadata
            }
        });

        let client = reqwest::Client::new();
        let mut request = match self.config.method.to_uppercase().as_str() {
            "POST" => client.post(&self.config.url),
            "PUT" => client.put(&self.config.url),
            _ => client.post(&self.config.url),
        };

        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        let res = request
            .json(&payload)
            .timeout(Duration::from_secs(self.config.timeout_secs))
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Webhook failed: Status {}, Body: {}", status, text));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Webhook"
    }
}
