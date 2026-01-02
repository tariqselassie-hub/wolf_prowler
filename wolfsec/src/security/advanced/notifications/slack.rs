use super::*;

pub struct SlackSender {
    config: SlackConfig,
}

impl SlackSender {
    pub fn new(config: SlackConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NotificationSender for SlackSender {
    async fn send(&self, title: &str, message: &str, metadata: &NotificationMetadata) -> Result<()> {
        let mut fields = Vec::new();
        for (key, value) in metadata {
            fields.push(serde_json::json!({
                "title": key,
                "value": value,
                "short": true
            }));
        }

        let payload = serde_json::json!({
            "channel": self.config.channel,
            "username": self.config.username,
            "text": format!("🚨 Security Alert: *{}*", title),
            "attachments": [{
                "fallback": message,
                "text": message,
                "color": "#F44336", // Default to Red for alerts
                "fields": fields,
                "footer": "Wolf Prowler Security",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        let client = reqwest::Client::new();
        let res = client.post(&self.config.webhook_url)
            .json(&payload)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Slack webhook failed: Status {}, Body: {}", status, text));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Slack"
    }
}
