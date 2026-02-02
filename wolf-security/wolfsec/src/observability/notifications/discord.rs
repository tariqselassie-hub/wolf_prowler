use super::*;

pub struct DiscordSender {
    config: DiscordConfig,
}

impl DiscordSender {
    pub fn new(config: DiscordConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NotificationSender for DiscordSender {
    async fn send(
        &self,
        title: &str,
        message: &str,
        metadata: &NotificationMetadata,
    ) -> Result<()> {
        let mut fields = Vec::new();
        for (key, value) in metadata {
            fields.push(serde_json::json!({
                "name": key,
                "value": value,
                "inline": true
            }));
        }

        let payload = serde_json::json!({
            "username": self.config.username,
            "embeds": [{
                "title": format!("🚨 Security Alert: {}", title),
                "description": message,
                "color": 15158528, // Red (hex: E74C3C)
                "fields": fields,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "footer": {
                    "text": "Wolf Prowler Security"
                }
            }]
        });

        let client = reqwest::Client::new();
        let res = client
            .post(&self.config.webhook_url)
            .json(&payload)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Discord webhook failed: Status {}, Body: {}",
                status,
                text
            ));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "Discord"
    }
}
