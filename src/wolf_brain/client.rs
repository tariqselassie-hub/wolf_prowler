use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::error;

use crate::core::settings::AppSettings;
use crate::utils::metrics_simple::SystemEvent;
use wolf_net::firewall::FirewallRule;

#[derive(Clone)]
pub struct LlamaClient {
    client: Client,
    config: Arc<RwLock<AppSettings>>,
    model: String,
    persona: String,
}

#[derive(Serialize)]
struct GenerateRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct GenerateResponse {
    response: String,
    done: bool,
}

impl LlamaClient {
    pub fn new(config: Arc<RwLock<AppSettings>>, model: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_default();

        Self {
            client,
            config,
            model: model.unwrap_or_else(|| "llama3".to_string()),
            persona: "You are 'Black', an autonomous AI unit of the Wolf Prowler Security Suite. \
                      You are a Red Team specialist and system guardian. \
                      Your responses should be concise, technical, and slightly aggressive but protective. \
                      Identity: The Red Wolf. \
                      You have access to network logs, security events, and system metrics. \
                      Current status: Online within Neural Center.".to_string(),
        }
    }

    pub async fn ask_black(&self, user_query: &str) -> Result<String> {
        let prompt = format!("{}\n\nUSER COMMAND: {}\n\nBLACK:", self.persona, user_query);

        // Get current base URL from settings
        let mut url = {
            let config = self.config.read().await;
            config
                .ai
                .llm_api_url
                .clone()
                .unwrap_or_else(|| "http://localhost:11434".to_string())
        };

        // Sanitize URL
        if url.ends_with("/api/generate") {
            url = url.replace("/api/generate", "");
        }
        if url.ends_with('/') {
            url.pop();
        }
        let base_url = url;

        let request = GenerateRequest {
            model: self.model.clone(),
            prompt,
            stream: false,
        };

        let response = self
            .client
            .post(format!("{}/api/generate", base_url))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            error!("Ollama API Error: {}", error_text);
            return Err(anyhow!("AI Backend Error: {}", error_text));
        }

        let resp_json: GenerateResponse = response.json().await?;
        Ok(resp_json.response.trim().to_string())
    }

    /// Summarizes a list of security events using the AI model.
    pub async fn summarize_events(&self, events: &[SystemEvent]) -> Result<String> {
        if events.is_empty() {
            return Ok("No recent security events to summarize.".to_string());
        }

        let mut events_text = String::new();
        // Take the most recent events (up to 20) to stay within context limits
        for event in events.iter().take(20) {
            events_text.push_str(&format!(
                "[{}] Severity: {}, Type: {}, Source: {}, Message: {}\n",
                event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                event.severity,
                event.event_type,
                event.source,
                event.message
            ));
        }

        let query = format!(
            "Analyze and summarize the following recent security events. Identify any critical threats or suspicious patterns that require immediate attention:\n\n{}",
            events_text
        );

        self.ask_black(&query).await
    }

    /// Suggests firewall rules based on recent security events and current configuration.
    pub async fn suggest_firewall_rules(
        &self,
        events: &[SystemEvent],
        current_rules: &[FirewallRule],
    ) -> Result<String> {
        if events.is_empty() {
            return Ok("No recent security events to analyze for firewall rules.".to_string());
        }

        let mut context = String::new();
        context.push_str("RECENT SECURITY EVENTS:\n");
        for event in events.iter().take(15) {
            context.push_str(&format!(
                "- [{}] {}: {} (Severity: {})\n",
                event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                event.event_type,
                event.message,
                event.severity
            ));
        }

        context.push_str("\nCURRENT FIREWALL RULES:\n");
        for rule in current_rules {
            context.push_str(&format!(
                "- Name: {}, Action: {:?}, Target: {:?}\n",
                rule.name, rule.action, rule.target
            ));
        }

        let query = format!(
            "{}\n\nBased on the security events above, suggest new firewall rules to mitigate these threats. \
            Ensure the rules do not conflict with existing ones. \
            Provide the suggestions in a clear, technical format, explaining the reasoning for each rule.",
            context
        );

        self.ask_black(&query).await
    }
}
