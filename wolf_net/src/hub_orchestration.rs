use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for the Hub connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    pub hub_url: String,
    pub api_key: String,
    pub agent_id: String,
    pub headless: bool,
}

/// Request payload for authentication
#[derive(Debug, Serialize)]
struct AuthRequest {
    agent_id: String,
    api_key: String,
}

/// Response payload for authentication
#[derive(Debug, Deserialize)]
struct AuthResponse {
    token: String,
    expires_in: u64,
}

/// Manages `headless-agent` mode and handles secure JWT authentication handshakes with the Central Hub.
pub struct HubOrchestration {
    config: HubConfig,
    client: reqwest::Client,
    /// Shared storage for the JWT token, shared with ReportingService
    auth_token: Arc<RwLock<Option<String>>>,
}

impl HubOrchestration {
    pub fn new(config: HubConfig, auth_token: Arc<RwLock<Option<String>>>) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            auth_token,
        }
    }

    /// Authenticates with the Hub to retrieve a JWT token
    pub async fn authenticate(&self) -> Result<u64> {
        let url = format!("{}/api/v1/agent/auth", self.config.hub_url);

        let payload = AuthRequest {
            agent_id: self.config.agent_id.clone(),
            api_key: self.config.api_key.clone(),
        };

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send auth request to Hub")?;

        if response.status().is_success() {
            let auth_data: AuthResponse = response
                .json()
                .await
                .context("Failed to parse auth response")?;

            let mut token_lock = self.auth_token.write().await;
            *token_lock = Some(auth_data.token);

            Ok(auth_data.expires_in)
        } else {
            Err(anyhow::anyhow!(
                "Hub authentication failed with status: {}",
                response.status()
            ))
        }
    }

    /// Runs the main orchestration loop, handling periodic re-authentication
    pub async fn run(&self) -> Result<()> {
        loop {
            match self.authenticate().await {
                Ok(expires_in) => {
                    // Refresh 60 seconds before expiration, or default to 1 hour if 0
                    let refresh_secs = if expires_in > 60 {
                        expires_in - 60
                    } else {
                        3600
                    };
                    println!(
                        "Hub authentication successful. Token expires in {}s. Refreshing in {}s.",
                        expires_in, refresh_secs
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(refresh_secs)).await;
                }
                Err(e) => {
                    eprintln!(
                        "Hub authentication failed: {}. Retrying in 30 seconds...",
                        e
                    );
                    // Retry delay
                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                }
            }
        }
    }
}
