use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for the Hub connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    /// URL of the central Hub service.
    pub hub_url: String,
    /// API key used for authentication with the Hub.
    pub api_key: String,
    /// Identifier for this agent instance.
    pub agent_id: String,
    /// Run in headless mode (no interactive UI).
    pub headless: bool,
}

/// Request payload for authentication
#[derive(Debug, Serialize)]
struct AuthRequest {
    /// Agent identifier for the auth request.
    agent_id: String,
    /// API key for the auth request.
    api_key: String,
}

/// Response payload for authentication
#[derive(Debug, Deserialize)]
struct AuthResponse {
    /// JWT token returned by the Hub.
    token: String,
    /// Expiration time in seconds.
    expires_in: u64,
}

/// Manages `headless-agent` mode and handles secure JWT authentication handshakes with the Central Hub.
pub struct HubOrchestration {
    config: HubConfig,
    client: reqwest::Client,
    /// Shared storage for the JWT token, shared with `ReportingService`
    auth_token: Arc<RwLock<Option<String>>>,
}

impl HubOrchestration {
    /// Creates a new `HubOrchestration` instance.
    ///
    /// * `config` – Configuration for connecting to the Hub.
    /// * `auth_token` – Shared token storage used by other components.
    pub fn new(config: HubConfig, auth_token: Arc<RwLock<Option<String>>>) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            auth_token,
        }
    }

    /// Authenticates with the Hub to retrieve a JWT token.
    ///
    /// Returns the expiration time of the token in seconds.
    ///
    /// # Errors
    /// Returns an error if the request fails or the response status is not successful.
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

            {
                let mut token_lock = self.auth_token.write().await;
                *token_lock = Some(auth_data.token);
            }

            Ok(auth_data.expires_in)
        } else {
            Err(anyhow::anyhow!(
                "Hub authentication failed with status: {}",
                response.status()
            ))
        }
    }

    /// Runs the main orchestration loop, handling periodic re‑authentication.
    ///
    /// This method will loop indefinitely, refreshing the authentication token before it expires.
    ///
    /// # Errors
    /// Returns error if authentication fails repeatedly (conceptually, though currently loops on error).
    #[allow(clippy::infinite_loop)]
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
                        "Hub authentication successful. Token expires in {expires_in}s. Refreshing in {refresh_secs}s."
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(refresh_secs)).await;
                }
                Err(e) => {
                    eprintln!(
                        "Hub authentication failed: {e}. Retrying in 30 seconds..."
                    );
                    // Retry delay
                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                }
            }
        }
    }
}
