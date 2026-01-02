use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::firewall::{FirewallPolicy, FirewallRule};
// use crate::reporting_service::TelemetryEvent;

/// Standard API Response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

// --- Status DTOs ---

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub peer_id: String,
    pub listeners: Vec<String>,
    pub connected_peers: usize,
    pub uptime_secs: u64,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub address: Option<String>,
    pub connected_since: Option<u64>,
}

// --- Request DTOs ---

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectPeerRequest {
    pub multiaddr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub peer_id: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BroadcastRequest {
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallUpdateRequest {
    pub enabled: Option<bool>,
    pub policy: Option<FirewallPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddRuleRequest {
    pub rule: FirewallRule,
}

// --- Control Logic ---

/// Commands that can be sent to the WolfNode from the API
#[derive(Debug)]
pub enum NodeCommand {
    Shutdown,
    ConnectPeer(String),
    DisconnectPeer(String),
    Broadcast(Vec<u8>),
    SendDirect { peer_id: String, data: Vec<u8> },
    UpdateFirewall(FirewallUpdateRequest),
}

/// Handle for controlling the WolfNode asynchronously
#[derive(Clone)]
pub struct WolfNodeControl {
    pub command_tx: mpsc::Sender<NodeCommand>,
    // pub telemetry_tx: Option<mpsc::Sender<TelemetryEvent>>,
}

impl WolfNodeControl {
    pub fn new(
        command_tx: mpsc::Sender<NodeCommand>,
        // telemetry_tx: Option<mpsc::Sender<TelemetryEvent>>,
    ) -> Self {
        Self {
            command_tx,
            // telemetry_tx,
        }
    }

    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::Shutdown)
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send shutdown command"))
    }

    pub async fn connect_peer(&self, addr: String) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::ConnectPeer(addr))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send connect command"))
    }

    pub async fn broadcast(&self, message: Vec<u8>) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::Broadcast(message))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send broadcast command"))
    }

    pub async fn disconnect_peer(&self, peer_id: String) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::DisconnectPeer(peer_id))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send disconnect command"))
    }

    pub async fn send_direct(&self, peer_id: String, data: Vec<u8>) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::SendDirect { peer_id, data })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send direct message command"))
    }

    pub async fn update_firewall(&self, req: FirewallUpdateRequest) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::UpdateFirewall(req))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send firewall update command"))
    }
}
