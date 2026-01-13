use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::firewall::{FirewallPolicy, FirewallRule};
// use crate::reporting_service::TelemetryEvent;

/// Standard API Response wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the request was successful.
    pub success: bool,
    /// The returned data if successful.
    pub data: Option<T>,
    /// Error message if unsuccessful.
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    /// Creates a successful response with the given data.
    #[must_use]
    pub const fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Creates an error response with the given message.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

// --- Status DTOs ---

/// Current status of the node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    /// The node's unique peer identifier.
    pub peer_id: String,
    /// List of addresses the node is listening on.
    pub listeners: Vec<String>,
    /// Number of currently connected peers.
    pub connected_peers: usize,
    /// Number of seconds the node has been running.
    pub uptime_secs: u64,
    /// The version string of the node.
    pub version: String,
}

/// Information about a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The unique identifier of the peer.
    pub peer_id: String,
    /// The known network address of the peer.
    pub address: Option<String>,
    /// Timestamp when the peer connected.
    pub connected_since: Option<u64>,
}

// --- Request DTOs ---

/// Request to connect to a new peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectPeerRequest {
    /// The multi-address of the target peer.
    pub multiaddr: String,
}

/// Request to send a direct message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// The target peer identifier.
    pub peer_id: String,
    /// The message content.
    pub message: String,
}

/// Request to broadcast a message to the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastRequest {
    /// The message content to broadcast.
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
/// Request to update firewall settings
pub struct FirewallUpdateRequest {
    /// Enable or disable the firewall.
    pub enabled: Option<bool>,
    /// Set the default firewall policy.
    pub policy: Option<FirewallPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Request to add a firewall rule
pub struct AddRuleRequest {
    /// The rule to be added.
    pub rule: FirewallRule,
}

// --- Control Logic ---

/// Commands that can be sent to the `WolfNode` from the API
#[derive(Debug)]
pub enum NodeCommand {
    /// Gracefully shutdown the node.
    Shutdown,
    /// Establish connection with a new peer.
    ConnectPeer(String),
    /// Terminate connection with an existing peer.
    DisconnectPeer(String),
    /// Broadcast data to the entire network.
    Broadcast(Vec<u8>),
    /// Send data directly to a specific peer.
    SendDirect {
        /// Target peer identifier.
        peer_id: String,
        /// Raw data to send.
        data: Vec<u8>,
    },
    /// Update internal firewall configuration.
    UpdateFirewall(FirewallUpdateRequest),
    /// Forward a coordination message to the Wolf Pack.
    Coordinator(crate::wolf_pack::coordinator::CoordinatorMsg),
}

/// Handle for controlling the `WolfNode` asynchronously
#[derive(Clone)]
pub struct WolfNodeControl {
    /// Transmitter channel for sending commands to the node's main loop.
    pub command_tx: mpsc::Sender<NodeCommand>,
}

impl WolfNodeControl {
    /// Creates a new `WolfNodeControl` handle.
    #[must_use]
    pub const fn new(command_tx: mpsc::Sender<NodeCommand>) -> Self {
        Self { command_tx }
    }

    /// Requests a graceful shutdown of the node.
    ///
    /// # Errors
    /// Returns an error if the command transmitter is closed.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::Shutdown)
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send shutdown command"))
    }

    /// Requests the node to connect to a specific multi‑address.
    ///
    /// # Errors
    /// Returns an error if the command transmitter is closed.
    pub async fn connect_peer(&self, addr: String) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::ConnectPeer(addr))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send connect command"))
    }

    /// Requests the node to broadcast a message to the gossipsub network.
    ///
    /// # Errors
    /// Returns an error if the command transmitter is closed.
    pub async fn broadcast(&self, message: Vec<u8>) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::Broadcast(message))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send broadcast command"))
    }

    /// Requests the node to disconnect from a specific peer ID.
    ///
    /// # Errors
    /// Returns an error if the command transmitter is closed.
    pub async fn disconnect_peer(&self, peer_id: String) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::DisconnectPeer(peer_id))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send disconnect command"))
    }

    /// Sends a direct message to a specific peer.
    ///
    /// # Errors
    /// Returns an error if the command transmitter is closed.
    pub async fn send_direct(&self, peer_id: String, data: Vec<u8>) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::SendDirect { peer_id, data })
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send direct message command"))
    }

    /// Updates the node's firewall configuration.
    ///
    /// # Errors
    /// Returns an error if the command transmitter is closed.
    pub async fn update_firewall(&self, req: FirewallUpdateRequest) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::UpdateFirewall(req))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send firewall update command"))
    }

    /// Sends a coordination message to the Wolf Pack coordinator.
    ///
    /// # Errors
    /// Returns an error if the command transmitter is closed.
    pub async fn send_coordinator_msg(
        &self,
        msg: crate::wolf_pack::coordinator::CoordinatorMsg,
    ) -> anyhow::Result<()> {
        self.command_tx
            .send(NodeCommand::Coordinator(msg))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send coordinator command"))
    }
}
