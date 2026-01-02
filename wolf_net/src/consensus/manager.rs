//! Consensus Manager
//!
//! Orchestrates the Raft consensus engine and integrates it with the P2P swarm.

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::error;

use crate::consensus::network::RaftNetworkMessage;
use crate::consensus::proposals::Proposal;
use crate::consensus::state::SharedState;
use crate::consensus::{ConsensusEngine, NodeStatus};

/// Commands that can be sent to the Consensus Manager
#[derive(Debug)]
pub enum ConsensusCommand {
    /// Submit a proposal to the cluster
    Propose(Proposal),
    /// Process an incoming Raft message from the network
    ProcessMessage(RaftNetworkMessage),
    /// Get current node status
    GetStatus(tokio::sync::oneshot::Sender<NodeStatus>),
    /// Get current shared state
    GetState(tokio::sync::oneshot::Sender<SharedState>),
}

/// The Consensus Manager handle
#[derive(Clone)]
pub struct ConsensusManager {
    command_tx: mpsc::Sender<ConsensusCommand>,
}

impl ConsensusManager {
    /// Create and start a new Consensus Manager
    pub async fn start(
        node_id: u64,
        peers: Vec<u64>,
        storage_path: &str,
        swarm_tx: mpsc::Sender<crate::swarm::SwarmCommand>,
    ) -> Result<Self> {
        let (command_tx, mut command_rx) = mpsc::channel(100);
        let mut engine = ConsensusEngine::new(node_id, peers, storage_path).await?;

        let manager_handle = Self { command_tx };

        // Spawn the main consensus loop
        tokio::spawn(async move {
            let mut tick_interval = tokio::time::interval(tokio::time::Duration::from_millis(100));

            loop {
                tokio::select! {
                    _ = tick_interval.tick() => {
                        engine.tick();
                        if let Err(e) = Self::handle_ready(&mut engine, &swarm_tx).await {
                            error!("Error handling Raft ready: {}", e);
                        }
                    }
                    Some(cmd) = command_rx.recv() => {
                        match cmd {
                            ConsensusCommand::Propose(proposal) => {
                                if let Err(e) = engine.propose(proposal).await {
                                    error!("Proposal failed: {}", e);
                                }
                            }
                            ConsensusCommand::ProcessMessage(net_msg) => {
                                match net_msg.decode() {
                                    Ok(raft_msg) => {
                                        if let Err(e) = engine.raw_node.step(raft_msg) {
                                            error!("Error stepping Raft: {}", e);
                                        }
                                    }
                                    Err(e) => error!("Failed to decode Raft message: {}", e),
                                }
                            }
                            ConsensusCommand::GetStatus(tx) => {
                                let _ = tx.send(engine.status());
                            }
                            ConsensusCommand::GetState(tx) => {
                                let state = engine.get_state().await;
                                let _ = tx.send((*state).clone());
                            }
                        }
                    }
                }
            }
        });

        Ok(manager_handle)
    }

    /// Handle the Raft "ready" state (messages to send, entries to apply)
    async fn handle_ready(
        engine: &mut ConsensusEngine,
        swarm_tx: &mpsc::Sender<crate::swarm::SwarmCommand>,
    ) -> Result<()> {
        let raft_messages = engine.step_ready().await?;

        for msg in raft_messages {
            let net_msg = RaftNetworkMessage::new(engine.node_id, msg.to, msg);
            if let Err(e) = swarm_tx
                .send(crate::swarm::SwarmCommand::ConsensusMessage(net_msg))
                .await
            {
                error!("Failed to send Raft network message to swarm: {}", e);
            }
        }

        Ok(())
    }

    /// Propose a change
    pub async fn propose(&self, proposal: Proposal) -> Result<()> {
        self.command_tx
            .send(ConsensusCommand::Propose(proposal))
            .await?;
        Ok(())
    }

    /// Process a received message
    pub async fn process_message(&self, msg: RaftNetworkMessage) -> Result<()> {
        self.command_tx
            .send(ConsensusCommand::ProcessMessage(msg))
            .await?;
        Ok(())
    }

    /// Get status
    pub async fn get_status(&self) -> Result<NodeStatus> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(ConsensusCommand::GetStatus(tx))
            .await?;
        Ok(rx.await?)
    }

    /// Get state
    pub async fn get_state(&self) -> Result<SharedState> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx.send(ConsensusCommand::GetState(tx)).await?;
        Ok(rx.await?)
    }
}
