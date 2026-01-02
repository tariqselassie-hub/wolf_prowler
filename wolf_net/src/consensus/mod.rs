//! Distributed Consensus Module
//!
//! Implements Raft-based consensus for multi-node Wolf Prowler coordination.
//! Enables shared threat intelligence, synchronized firewall rules, and high availability.

pub mod manager;
pub mod network;
pub mod proposals;
pub mod state;
pub mod storage;

use crate::consensus::proposals::Proposal;
use crate::consensus::state::SharedState;
use crate::consensus::storage::SledStorage;
use anyhow::Result;
use raft::{Config as RaftConfig, RawNode, StateRole, Storage};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Consensus engine managing Raft protocol and shared state
pub struct ConsensusEngine {
    /// Raft node instance
    raw_node: RawNode<SledStorage>,

    /// This node's ID
    node_id: u64,

    /// Peer node IDs
    peers: Vec<u64>,

    /// Shared state machine
    state_machine: Arc<RwLock<SharedState>>,

    /// Persistent storage
    storage: Arc<SledStorage>,
}

impl ConsensusEngine {
    /// Create a new consensus engine
    pub async fn new(node_id: u64, peers: Vec<u64>, storage_path: &str) -> Result<Self> {
        tracing::info!(
            "Initializing consensus engine: node_id={}, peers={:?}",
            node_id,
            peers
        );

        // Configure Raft
        let config = RaftConfig {
            id: node_id,
            election_tick: 10,
            heartbeat_tick: 3,
            max_size_per_msg: 1024 * 1024, // 1MB
            max_inflight_msgs: 256,
            ..Default::default()
        };

        config.validate()?;

        // Create persistent storage
        let storage = Arc::new(SledStorage::new(storage_path)?);

        // Setup logger
        use slog::Drain;
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let logger = slog::Logger::root(drain, slog::o!("node_id" => node_id));

        // Create Raft node
        let raw_node =
            RawNode::new(&config, (*storage).clone(), &logger).map_err(|e| anyhow::anyhow!(e))?;

        // Initialize shared state
        let state_machine = Arc::new(RwLock::new(SharedState::new()));

        // Bootstrap configuration if empty
        if storage.initial_state()?.conf_state.voters.is_empty() && !peers.is_empty() {
            tracing::info!("Bootstrapping Raft configuration with peers: {:?}", peers);
            let mut conf_state = raft::eraftpb::ConfState::default();
            conf_state.voters = peers.clone();
            storage.set_conf_state(&conf_state)?;
        }

        Ok(Self {
            raw_node,
            node_id,
            peers,
            state_machine,
            storage,
        })
    }

    /// Propose a change to the cluster
    pub async fn propose(&mut self, proposal: Proposal) -> Result<()> {
        if !self.is_leader() {
            anyhow::bail!("Only leader can propose changes");
        }

        let data = bincode::serialize(&proposal)?;

        tracing::debug!(
            "Proposing to cluster: {:?} ({} bytes)",
            proposal,
            data.len()
        );

        self.raw_node.propose(vec![], data)?;

        Ok(())
    }

    /// Check if this node is the leader
    pub fn is_leader(&self) -> bool {
        self.raw_node.raft.r.state == StateRole::Leader
    }

    /// Get current leader ID
    pub fn leader_id(&self) -> Option<u64> {
        let leader = self.raw_node.raft.r.leader_id;
        if leader == 0 {
            None
        } else {
            Some(leader)
        }
    }

    /// Get node status
    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            node_id: self.node_id,
            state: match self.raw_node.raft.r.state {
                StateRole::Follower => "Follower".to_string(),
                StateRole::Candidate => "Candidate".to_string(),
                StateRole::Leader => "Leader".to_string(),
                StateRole::PreCandidate => "PreCandidate".to_string(),
            },
            leader_id: self.leader_id(),
            term: self.raw_node.raft.r.term,
            peers: self.peers.clone(),
        }
    }

    /// Process Raft tick (call periodically)
    pub fn tick(&mut self) {
        self.raw_node.tick();
    }

    /// Get read-only access to shared state
    pub async fn get_state(&self) -> tokio::sync::RwLockReadGuard<'_, SharedState> {
        self.state_machine.read().await
    }

    async fn apply_committed_entries(&mut self, entries: Vec<raft::prelude::Entry>) -> Result<()> {
        for entry in entries {
            if entry.data.is_empty() {
                continue;
            }

            let proposal: Proposal = bincode::deserialize(&entry.data)?;
            tracing::info!("Applying proposal at index {}: {:?}", entry.index, proposal);

            let mut state: tokio::sync::RwLockWriteGuard<'_, SharedState> =
                self.state_machine.write().await;
            state.apply(proposal)?;
            state.last_applied = entry.index;
        }
        Ok(())
    }

    /// Apply committed entries and return messages to send
    pub async fn step_ready(&mut self) -> Result<Vec<raft::prelude::Message>> {
        if !self.raw_node.has_ready() {
            return Ok(Vec::new());
        }

        let ready = self.raw_node.ready();

        // Send messages
        let messages = ready.messages().to_vec();

        // Apply committed entries
        let committed_entries = ready.committed_entries().to_vec();
        if !committed_entries.is_empty() {
            self.apply_committed_entries(committed_entries).await?;
        }

        // Persist storage
        if !ready.entries().is_empty() {
            self.storage.append(ready.entries())?;
        }

        if let Some(hs) = ready.hs() {
            self.storage.set_hard_state(hs)?;
        }

        if !ready.snapshot().is_empty() {
            self.storage.apply_snapshot(ready.snapshot().clone())?;
        }

        // Advance
        let light_rd = self.raw_node.advance(ready);

        // Handle LightReady
        let mut all_messages = messages;
        all_messages.extend(light_rd.messages().to_vec());

        let light_committed_entries = light_rd.committed_entries().to_vec();
        if !light_committed_entries.is_empty() {
            self.apply_committed_entries(light_committed_entries)
                .await?;
        }

        if let Some(commit) = light_rd.commit_index() {
            self.storage.set_commit_index(commit)?;
        }

        self.raw_node.advance_apply();

        Ok(all_messages)
    }
}

/// Node status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_id: u64,
    pub state: String,
    pub leader_id: Option<u64>,
    pub term: u64,
    pub peers: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_consensus_engine_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().to_str().unwrap();

        let engine = ConsensusEngine::new(1, vec![2, 3], storage_path)
            .await
            .unwrap();

        assert_eq!(engine.node_id, 1);
        assert_eq!(engine.peers, vec![2, 3]);
    }

    #[tokio::test]
    async fn test_node_status() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().to_str().unwrap();

        let engine = ConsensusEngine::new(1, vec![2, 3], storage_path)
            .await
            .unwrap();

        let status = engine.status();
        assert_eq!(status.node_id, 1);
        assert_eq!(status.peers, vec![2, 3]);
    }
}
