use super::error::{Result, WolfPackError};
use super::howl::{HowlMessage, HowlPayload, HowlPriority};
use super::state::{HuntId, WolfRole, WolfState};
use super::state_machine::{StateTransitionResult, WolfStateMachine};
use crate::peer::PeerId;
use crate::swarm::{ReputationReporter, SwarmCommand};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

/// Messages handled by the `HuntCoordinator` actor.
#[derive(Debug)]
pub enum CoordinatorMsg {
    /// A Scout has detected a threat and is requesting a Hunt.
    WarningHowl {
        /// Source peer
        source: PeerId,
        /// Target IP
        target_ip: String,
        /// Evidence
        evidence: String,
    },
    /// A Hunter reports the result of their verification.
    HuntReport {
        /// Hunt ID
        hunt_id: HuntId,
        /// Reporting hunter
        hunter: PeerId,
        /// Confirmation status
        confirmed: bool,
    },
    /// An Alpha or Beta requests a hunt (Authoritative).
    HuntRequest {
        /// Unique Hunt ID
        hunt_id: HuntId,
        /// Source peer
        source: PeerId,
        /// Target IP
        target_ip: String,
        /// Min role
        min_role: WolfRole,
    },
    /// An authoritative Kill Order from Alpha/Beta.
    KillOrder {
        /// Target IP
        target_ip: String,
        /// Authorizing peer
        authorizer: PeerId,
        /// Reason
        reason: String,
        /// Hunt ID
        hunt_id: HuntId,
    },
    /// Updates about territory ownership.
    TerritoryUpdate {
        /// Region CIDR
        region: String,
        /// Owner peer
        owner: PeerId,
        /// Status
        status: String,
    },
    /// Admin/System command to force a role change (e.g., God Mode toggle).
    ForceRank {
        /// Target peer (usually local)
        target: PeerId,
        /// New role
        new_role: WolfRole,
    },
    /// Election: Request Vote
    ElectionRequest {
        /// Term
        term: u64,
        /// Candidate
        candidate_id: PeerId,
        /// Prestige
        prestige: u32,
    },
    /// Election: Vote Cast
    ElectionVote {
        /// Term
        term: u64,
        /// Voter
        voter_id: PeerId,
        /// Vote status
        granted: bool,
    },
    /// Election: Leader Heartbeat
    AlphaHeartbeat {
        /// Term
        term: u64,
        /// Leader
        leader_id: PeerId,
    },
    /// Internal tick for garbage collection / timeouts.
    Tick,
}

use super::ElectionManager;

/// The main actor managing the Hunter-Killer Grid.
pub struct HuntCoordinator {
    /// Public view of the state (shared with other components).
    public_state: Arc<RwLock<WolfState>>,
    /// Private state owned by the actor (no locking needed for internal logic).
    state: WolfState,
    /// Channel for receiving actor messages.
    receiver: mpsc::Receiver<CoordinatorMsg>,
    /// Channel for sending commands to Swarm
    swarm_sender: mpsc::Sender<SwarmCommand>,
    /// active hunt timeouts tracking (`HuntID` -> Expiration Time)
    timeouts: HashMap<HuntId, std::time::SystemTime>,
    /// Election Manager
    election_manager: ElectionManager,
    /// Reputation reporter hook
    reputation_reporter: Option<Arc<dyn ReputationReporter>>,
}

impl HuntCoordinator {
    /// Create a new `HuntCoordinator`
    #[must_use]
    pub fn new(
        initial_role: WolfRole,
        swarm_sender: mpsc::Sender<SwarmCommand>,
        local_peer_id: PeerId,
        initial_prestige: u32,
        reputation_reporter: Option<Arc<dyn ReputationReporter>>,
    ) -> (Self, mpsc::Sender<CoordinatorMsg>, Arc<RwLock<WolfState>>) {
        let (tx, rx) = mpsc::channel(100); // Bounded channel for backpressure
        let initial_state = WolfState::new(initial_role);
        let public_state = Arc::new(RwLock::new(initial_state.clone()));

        let actor = Self {
            public_state: public_state.clone(),
            state: initial_state,
            receiver: rx,
            swarm_sender,
            timeouts: HashMap::new(),
            election_manager: ElectionManager::new(local_peer_id, initial_prestige),
            reputation_reporter,
        };

        (actor, tx, public_state)
    }

    /// Start the coordinator actor
    #[allow(clippy::cognitive_complexity)]
    pub async fn run(mut self) {
        info!("🐺 HuntCoordinator Actor Started");

        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                msg = self.receiver.recv() => {
                    if let Some(m) = msg {
                        if let Err(e) = self.handle_message(m).await {
                            warn!("Error handling coordinator message: {e}");
                        }
                    } else {
                        warn!("HuntCoordinator channel closed. Shutting down.");
                        break;
                    }
                }
                _ = interval.tick() => {
                    if let Err(e) = self.handle_message(CoordinatorMsg::Tick).await {
                        warn!("Error during coordinator tick: {}", e);
                    }
                }
            }
        }
    }

    async fn handle_message(&mut self, msg: CoordinatorMsg) -> Result<()> {
        match msg {
            CoordinatorMsg::WarningHowl {
                source,
                target_ip,
                evidence,
            } => self.handle_warning_howl(source, target_ip, evidence).await,
            CoordinatorMsg::HuntReport {
                hunt_id,
                hunter,
                confirmed,
            } => self.handle_hunt_report(hunt_id, hunter, confirmed).await,
            CoordinatorMsg::HuntRequest {
                hunt_id,
                source,
                target_ip,
                min_role,
            } => {
                self.handle_hunt_request(hunt_id, source, target_ip, min_role)
                    .await
            }
            CoordinatorMsg::KillOrder {
                target_ip,
                authorizer,
                reason,
                hunt_id,
            } => {
                self.handle_kill_order(target_ip, authorizer, reason, hunt_id)
                    .await
            }
            CoordinatorMsg::TerritoryUpdate {
                region,
                owner,
                status,
            } => self.handle_territory_update(region, owner, status).await,
            CoordinatorMsg::ForceRank {
                target: _,
                new_role,
            } => {
                // For local node updates, we just update state.
                // Distributed updates would require consensus msg.
                WolfStateMachine::force_role(&mut self.state, new_role);
                self.sync_public_state().await;
                info!("Rank Forced Updated to {:?}", new_role);
                Ok(())
            }
            CoordinatorMsg::Tick => self.handle_tick().await,
            CoordinatorMsg::ElectionRequest {
                term,
                candidate_id,
                prestige,
            } => {
                self.handle_election_request(term, candidate_id, prestige)
                    .await
            }
            CoordinatorMsg::ElectionVote {
                term,
                voter_id,
                granted,
            } => self.handle_election_vote(term, voter_id, granted).await,
            CoordinatorMsg::AlphaHeartbeat { term, leader_id } => {
                self.handle_alpha_heartbeat(term, leader_id).await
            }
        }
    }

    async fn handle_warning_howl(
        &mut self,
        source: PeerId,
        target_ip: String,
        evidence: String,
    ) -> Result<()> {
        match WolfStateMachine::on_warning_howl(
            &mut self.state,
            source.clone(),
            target_ip.clone(),
            evidence,
        ) {
            Ok(hunt_id) => {
                info!(
                    "Received Warning Howl from {}. Initiating Hunt {} on {}",
                    source, hunt_id, target_ip
                );
                // Set Timeout (Fail-Safe)
                self.timeouts.insert(
                    hunt_id,
                    std::time::SystemTime::now() + Duration::from_secs(30),
                );
                self.sync_public_state().await;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn handle_hunt_report(
        &mut self,
        hunt_id: HuntId,
        hunter: PeerId,
        confirmed: bool,
    ) -> Result<()> {
        let transition_result =
            WolfStateMachine::on_hunt_report(&mut self.state, &hunt_id, &hunter, confirmed)?;

        if let StateTransitionResult::Strike {
            hunt_id,
            target_ip,
            participants: _,
        } = transition_result
        {
            self.handle_strike_transition(hunt_id, target_ip).await?;
        }

        self.sync_public_state().await;
        Ok(())
    }

    /// Execute Strike phase - ban target IP via firewall
    async fn execute_strike(&self, target_ip: &str, hunt_id: &str) -> Result<()> {
        info!("⚔️ STRIKE: Banning {} (Hunt: {})", target_ip, hunt_id);

        // Send command to Swarm to update firewall
        self.swarm_sender
            .send(SwarmCommand::BlockIp {
                ip: target_ip.to_string(),
            })
            .await
            .map_err(|e| {
                WolfPackError::NetworkError(format!("Failed to send block command: {e}"))
            })?;

        warn!(
            "🚫 TARGET NEUTRALIZED: {} added to firewall blocklist",
            target_ip
        );
        Ok(())
    }

    async fn handle_strike_transition(&mut self, hunt_id: String, target_ip: String) -> Result<()> {
        info!("🎯 Hunt {}: STRIKE EXECUTION on {}", hunt_id, target_ip);

        // Execute Strike (firewall ban)
        self.execute_strike(&target_ip, &hunt_id).await?;

        // Complete strike transition to Feast
        let feast_result = WolfStateMachine::complete_strike(&mut self.state, &hunt_id)?;

        if let StateTransitionResult::Feast {
            hunt_id: _,
            participants,
        } = feast_result
        {
            self.distribute_rewards(&hunt_id, &participants).await?;
            info!("✅ Hunt {} completed successfully", hunt_id);
        } else {
            warn!("Unexpected state after strike completion for hunt {hunt_id}");
        }
        Ok(())
    }

    /// Distribute prestige rewards (Feast phase)
    async fn distribute_rewards(
        &mut self,
        hunt_id: &str,
        participants: &std::collections::HashSet<PeerId>,
    ) -> Result<()> {
        // Award prestige to all participants
        let reward_per_hunter = 10u32; // Base reward
        let count = u32::try_from(participants.len()).unwrap_or(u32::MAX);
        let total_reward = reward_per_hunter.saturating_mul(count);

        info!(
            "🍖 FEAST: Distributing {} prestige among {} hunters (Hunt: {})",
            total_reward,
            participants.len(),
            hunt_id
        );

        // Award prestige to local node if participating
        self.state.add_prestige(reward_per_hunter);

        // Award reputation to all participants
        if let Some(reporter) = &self.reputation_reporter {
            for peer_id in participants {
                reporter
                    .report_event(
                        &peer_id.to_string(),
                        "Security",
                        0.05, // Positive impact for successful hunt participation
                        format!("Participated in successful hunt {hunt_id}"),
                    )
                    .await;
            }
        }

        info!(
            "💎 Local prestige increased by {} (new total: {})",
            reward_per_hunter, self.state.prestige
        );
        Ok(())
    }

    async fn handle_tick(&mut self) -> Result<()> {
        // Garbage Collection: Remove timed out hunts
        let now = std::time::SystemTime::now();
        let mut expired = Vec::new();

        for (id, time) in &self.timeouts {
            if now > *time {
                expired.push(id.clone());
            }
        }

        if !expired.is_empty() {
            for id in expired {
                warn!("Hunt {} timed out. Marking FAILED.", id);
                let _ = WolfStateMachine::fail_hunt(&mut self.state, &id);
                self.timeouts.remove(&id);
            }
            self.sync_public_state().await;
        }

        // Prestige Decay: Reduce prestige every 60 seconds of inactivity (simulated check every tick)
        if rand::random::<f64>() < (1.0 / 60.0) {
            self.state.apply_decay();
            if self.state.prestige > 0 {
                info!(
                    "📉 Prestige Decay Applied. Current: {}",
                    self.state.prestige
                );
            }
            self.sync_public_state().await;
        }

        // Handle election logic tick
        if let Some(howl_to_send) = self.election_manager.tick() {
            let bytes = howl_to_send
                .to_bytes()
                .map_err(|e| WolfPackError::CoordinationError(e.to_string()))?;
            self.swarm_sender
                .send(SwarmCommand::Broadcast(bytes))
                .await
                .map_err(|e| {
                    WolfPackError::CoordinationError(format!(
                        "Failed to send election tick to swarm: {e}"
                    ))
                })?;
        }
        Ok(())
    }

    async fn handle_hunt_request(
        &mut self,
        hunt_id: HuntId,
        source: PeerId,
        target_ip: String,
        _min_role: WolfRole,
    ) -> Result<()> {
        info!(
            "📜 HUNT REQUEST: {} requested hunt on {} (ID: {})",
            source, target_ip, hunt_id
        );

        if let Err(e) =
            WolfStateMachine::on_hunt_request(&mut self.state, &source, target_ip, &hunt_id)
        {
            warn!("Failed to process hunt request: {}", e);
            return Ok(()); // Don't crash actor
        }

        // Use timeout mechanism
        self.timeouts.insert(
            hunt_id.clone(),
            std::time::SystemTime::now() + std::time::Duration::from_secs(60),
        );

        info!("✅ Hunt {} initiated from request", hunt_id);
        self.sync_public_state().await;
        Ok(())
    }

    async fn handle_kill_order(
        &mut self,
        target_ip: String,
        authorizer: PeerId,
        reason: String,
        hunt_id: HuntId,
    ) -> Result<()> {
        info!(
            "☠️ KILL ORDER RECEIVED: {} ordered neutralization of {} (Reason: {})",
            authorizer, target_ip, reason
        );

        WolfStateMachine::on_kill_order(
            &mut self.state,
            target_ip.clone(),
            &authorizer,
            &reason,
            hunt_id.clone(),
        )?;
        self.sync_public_state().await;

        // Execute Strike immediately
        self.execute_strike(&target_ip, &hunt_id).await?;
        Ok(())
    }

    async fn handle_territory_update(
        &mut self,
        region: String,
        owner: PeerId,
        status: String,
    ) -> Result<()> {
        info!(
            "🗺️ TERRITORY UPDATE: {} claims {} (Status: {})",
            owner, region, status
        );

        if WolfStateMachine::update_territory(&mut self.state, region.clone())? {
            info!("Added new territory: {}", region);
            self.sync_public_state().await;
        }
        Ok(())
    }

    async fn handle_election_request(
        &mut self,
        term: u64,
        candidate_id: PeerId,
        prestige: u32,
    ) -> Result<()> {
        let howl = HowlMessage::new(
            candidate_id.clone(), // The candidate is the sender
            HowlPriority::Alert,
            HowlPayload::ElectionRequest {
                term,
                candidate_id,
                last_log_index: 0, // Not implemented
                prestige,
            },
        );
        match self.election_manager.handle_howl(&howl) {
            Some(response_howl) => {
                if let Ok(bytes) = response_howl.to_bytes() {
                    // A vote response should ideally be sent directly to the candidate.
                    // For now, we broadcast it as per the simple gossipsub model.
                    self.swarm_sender
                        .send(SwarmCommand::Broadcast(bytes))
                        .await
                        .map_err(|e| {
                            WolfPackError::ElectionError(format!(
                                "Failed to send election vote response to swarm: {e}"
                            ))
                        })?;
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    async fn handle_election_vote(
        &mut self,
        term: u64,
        voter_id: PeerId,
        granted: bool,
    ) -> Result<()> {
        let howl = HowlMessage::new(
            voter_id.clone(), // The voter is the sender
            HowlPriority::Info,
            HowlPayload::ElectionVote {
                term,
                voter_id,
                granted,
            },
        );
        match self.election_manager.handle_howl(&howl) {
            Some(response_howl) => {
                // This response would be a heartbeat if we won the election.
                if let Ok(bytes) = response_howl.to_bytes() {
                    self.swarm_sender
                        .send(SwarmCommand::Broadcast(bytes))
                        .await
                        .map_err(|e| {
                            WolfPackError::ElectionError(format!(
                                "Failed to send election result to swarm: {e}"
                            ))
                        })?;
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    async fn handle_alpha_heartbeat(&mut self, term: u64, leader_id: PeerId) -> Result<()> {
        let howl = HowlMessage::new(
            leader_id.clone(), // The leader is the sender
            HowlPriority::Info,
            HowlPayload::AlphaHeartbeat { term, leader_id },
        );
        // Heartbeats update local state. They don't generate a response to broadcast.
        let _ = self.election_manager.handle_howl(&howl);
        self.sync_public_state().await;
        Ok(())
    }

    /// Synchronizes the private actor state to the public shared state.
    async fn sync_public_state(&self) {
        let mut public = self.public_state.write().await;
        *public = self.state.clone();
    }
}
