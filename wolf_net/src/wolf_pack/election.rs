use super::howl::{HowlMessage, HowlPayload, HowlPriority};
use crate::peer::PeerId;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const BASE_ELECTION_TIMEOUT_MS: u64 = 5000;
const ELECTION_TIMEOUT_VARIANCE_MS: u64 = 3000;
const HEARTBEAT_INTERVAL_MS: u64 = 2000;

/// Current state of the node in the Raft consensus lifecycle
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElectionState {
    /// Followers passively listen to the Leader
    Follower,
    /// Candidates campaign for leadership
    Candidate,
    /// Leaders send heartbeats and manage the pack
    Leader,
}

/// Manages the consensus and leader election logic (Raft-lite)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionManager {
    /// Local peer ID
    pub local_peer_id: PeerId,
    /// Current election term
    pub current_term: u64,
    /// ID of the peer voted for in the current term
    pub voted_for: Option<PeerId>,
    /// Current role in election
    pub state: ElectionState,

    // Volatile state
    /// Known leader
    pub leader_id: Option<PeerId>,
    /// Last heard from leader
    #[serde(skip, default = "std::time::Instant::now")]
    last_heartbeat: Instant,
    /// Randomized timeout deadline
    #[serde(skip, default = "ElectionManager::randomized_timeout")]
    election_timeout: Duration,
    /// Votes received in current term (if Candidate)
    #[serde(skip)]
    votes_received: HashSet<PeerId>,

    // For weighting votes
    /// Local prestige score
    pub local_prestige: u32,
    /// Number of peers in the cluster
    pub cluster_size: usize,
}

impl ElectionManager {
    /// Create a new `ElectionManager`
    #[must_use]
    pub fn new(local_peer_id: PeerId, local_prestige: u32) -> Self {
        // Ensure base timeout is significantly larger than heartbeat to prevent thrashing
        // Ensure base timeout is significantly larger than heartbeat to prevent thrashing
        const _: () = assert!(
            BASE_ELECTION_TIMEOUT_MS > HEARTBEAT_INTERVAL_MS * 2,
            "Election timeout should be at least 2x heartbeat interval"
        );

        Self {
            local_peer_id,
            current_term: 0,
            voted_for: None,
            state: ElectionState::Follower,
            leader_id: None,
            last_heartbeat: Instant::now(),
            election_timeout: Self::randomized_timeout(),
            votes_received: HashSet::new(),
            local_prestige,
            cluster_size: 1, // Default to 1 (standalone)
        }
    }

    /// Updates the local node's prestige (impacting vote weight/eligibility)
    pub fn update_prestige(&mut self, prestige: u32) {
        self.local_prestige = prestige;
    }

    /// Proceed time and return any messages to send (e.g. Heartbeats, `VoteRequests`)
    pub fn tick(&mut self) -> Option<HowlMessage> {
        let now = Instant::now();

        match self.state {
            ElectionState::Follower | ElectionState::Candidate => {
                if now.duration_since(self.last_heartbeat) > self.election_timeout {
                    let (msg, won) = self.start_election();
                    if won {
                        return Some(self.send_heartbeat());
                    }
                    return Some(msg);
                }
            }
            ElectionState::Leader => {
                if now.duration_since(self.last_heartbeat)
                    > Duration::from_millis(HEARTBEAT_INTERVAL_MS)
                {
                    self.last_heartbeat = now;
                    return Some(self.send_heartbeat());
                }
            }
        }
        None
    }

    /// Process an incoming Howl message related to elections
    #[must_use]
    pub fn handle_howl(&mut self, msg: &HowlMessage) -> Option<HowlMessage> {
        match &msg.payload {
            HowlPayload::ElectionRequest {
                term,
                candidate_id,
                prestige,
                ..
            } => Some(self.handle_election_request(*term, candidate_id, *prestige)),
            HowlPayload::ElectionVote {
                term,
                granted,
                voter_id: _,
            } => self.handle_vote(*term, *granted, msg.sender.clone()),
            HowlPayload::AlphaHeartbeat { term, leader_id } => {
                self.handle_heartbeat(*term, leader_id)
            }
            _ => None,
        }
    }

    pub fn start_election(&mut self) -> (HowlMessage, bool) {
        self.state = ElectionState::Candidate;
        self.current_term = self.current_term.saturating_add(1);
        self.voted_for = Some(self.local_peer_id.clone());
        self.votes_received.clear();
        self.votes_received.insert(self.local_peer_id.clone());
        self.last_heartbeat = Instant::now();
        self.election_timeout = Self::randomized_timeout();
        self.leader_id = None;

        tracing::info!(
            "Starting election for term {} (Cluster Size: {})",
            self.current_term,
            self.cluster_size
        );

        // Check if we already have quorum (e.g. if we are the only node)
        if self.votes_received.len() >= self.calculate_quorum() {
            tracing::info!(
                "Won election immediately for term {}! Becoming Leader.",
                self.current_term
            );
            self.state = ElectionState::Leader;
            self.leader_id = Some(self.local_peer_id.clone());
            return (self.send_heartbeat(), true);
        }

        // Broadcast RequestVote
        (
            HowlMessage::new(
                self.local_peer_id.clone(),
                HowlPriority::Alert,
                HowlPayload::ElectionRequest {
                    term: self.current_term,
                    candidate_id: self.local_peer_id.clone(),
                    last_log_index: 0, // Not implemented yet
                    prestige: self.local_prestige,
                },
            ),
            false,
        )
    }

    fn send_heartbeat(&self) -> HowlMessage {
        HowlMessage::new(
            self.local_peer_id.clone(),
            HowlPriority::Info,
            HowlPayload::AlphaHeartbeat {
                term: self.current_term,
                leader_id: self.local_peer_id.clone(),
            },
        )
    }

    fn handle_election_request(
        &mut self,
        term: u64,
        candidate_id: &PeerId,
        candidate_prestige: u32,
    ) -> HowlMessage {
        // 1. Reply false if term < currentTerm
        if term < self.current_term {
            return self.send_vote(term, false);
        }

        // Update term if newer
        if term > self.current_term {
            self.current_term = term;
            self.state = ElectionState::Follower;
            self.voted_for = None;
            self.leader_id = None;
        }

        // 2. Grant vote if not voted yet, and candidate meets criteria
        // Criteria: Candidate Rank/Prestige >= Local Rank/Prestige (Simple logic for now)
        // Tie-breaker: Lexicographical ID (common Raft optimization, though not strictly required if randomized timeouts)

        let can_vote = self.voted_for.is_none() || self.voted_for.as_ref() == Some(candidate_id);

        // Prestige check: Only vote for candidates with >= prestige to ensure best leader
        // Relaxed condition: If I am follower, I respect higher prestige.
        // If equal prestige, tie break can be anything.
        // let prestige_sufficient = candidate_prestige >= self.local_prestige;
        let prestige_sufficient = candidate_prestige >= self.local_prestige;

        if can_vote && prestige_sufficient {
            self.voted_for = Some(candidate_id.clone());
            self.election_timeout = Self::randomized_timeout(); // Reset timeout
            return self.send_vote(term, true);
        }

        self.send_vote(term, false)
    }

    fn handle_vote(&mut self, term: u64, granted: bool, voter: PeerId) -> Option<HowlMessage> {
        if term < self.current_term {
            return None;
        }

        if self.state == ElectionState::Candidate && term == self.current_term && granted {
            self.votes_received.insert(voter);

            let quorum = self.calculate_quorum();
            if self.votes_received.len() >= quorum {
                tracing::info!(
                    "Won election for term {} with {} votes! Becoming Leader.",
                    self.current_term,
                    self.votes_received.len()
                );
                self.state = ElectionState::Leader;
                self.leader_id = Some(self.local_peer_id.clone());
                self.last_heartbeat = Instant::now();
                return Some(self.send_heartbeat());
            }
        }
        None
    }

    /// Calculates the required quorum size for the current cluster
    #[must_use]
    pub fn calculate_quorum(&self) -> usize {
        if self.cluster_size <= 1 {
            return 1;
        }
        (self.cluster_size / 2) + 1
    }

    /// Updates the known cluster size
    pub fn update_cluster_size(&mut self, size: usize) {
        if size != self.cluster_size {
            tracing::debug!("Cluster size updated: {} -> {}", self.cluster_size, size);
            self.cluster_size = size;
        }
    }

    fn handle_heartbeat(&mut self, term: u64, leader_id: &PeerId) -> Option<HowlMessage> {
        if term < self.current_term {
            // Reply with current term? Or just ignore. Standard Raft replies with term.
            // For Gossip protocol, we might not reply directly, just ignore.
            return None;
        }

        self.current_term = term;
        self.leader_id = Some(leader_id.clone());
        self.state = ElectionState::Follower;
        self.last_heartbeat = Instant::now();
        self.election_timeout = Self::randomized_timeout();

        None
    }

    fn send_vote(&self, term: u64, granted: bool) -> HowlMessage {
        HowlMessage::new(
            self.local_peer_id.clone(),
            HowlPriority::Info,
            HowlPayload::ElectionVote {
                term,
                voter_id: self.local_peer_id.clone(),
                granted,
            },
        )
    }

    fn randomized_timeout() -> Duration {
        let base = BASE_ELECTION_TIMEOUT_MS;
        let variance_limit = std::cmp::max(1, ELECTION_TIMEOUT_VARIANCE_MS);
        let variance = rand::thread_rng().gen_range(0..variance_limit);
        Duration::from_millis(base.saturating_add(variance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_follower_update_on_higher_term_heartbeat() {
        let local_id = PeerId::new();
        let mut election = ElectionManager::new(local_id.clone(), 10);

        // Initial state
        assert_eq!(election.current_term, 0);
        assert_eq!(election.state, ElectionState::Follower);

        let leader_id = PeerId::new();
        let higher_term = 5;

        let heartbeat = HowlMessage::new(
            leader_id.clone(),
            HowlPriority::Info,
            HowlPayload::AlphaHeartbeat {
                term: higher_term,
                leader_id: leader_id.clone(),
            },
        );

        let _ = election.handle_howl(&heartbeat);

        assert_eq!(election.current_term, higher_term);
        assert_eq!(election.leader_id, Some(leader_id));
        assert_eq!(election.state, ElectionState::Follower);
    }
}
