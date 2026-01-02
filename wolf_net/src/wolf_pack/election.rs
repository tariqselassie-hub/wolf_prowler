use super::error::Result;
// use super::error::WolfPackError;
use super::howl::{HowlMessage, HowlPayload, HowlPriority};
use crate::peer::PeerId;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const BASE_ELECTION_TIMEOUT_MS: u64 = 5000;
const ELECTION_TIMEOUT_VARIANCE_MS: u64 = 3000;
const HEARTBEAT_INTERVAL_MS: u64 = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElectionState {
    Follower,
    Candidate,
    Leader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionManager {
    pub local_peer_id: PeerId,
    pub current_term: u64,
    pub voted_for: Option<PeerId>,
    pub state: ElectionState,

    // Volatile state
    pub leader_id: Option<PeerId>,
    #[serde(skip, default = "std::time::Instant::now")]
    last_heartbeat: Instant,
    #[serde(skip, default = "ElectionManager::randomized_timeout")]
    election_timeout: Duration,
    #[serde(skip)]
    votes_received: HashSet<PeerId>,

    // For weighting votes
    pub local_prestige: u32,
}

impl ElectionManager {
    pub fn new(local_peer_id: PeerId, local_prestige: u32) -> Self {
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
        }
    }

    pub fn update_prestige(&mut self, prestige: u32) {
        self.local_prestige = prestige;
    }

    /// Proceed time and return any messages to send (e.g. Heartbeats, VoteRequests)
    pub fn tick(&mut self) -> Option<HowlMessage> {
        let now = Instant::now();

        match self.state {
            ElectionState::Follower | ElectionState::Candidate => {
                if now.duration_since(self.last_heartbeat) > self.election_timeout {
                    return Some(self.start_election());
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

    pub fn handle_howl(&mut self, msg: &HowlMessage) -> Result<Option<HowlMessage>> {
        match &msg.payload {
            HowlPayload::ElectionRequest {
                term,
                candidate_id,
                prestige,
                ..
            } => self.handle_election_request(*term, candidate_id, *prestige),
            HowlPayload::ElectionVote {
                term,
                granted,
                voter_id: _,
            } => self.handle_vote(*term, *granted, msg.sender.clone()),
            HowlPayload::AlphaHeartbeat { term, leader_id } => {
                self.handle_heartbeat(*term, leader_id)
            }
            _ => Ok(None),
        }
    }

    fn start_election(&mut self) -> HowlMessage {
        self.state = ElectionState::Candidate;
        self.current_term += 1;
        self.voted_for = Some(self.local_peer_id.clone());
        self.votes_received.clear();
        self.votes_received.insert(self.local_peer_id.clone());
        self.last_heartbeat = Instant::now();
        self.election_timeout = Self::randomized_timeout();
        self.leader_id = None;

        println!("Starting election for term {}", self.current_term);

        // Broadcast RequestVote
        HowlMessage::new(
            self.local_peer_id.clone(),
            HowlPriority::Alert,
            HowlPayload::ElectionRequest {
                term: self.current_term,
                candidate_id: self.local_peer_id.clone(),
                last_log_index: 0, // Not implemented yet
                prestige: self.local_prestige,
            },
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
    ) -> Result<Option<HowlMessage>> {
        // 1. Reply false if term < currentTerm
        if term < self.current_term {
            return Ok(Some(self.send_vote(term, false)));
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
        let prestige_sufficient = candidate_prestige >= self.local_prestige;

        if can_vote && prestige_sufficient {
            self.voted_for = Some(candidate_id.clone());
            self.election_timeout = Self::randomized_timeout(); // Reset timeout
            return Ok(Some(self.send_vote(term, true)));
        }

        Ok(Some(self.send_vote(term, false)))
    }

    fn handle_vote(
        &mut self,
        term: u64,
        granted: bool,
        voter: PeerId,
    ) -> Result<Option<HowlMessage>> {
        if term < self.current_term {
            return Ok(None);
        }

        if self.state == ElectionState::Candidate && term == self.current_term && granted {
            self.votes_received.insert(voter);

            // Should be configurable based on cluster size, using 3 for MVP
            if self.votes_received.len() >= 2 {
                // Simple quorum of 2 (self + 1) for small packs
                println!(
                    "Won election for term {}! Becoming Leader.",
                    self.current_term
                );
                self.state = ElectionState::Leader;
                self.leader_id = Some(self.local_peer_id.clone());
                self.last_heartbeat = Instant::now();
                return Ok(Some(self.send_heartbeat()));
            }
        }
        Ok(None)
    }

    fn handle_heartbeat(&mut self, term: u64, leader_id: &PeerId) -> Result<Option<HowlMessage>> {
        if term < self.current_term {
            // Reply with current term? Or just ignore. Standard Raft replies with term.
            // For Gossip protocol, we might not reply directly, just ignore.
            return Ok(None);
        }

        self.current_term = term;
        self.leader_id = Some(leader_id.clone());
        self.state = ElectionState::Follower;
        self.last_heartbeat = Instant::now();
        self.election_timeout = Self::randomized_timeout();

        Ok(None)
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
        let variance = rand::thread_rng().gen_range(0..ELECTION_TIMEOUT_VARIANCE_MS);
        Duration::from_millis(base + variance)
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
