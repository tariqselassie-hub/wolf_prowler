use crate::peer::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::SystemTime;

/// The role of this specific node in the pack hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WolfRole {
    /// Untrusted / New (Can only listen)
    Stray,
    /// Detector (Can initiate warnings)
    Scout,
    /// Verifier (Can participate in active hunts)
    Hunter,
    /// Coordinator (Can authorize local hunts)
    Beta,
    /// Leader (Pack strategy & global bans)
    Alpha,
    /// Dev God Mode (Absolute authority)
    Omega,
}

impl Default for WolfRole {
    fn default() -> Self {
        WolfRole::Stray
    }
}

/// Unique identifier for a Hunt operation.
pub type HuntId = String;

/// The lifecycle state of a Hunt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HuntStatus {
    /// Potential threat detected
    Scent,
    /// Verification in progress
    Stalk,
    /// Active neutralization
    Strike,
    /// Post-hunt analysis and reward
    Feast,
    /// Target lost or false positive
    Failed,
}

/// Active Hunt Tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveHunt {
    /// Unique ID for the hunt
    pub hunt_id: HuntId,
    /// The target IP address
    pub target_ip: String,
    /// Current status of the hunt
    pub status: HuntStatus,
    /// Implicated peers involved in the hunt
    pub participants: HashSet<PeerId>,
    /// When the hunt began
    pub start_time: SystemTime,
    /// Collected evidence strings
    pub evidence: Vec<String>,
    /// Confidence score (0.0 to 1.0) based on peer verification
    pub confidence: f64,
}

/// The atomic state of the local Wolf Node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfState {
    /// The node's current role
    pub role: WolfRole,
    /// The node's reputation score
    pub prestige: u32,
    /// List of currently active hunts
    pub active_hunts: Vec<ActiveHunt>,
    /// List of territories (IP ranges) this node monitors
    // In a real implementation, we'd use a dedicated IP handling crate, keeping string for simplicity now
    pub territories: Vec<String>,
    /// The current leader's ID
    pub leader_id: Option<String>,
    /// Current election term
    pub election_term: u64,
    /// Current election state (e.g., "Follower", "Candidate")
    pub election_state: String,
}

impl Default for WolfState {
    fn default() -> Self {
        Self {
            role: WolfRole::default(),
            prestige: 0,
            active_hunts: Vec::new(),
            territories: Vec::new(),
            leader_id: None,
            election_term: 0,
            election_state: "Follower".to_string(),
        }
    }
}

impl WolfState {
    /// Creates a new WolfState with a specific role
    pub fn new(role: WolfRole) -> Self {
        Self {
            role,
            ..Default::default()
        }
    }

    /// Increases prestige and checks for evolution
    pub fn add_prestige(&mut self, amount: u32) {
        self.prestige = self.prestige.saturating_add(amount);
        self.evolve();
    }

    /// Decreases prestige and checks for devolution
    pub fn slash_prestige(&mut self, amount: u32) {
        self.prestige = self.prestige.saturating_sub(amount);
        self.devolve();
    }

    /// Applies natural decay to prestige over time
    pub fn apply_decay(&mut self) {
        // Natural decay over time.
        // 1 point loss per tick (handled by coordinator).
        if self.prestige > 0 {
            self.prestige -= 1;
            // Decay can trigger devoluation if you fall below threshold
            self.devolve();
        }
    }

    /// Checks if the node should evolve based on prestige thresholds.
    /// This is the "Gamification" logic.
    fn evolve(&mut self) {
        if self.role == WolfRole::Omega {
            return;
        } // Omega never changes

        // Example thresholds
        let new_role = match self.prestige {
            p if p >= 5000 => WolfRole::Alpha, // High bar for Alpha
            p if p >= 1000 => WolfRole::Beta,
            p if p >= 200 => WolfRole::Hunter,
            p if p >= 50 => WolfRole::Scout,
            _ => WolfRole::Stray,
        };

        // Only upgrade, never auto-downgrade via this function (that requires specific slashing)
        if new_role > self.role {
            self.role = new_role;
        }
    }

    fn devolve(&mut self) {
        if self.role == WolfRole::Omega {
            return;
        }

        let correct_role = match self.prestige {
            p if p >= 5000 => WolfRole::Alpha,
            p if p >= 1000 => WolfRole::Beta,
            p if p >= 200 => WolfRole::Hunter,
            p if p >= 50 => WolfRole::Scout,
            _ => WolfRole::Stray,
        };

        if correct_role < self.role {
            self.role = correct_role;
        }
    }
}
