use crate::peer::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::SystemTime;

/// The role of this specific node in the pack hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WolfRole {
    Stray,  // Untrusted / New (Can only listen)
    Scout,  // Detector (Can initiate warnings)
    Hunter, // Verifier (Can participate in active hunts)
    Beta,   // Coordinator (Can authorize local hunts)
    Alpha,  // Leader (Pack strategy & global bans)
    Omega,  // Dev God Mode (Absolute authority)
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
    Scent,  // Potential threat detected
    Stalk,  // Verification in progress
    Strike, // Active neutralization
    Feast,  // Post-hunt analysis and reward
    Failed, // Target lost or false positive
}

/// Active Hunt Tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveHunt {
    pub hunt_id: HuntId,
    pub target_ip: String,
    pub status: HuntStatus,
    pub participants: HashSet<PeerId>,
    pub start_time: SystemTime,
    pub evidence: Vec<String>,
    /// Confidence score (0.0 to 1.0) based on peer verification
    pub confidence: f64,
}

/// The atomic state of the local Wolf Node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfState {
    pub role: WolfRole,
    pub prestige: u32,
    pub active_hunts: Vec<ActiveHunt>,
    // In a real implementation, we'd use a dedicated IP handling crate, keeping string for simplicity now
    pub territories: Vec<String>,
    pub leader_id: Option<String>,
    pub election_term: u64,
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
    pub fn new(role: WolfRole) -> Self {
        Self {
            role,
            ..Default::default()
        }
    }

    pub fn add_prestige(&mut self, amount: u32) {
        self.prestige = self.prestige.saturating_add(amount);
        self.evolve();
    }

    pub fn slash_prestige(&mut self, amount: u32) {
        self.prestige = self.prestige.saturating_sub(amount);
        self.devolve();
    }

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
