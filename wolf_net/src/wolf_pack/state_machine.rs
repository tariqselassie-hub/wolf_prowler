use super::error::{Result, WolfPackError};
use super::state::{ActiveHunt, HuntId, HuntStatus, WolfRole, WolfState};
use crate::peer::PeerId;
use std::collections::HashSet;
use std::time::SystemTime;
use uuid::Uuid;

/// Return value indicating the result of a state transition that might require external action.
#[derive(Debug, PartialEq, Eq)]
pub enum StateTransitionResult {
    /// State updated, no side effects needed.
    None,
    /// Hunt transitioned to Strike phase (Consensus Reached).
    Strike {
        hunt_id: HuntId,
        target_ip: String,
        participants: HashSet<PeerId>,
    },
    /// Hunt transitioned to Feast phase (Rewarding).
    Feast {
        hunt_id: HuntId,
        participants: HashSet<PeerId>,
    },
    /// Hunt failed or timed out.
    HuntFailed { hunt_id: HuntId },
}

/// A pure state machine for WolfPack logic.
/// managed by the HuntCoordinator.
pub struct WolfStateMachine;

impl WolfStateMachine {
    /// Handles a Warning Howl (Scout detects threat).
    /// Initiates a new Hunt in 'Stalk' mode if valid.
    pub fn on_warning_howl(
        state: &mut WolfState,
        source: PeerId,
        target_ip: String,
        evidence: String,
    ) -> Result<HuntId> {
        // Validation logic can go here (e.g. check if source is blocked, etc - though that might need more context)

        let hunt_id = format!("hunt-{}-{}", target_ip, Uuid::new_v4());

        // Create Active Hunt Record
        let hunt = ActiveHunt {
            hunt_id: hunt_id.clone(),
            target_ip,
            status: HuntStatus::Stalk,
            participants: HashSet::from([source.clone()]),
            start_time: SystemTime::now(),
            evidence: vec![evidence],
        };

        state.active_hunts.push(hunt);
        Ok(hunt_id)
    }

    /// Handles a Hunt Request from an Authority (Alpha/Beta).
    /// Initiates a new Hunt in 'Scent' mode.
    pub fn on_hunt_request(
        state: &mut WolfState,
        source: PeerId,
        target_ip: String,
        hunt_id: String,
    ) -> Result<()> {
        if state.active_hunts.iter().any(|h| h.hunt_id == hunt_id) {
            // Already active, just ignore
            return Ok(());
        }

        let hunt = ActiveHunt {
            hunt_id: hunt_id.clone(),
            target_ip,
            status: HuntStatus::Scent,
            participants: HashSet::from([source.clone()]),
            start_time: SystemTime::now(),
            evidence: vec![format!("Requested by Authority {}", source)],
        };
        state.active_hunts.push(hunt);
        Ok(())
    }

    /// Handles a Hunt Report (Hunter validates threat).
    /// Returns a transition result if the hunt status changes appropriately.
    pub fn on_hunt_report(
        state: &mut WolfState,
        hunt_id: &str,
        hunter: PeerId,
        confirmed: bool,
    ) -> Result<StateTransitionResult> {
        let hunt = state
            .active_hunts
            .iter_mut()
            .find(|h| h.hunt_id == hunt_id)
            .ok_or_else(|| WolfPackError::HuntNotFound(hunt_id.to_string()))?;

        if hunt.status != HuntStatus::Stalk {
            // Reports only matter in Stalk phase (or Scent, but Stalk is verifying)
            return Ok(StateTransitionResult::None);
        }

        hunt.participants.insert(hunter.clone());

        if confirmed {
            hunt.evidence.push(format!("Confirmed by {}", hunter));
        }

        // Consensus Logic
        let total_participants = hunt.participants.len();
        let confirmations = hunt
            .evidence
            .iter()
            .filter(|e| e.contains("Confirmed by"))
            .count();

        // Rule: Min 3 participants AND 66% consensus
        if total_participants >= 3 {
            let consensus_percentage = (confirmations as f64 / total_participants as f64) * 100.0;
            if consensus_percentage >= 66.0 {
                hunt.status = HuntStatus::Strike;
                return Ok(StateTransitionResult::Strike {
                    hunt_id: hunt.hunt_id.clone(),
                    target_ip: hunt.target_ip.clone(),
                    participants: hunt.participants.clone(),
                });
            }
        }

        Ok(StateTransitionResult::None)
    }

    /// Marks a hunt as successfully struck and ready for rewards.
    pub fn complete_strike(state: &mut WolfState, hunt_id: &str) -> Result<StateTransitionResult> {
        let hunt = state
            .active_hunts
            .iter_mut()
            .find(|h| h.hunt_id == hunt_id)
            .ok_or_else(|| WolfPackError::HuntNotFound(hunt_id.to_string()))?;

        if hunt.status == HuntStatus::Strike {
            hunt.status = HuntStatus::Feast;
            return Ok(StateTransitionResult::Feast {
                hunt_id: hunt.hunt_id.clone(),
                participants: hunt.participants.clone(),
            });
        }
        Ok(StateTransitionResult::None)
    }

    /// Fails a hunt (timeout or otherwise).
    pub fn fail_hunt(state: &mut WolfState, hunt_id: &str) -> Result<()> {
        if let Some(pos) = state.active_hunts.iter().position(|h| h.hunt_id == hunt_id) {
            let hunt = &mut state.active_hunts[pos];
            if hunt.status == HuntStatus::Stalk || hunt.status == HuntStatus::Scent {
                hunt.status = HuntStatus::Failed;
            }
        }
        Ok(())
    }

    /// Updates the local node's role manually.
    pub fn force_role(state: &mut WolfState, new_role: WolfRole) {
        state.role = new_role;
    }
}
