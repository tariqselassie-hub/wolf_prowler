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
        // Check if there is an existing hunt for this IP in Scent or Stalk mode.
        // If it's in Scent (Authority requested), promote it to Stalk.
        if let Some(hunt) = state.active_hunts.iter_mut().find(|h| {
            h.target_ip == target_ip
                && (h.status == HuntStatus::Scent || h.status == HuntStatus::Stalk)
        }) {
            if hunt.status == HuntStatus::Scent {
                hunt.status = HuntStatus::Stalk;
            }
            hunt.participants.insert(source);
            hunt.evidence.push(evidence);
            return Ok(hunt.hunt_id.clone());
        }

        let hunt_id = format!("hunt-{}-{}", target_ip, Uuid::new_v4());

        // Create Active Hunt Record
        let hunt = ActiveHunt {
            hunt_id: hunt_id.clone(),
            target_ip,
            status: HuntStatus::Stalk,
            participants: HashSet::from([source.clone()]),
            start_time: SystemTime::now(),
            evidence: vec![evidence],
            confidence: 0.2, // Initial confidence from a single scout
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
            confidence: 0.5, // Higher initial confidence from authority
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

        // Update confidence based on confirmations
        hunt.confidence = (confirmations as f64 / total_participants as f64).min(1.0);

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

    /// Handles a Kill Order (Authoritative Strike).
    /// Ensures the hunt is tracked in state even if it originated externally.
    pub fn on_kill_order(
        state: &mut WolfState,
        target_ip: String,
        authorizer: PeerId,
        reason: String,
        hunt_id: HuntId,
    ) -> Result<()> {
        if !state.active_hunts.iter().any(|h| h.hunt_id == hunt_id) {
            let hunt = ActiveHunt {
                hunt_id,
                target_ip,
                status: HuntStatus::Strike,
                participants: HashSet::from([authorizer.clone()]),
                start_time: SystemTime::now(),
                evidence: vec![format!("Kill Order by {}: {}", authorizer, reason)],
                confidence: 1.0, // Absolute confidence for kill orders
            };
            state.active_hunts.push(hunt);
        }
        Ok(())
    }

    /// Updates territory registry.
    /// Returns true if the territory was newly added.
    pub fn update_territory(state: &mut WolfState, region: String) -> Result<bool> {
        if !state.territories.contains(&region) {
            state.territories.push(region);
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerId;
    use crate::wolf_pack::state::{ActiveHunt, HuntStatus, WolfRole, WolfState};
    use std::collections::HashSet;
    use std::time::SystemTime;

    #[test]
    fn test_warning_howl_creates_hunt() {
        let mut state = WolfState::new(WolfRole::Scout);
        let source = PeerId::new();
        let target_ip = "192.168.1.100".to_string();
        let evidence = "Port scanning detected".to_string();

        let result = WolfStateMachine::on_warning_howl(
            &mut state,
            source.clone(),
            target_ip.clone(),
            evidence,
        );
        assert!(result.is_ok());

        assert_eq!(state.active_hunts.len(), 1);
        let hunt = &state.active_hunts[0];
        assert_eq!(hunt.target_ip, target_ip);
        assert_eq!(hunt.status, HuntStatus::Stalk);
        assert!(hunt.participants.contains(&source));
    }

    #[test]
    fn test_hunt_report_consensus_strike() {
        let mut state = WolfState::new(WolfRole::Hunter);
        let hunt_id = "test-hunt".to_string();
        let target_ip = "1.2.3.4".to_string();

        state.active_hunts.push(ActiveHunt {
            hunt_id: hunt_id.clone(),
            target_ip: target_ip.clone(),
            status: HuntStatus::Stalk,
            participants: HashSet::new(),
            start_time: SystemTime::now(),
            evidence: Vec::new(),
            confidence: 0.0,
        });

        let p1 = PeerId::new();
        let p2 = PeerId::new();
        let p3 = PeerId::new();

        // Report 1
        let res1 = WolfStateMachine::on_hunt_report(&mut state, &hunt_id, p1, true).unwrap();
        assert_eq!(res1, StateTransitionResult::None);

        // Report 2
        let res2 = WolfStateMachine::on_hunt_report(&mut state, &hunt_id, p2, true).unwrap();
        assert_eq!(res2, StateTransitionResult::None);

        // Report 3 - Should trigger Strike
        let res3 = WolfStateMachine::on_hunt_report(&mut state, &hunt_id, p3, true).unwrap();

        match res3 {
            StateTransitionResult::Strike {
                hunt_id: id,
                target_ip: ip,
                ..
            } => {
                assert_eq!(id, hunt_id);
                assert_eq!(ip, target_ip);
            }
            _ => panic!("Expected Strike transition, got {:?}", res3),
        }

        assert_eq!(state.active_hunts[0].status, HuntStatus::Strike);
    }

    #[test]
    fn test_complete_strike_to_feast() {
        let mut state = WolfState::new(WolfRole::Hunter);
        let hunt_id = "strike-hunt".to_string();

        state.active_hunts.push(ActiveHunt {
            hunt_id: hunt_id.clone(),
            target_ip: "5.6.7.8".to_string(),
            status: HuntStatus::Strike,
            participants: HashSet::new(),
            start_time: SystemTime::now(),
            evidence: Vec::new(),
            confidence: 0.8,
        });

        let res = WolfStateMachine::complete_strike(&mut state, &hunt_id).unwrap();

        match res {
            StateTransitionResult::Feast { hunt_id: id, .. } => {
                assert_eq!(id, hunt_id);
            }
            _ => panic!("Expected Feast transition, got {:?}", res),
        }

        assert_eq!(state.active_hunts[0].status, HuntStatus::Feast);
    }

    #[test]
    fn test_kill_order_authoritative() {
        let mut state = WolfState::new(WolfRole::Stray);
        let authorizer = PeerId::new();
        let target_ip = "10.0.0.5".to_string();
        let hunt_id = "manual-kill-1".to_string();

        WolfStateMachine::on_kill_order(
            &mut state,
            target_ip.clone(),
            authorizer.clone(),
            "Malicious activity".to_string(),
            hunt_id.clone(),
        )
        .unwrap();

        assert_eq!(state.active_hunts.len(), 1);
        let hunt = &state.active_hunts[0];
        assert_eq!(hunt.status, HuntStatus::Strike);
        assert_eq!(hunt.hunt_id, hunt_id);
        assert!(hunt.participants.contains(&authorizer));
    }

    #[test]
    fn test_territory_update() {
        let mut state = WolfState::new(WolfRole::Stray);
        let region = "192.168.1.0/24".to_string();

        let added = WolfStateMachine::update_territory(&mut state, region.clone()).unwrap();
        assert!(added);
        assert!(state.territories.contains(&region));

        let added_again = WolfStateMachine::update_territory(&mut state, region.clone()).unwrap();
        assert!(!added_again);
        assert_eq!(state.territories.len(), 1);
    }
}
