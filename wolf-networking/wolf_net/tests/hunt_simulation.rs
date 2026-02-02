//! Hunt Simulation Tests
//!
//! This module simulates the complete "Wolf Pack" Hunt Lifecycle:
//! Scent -> Stalk -> Strike -> Feast.
//!
//! It verifies the coordination state machine and consensus mechanisms.

use std::time::Duration;
use tokio::time::sleep;
use wolf_net::peer::PeerId;
use wolf_net::wolf_pack::coordinator::{CoordinatorMsg, HuntCoordinator};
use wolf_net::wolf_pack::state::{HuntStatus, WolfRole};

/// Simulates a full end-to-end hunt lifecycle.
///
/// Workflow:
/// 1. **Setup**: Initialize a `HuntCoordinator` as a Beta (Authority).
/// 2. **Scent**: Authority issues a `HuntRequest`, creating a new hunt in `Scent` status.
/// 3. **Stalk**: A Scout reports a `WarningHowl`, advancing the hunt to `Stalk`.
/// 4. **Strike**: Hunters report confirmation (`HuntReport`). The system waits for consensus (66%).
/// 5. **Feast**: Once consensus is reached, the hunt transitions to `Feast` (successful conclusion).
#[tokio::test]
async fn test_full_scent_to_strike_simulation() {
    // 1. Setup Coordinator
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(100);
    let local_id = PeerId::new();
    let (coordinator, coord_tx, state) = HuntCoordinator::new(
        WolfRole::Beta, // Local node is a Beta (Authority)
        swarm_tx,
        local_id.clone(),
        100,
        None,
    );

    tokio::spawn(async move {
        coordinator.run().await;
    });

    let target_ip = "1.2.3.4".to_string();
    let hunt_id = "sim-hunt-001".to_string();
    let authority_id = PeerId::new();
    let scout_id = PeerId::new();

    // We need enough hunters to reach 66% consensus.
    // Participants: Auth(1) + Scout(1) + Hunters(4) = 6 total.
    // Confirmations needed: 4 (4/6 = 66.6%)
    let hunters: Vec<PeerId> = (0..4).map(|_| PeerId::new()).collect();

    // PHASE 1: SCENT - Authority requests a hunt
    coord_tx
        .send(CoordinatorMsg::HuntRequest {
            hunt_id: hunt_id.clone(),
            source: authority_id.clone(),
            target_ip: target_ip.clone(),
            min_role: WolfRole::Hunter,
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(50)).await;
    {
        let s = state.read().await;
        let hunt = s
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_id)
            .expect("Hunt not found");
        assert_eq!(hunt.status, HuntStatus::Scent);
    }

    // PHASE 2: STALK - Scout detects activity and issues WarningHowl
    coord_tx
        .send(CoordinatorMsg::WarningHowl {
            source: scout_id.clone(),
            target_ip: target_ip.clone(),
            evidence: "Observed suspicious traffic".to_string(),
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(50)).await;
    {
        let s = state.read().await;
        let hunt = s
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_id)
            .expect("Hunt not found");
        assert_eq!(hunt.status, HuntStatus::Stalk);
        assert!(hunt.participants.contains(&scout_id));
    }

    // PHASE 3: STRIKE - Hunters report and reach consensus
    for (i, hunter_id) in hunters.iter().enumerate() {
        coord_tx
            .send(CoordinatorMsg::HuntReport {
                hunt_id: hunt_id.clone(),
                hunter: hunter_id.clone(),
                confirmed: true,
            })
            .await
            .unwrap();

        sleep(Duration::from_millis(20)).await;

        let s = state.read().await;
        let hunt = s
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_id)
            .unwrap();

        if i < 3 {
            // With 3 confirmations out of 6 participants (50%), should still be Stalk
            assert_eq!(
                hunt.status,
                HuntStatus::Stalk,
                "Should not transition yet at {} reports",
                i + 1
            );
        } else {
            // With 4 confirmations out of 6 participants (66.6%), should transition
            // Note: Coordinator immediately moves Strike -> Feast
            assert_eq!(
                hunt.status,
                HuntStatus::Feast,
                "Should have transitioned to Feast at 4 reports"
            );
        }
    }

    // FINAL VERIFICATION
    {
        let s = state.read().await;
        let hunt = s
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_id)
            .unwrap();
        assert_eq!(hunt.status, HuntStatus::Feast);
        // Participants: Authority, Scout, 4 Hunters
        assert_eq!(hunt.participants.len(), 6);
        println!("✅ Full Hunt Lifecycle Simulation Successful: Scent -> Stalk -> Strike -> Feast");
    }
}
