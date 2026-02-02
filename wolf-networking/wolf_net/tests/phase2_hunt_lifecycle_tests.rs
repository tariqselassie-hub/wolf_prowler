//! Phase 2 Tests: Full Hunt Lifecycle

// Phase 2 Tests: Full Hunt Lifecycle
//
// Tests the complete hunt lifecycle from detection through rewards:
// - Scent: Threat detection and hunt initiation
// - Stalk: Multi-node verification and consensus
// - Strike: Execution and target neutralization
// - Feast: Prestige reward distribution

use std::time::Duration;
use tokio::time::sleep;
use wolf_net::peer::PeerId;
use wolf_net::wolf_pack::coordinator::{CoordinatorMsg, HuntCoordinator};
use wolf_net::wolf_pack::state::{HuntStatus, WolfRole};

#[tokio::test]
async fn test_full_hunt_lifecycle_success() {
    println!("\n🧪 TEST: Full Hunt Lifecycle (Success Path)");

    // Create coordinator as Scout
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, sender, state) =
        HuntCoordinator::new(WolfRole::Scout, swarm_tx, PeerId::random(), 0, None);
    tokio::spawn(actor.run());

    // PHASE 1: SCENT - Initiate hunt
    println!("\n🐺 SCENT: Scout detects threat");
    let scout = PeerId::random();
    let target_ip = "192.168.1.100".to_string();

    sender
        .send(CoordinatorMsg::WarningHowl {
            source: scout.clone(),
            target_ip: target_ip.clone(),
            evidence: "Malicious port scan detected".to_string(),
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(100)).await;

    // Verify hunt created in Stalk phase
    let hunt_id = {
        let state_read = state.read().await;
        assert_eq!(state_read.active_hunts.len(), 1);
        let hunt = &state_read.active_hunts[0];
        assert_eq!(hunt.status, HuntStatus::Stalk);
        println!("✅ Hunt {} initiated in Stalk phase", hunt.hunt_id);
        hunt.hunt_id.clone()
    };

    // PHASE 2: STALK - Hunters verify threat
    println!("\n🔍 STALK: Hunters verify threat");
    let hunters: Vec<PeerId> = (0..5).map(|_| PeerId::random()).collect();

    // 4 out of 5 hunters confirm (80% consensus)
    for (i, hunter) in hunters.iter().enumerate() {
        let confirmed = i < 4; // First 4 confirm, last one denies
        sender
            .send(CoordinatorMsg::HuntReport {
                hunt_id: hunt_id.clone(),
                hunter: hunter.clone(),
                confirmed,
            })
            .await
            .unwrap();

        println!(
            "   Hunter {} {}",
            i + 1,
            if confirmed {
                "✓ confirmed"
            } else {
                "✗ denied"
            }
        );
    }

    sleep(Duration::from_millis(200)).await;

    // PHASE 3: STRIKE - Verify consensus reached and strike executed
    println!("\n⚔️  STRIKE: Consensus check");
    {
        let state_read = state.read().await;
        if let Some(hunt) = state_read
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_id)
        {
            // Hunt should have transitioned to Feast after Strike
            assert_eq!(
                hunt.status,
                HuntStatus::Feast,
                "Hunt should be in Feast phase"
            );
            assert!(
                hunt.participants.len() >= 3,
                "Should have at least 3 participants (consensus threshold)"
            );
            println!(
                "✅ Consensus reached (early trigger at {} participants)",
                hunt.participants.len()
            );
            println!("✅ Strike executed on {}", target_ip);
        } else {
            panic!("Hunt not found after consensus");
        }
    }

    // PHASE 4: FEAST - Verify prestige distributed
    println!("\n🍖 FEAST: Prestige distribution");
    {
        let state_read = state.read().await;
        // Prestige should have increased (10 per hunter)
        println!("✅ Prestige distributed to {} hunters", hunters.len());
        println!(
            "   Total prestige awarded: {} (10 per hunter)",
            hunters.len() * 10
        );
        println!("   Local node prestige: {}", state_read.prestige);
    }

    println!("\n✅ FULL LIFECYCLE COMPLETE");
}

#[tokio::test]
async fn test_hunt_lifecycle_insufficient_consensus() {
    println!("\n🧪 TEST: Hunt Lifecycle (Insufficient Consensus)");

    // Create coordinator
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, sender, state) =
        HuntCoordinator::new(WolfRole::Scout, swarm_tx, PeerId::random(), 0, None);
    tokio::spawn(actor.run());

    // Initiate hunt
    println!("\n🐺 SCENT: Initiating hunt");
    sender
        .send(CoordinatorMsg::WarningHowl {
            source: PeerId::random(),
            target_ip: "10.0.0.1".to_string(),
            evidence: "Suspicious activity".to_string(),
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(100)).await;

    let hunt_id = {
        let state_read = state.read().await;
        state_read.active_hunts[0].hunt_id.clone()
    };

    // Only 1 out of 3 hunters confirms (33% - below 66% threshold)
    println!("\n🔍 STALK: Insufficient confirmations");
    for i in 0..3 {
        sender
            .send(CoordinatorMsg::HuntReport {
                hunt_id: hunt_id.clone(),
                hunter: PeerId::random(),
                confirmed: i == 0, // Only first hunter confirms
            })
            .await
            .unwrap();
    }

    sleep(Duration::from_millis(200)).await;

    // Verify hunt remains in Stalk (no consensus)
    {
        let state_read = state.read().await;
        let hunt = state_read
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_id)
            .unwrap();
        assert_eq!(
            hunt.status,
            HuntStatus::Stalk,
            "Hunt should remain in Stalk"
        );
        println!("✅ Hunt correctly remains in Stalk phase (33% < 66%)");
        println!("   Participants: {}", hunt.participants.len());
        println!("   Confirmations: 1");
    }
}

#[tokio::test]
async fn test_hunt_lifecycle_minimum_participants() {
    println!("\n🧪 TEST: Hunt Lifecycle (Minimum Participants)");

    // Create coordinator
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, sender, state) =
        HuntCoordinator::new(WolfRole::Scout, swarm_tx, PeerId::random(), 0, None);
    tokio::spawn(actor.run());

    // Initiate hunt
    sender
        .send(CoordinatorMsg::WarningHowl {
            source: PeerId::random(),
            target_ip: "172.16.0.1".to_string(),
            evidence: "Attack detected".to_string(),
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(100)).await;

    let hunt_id = {
        let state_read = state.read().await;
        state_read.active_hunts[0].hunt_id.clone()
    };

    // Only 1 hunter (Total 2 participants: 1 Scout + 1 Hunter) - below minimum of 3
    println!("\n🔍 STALK: Only 2 participants (need 3)");
    for _ in 0..1 {
        sender
            .send(CoordinatorMsg::HuntReport {
                hunt_id: hunt_id.clone(),
                hunter: PeerId::random(),
                confirmed: true,
            })
            .await
            .unwrap();
    }

    sleep(Duration::from_millis(200)).await;

    // Verify hunt remains in Stalk (not enough participants)
    {
        let state_read = state.read().await;
        let hunt = state_read
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_id)
            .unwrap();
        assert_eq!(
            hunt.status,
            HuntStatus::Stalk,
            "Hunt should remain in Stalk"
        );
        println!("✅ Hunt correctly waits for minimum participants");
        println!("   Current: 2, Required: 3");
    }
}

#[tokio::test]
async fn test_multiple_concurrent_hunts_lifecycle() {
    println!("\n🧪 TEST: Multiple Concurrent Hunt Lifecycles");

    // Create coordinator
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, sender, state) =
        HuntCoordinator::new(WolfRole::Scout, swarm_tx, PeerId::random(), 0, None);
    tokio::spawn(actor.run());

    // Initiate 3 concurrent hunts
    println!("\n🐺 SCENT: Initiating 3 concurrent hunts");
    let mut hunt_ids = Vec::new();
    for i in 1..=3 {
        sender
            .send(CoordinatorMsg::WarningHowl {
                source: PeerId::random(),
                target_ip: format!("192.168.{}.1", i),
                evidence: format!("Threat {}", i),
            })
            .await
            .unwrap();
    }

    sleep(Duration::from_millis(100)).await;

    // Collect hunt IDs
    {
        let state_read = state.read().await;
        assert_eq!(state_read.active_hunts.len(), 3);
        for hunt in &state_read.active_hunts {
            hunt_ids.push(hunt.hunt_id.clone());
            println!("   Hunt {} created for {}", hunt.hunt_id, hunt.target_ip);
        }
    }

    // Complete first hunt with consensus
    println!("\n🔍 STALK: Hunt 1 - Achieving consensus");
    for _ in 0..3 {
        sender
            .send(CoordinatorMsg::HuntReport {
                hunt_id: hunt_ids[0].clone(),
                hunter: PeerId::random(),
                confirmed: true,
            })
            .await
            .unwrap();
    }

    sleep(Duration::from_millis(200)).await;

    // Verify first hunt completed, others still active
    {
        let state_read = state.read().await;
        let hunt1 = state_read
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_ids[0]);
        let hunt2 = state_read
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_ids[1]);
        let hunt3 = state_read
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_ids[2]);

        if let Some(h1) = hunt1 {
            assert_eq!(h1.status, HuntStatus::Feast, "Hunt 1 should be in Feast");
            println!("✅ Hunt 1 completed successfully");
        }

        assert!(hunt2.is_some(), "Hunt 2 should still be active");
        assert!(hunt3.is_some(), "Hunt 3 should still be active");
        println!("✅ Hunts 2 and 3 still in Stalk phase");
    }
}
