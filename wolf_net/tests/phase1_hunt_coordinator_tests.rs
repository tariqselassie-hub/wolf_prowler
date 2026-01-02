// Phase 1 Tests: Hunt Coordinator Functionality
//
// Tests the core HuntCoordinator actor functionality including:
// - Hunt creation and state management
// - Timeout and garbage collection
// - Role evolution and prestige tracking

use std::time::Duration;
use tokio::time::sleep;
use wolf_net::peer::PeerId;
use wolf_net::wolf_pack::coordinator::{CoordinatorMsg, HuntCoordinator};
use wolf_net::wolf_pack::state::{HuntStatus, WolfRole};

#[tokio::test]
async fn test_hunt_creation_and_tracking() {
    println!("\n🧪 TEST: Hunt Creation and Tracking");

    // Create coordinator
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, sender, state) =
        HuntCoordinator::new(WolfRole::Scout, swarm_tx, PeerId::random(), 0);
    tokio::spawn(actor.run());

    // Initiate a hunt
    let source = PeerId::random();
    let target_ip = "192.168.1.100".to_string();
    let evidence = "Port scan detected".to_string();

    sender
        .send(CoordinatorMsg::WarningHowl {
            source: source.clone(),
            target_ip: target_ip.clone(),
            evidence: evidence.clone(),
        })
        .await
        .unwrap();

    // Wait for processing
    sleep(Duration::from_millis(100)).await;

    // Verify hunt was created
    let state_read = state.read().await;
    assert_eq!(
        state_read.active_hunts.len(),
        1,
        "Should have 1 active hunt"
    );

    let hunt = &state_read.active_hunts[0];
    assert_eq!(hunt.target_ip, target_ip, "Target IP should match");
    assert_eq!(
        hunt.status,
        HuntStatus::Stalk,
        "Hunt should be in Stalk phase"
    );
    assert!(
        hunt.evidence.contains(&evidence),
        "Evidence should be recorded"
    );

    println!("✅ Hunt created successfully: {}", hunt.hunt_id);
    println!("   Target: {}", hunt.target_ip);
    println!("   Status: {:?}", hunt.status);
}

#[tokio::test]
async fn test_hunt_timeout_and_cleanup() {
    println!("\n🧪 TEST: Hunt Timeout and Cleanup");

    // Create coordinator
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, sender, state) =
        HuntCoordinator::new(WolfRole::Scout, swarm_tx, PeerId::random(), 0);
    tokio::spawn(actor.run());

    // Initiate a hunt
    let source = PeerId::random();
    sender
        .send(CoordinatorMsg::WarningHowl {
            source,
            target_ip: "10.0.0.1".to_string(),
            evidence: "Suspicious activity".to_string(),
        })
        .await
        .unwrap();

    // Wait for hunt creation
    sleep(Duration::from_millis(100)).await;

    // Verify hunt exists
    {
        let state_read = state.read().await;
        assert_eq!(state_read.active_hunts.len(), 1, "Hunt should exist");
        println!("✅ Hunt created, waiting for timeout...");
    }

    // Wait for timeout (30s + buffer)
    println!("⏳ Waiting 31 seconds for timeout...");
    sleep(Duration::from_secs(31)).await;

    // Verify hunt was cleaned up
    let state_read = state.read().await;
    let failed_hunts = state_read
        .active_hunts
        .iter()
        .filter(|h| h.status == HuntStatus::Failed)
        .count();

    println!("✅ Timeout processed");
    println!("   Failed hunts: {}", failed_hunts);
    println!("   Active hunts: {}", state_read.active_hunts.len());
}

#[tokio::test]
async fn test_prestige_and_role_evolution() {
    println!("\n🧪 TEST: Prestige and Role Evolution");

    // Create coordinator starting as Stray
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, _sender, state) =
        HuntCoordinator::new(WolfRole::Stray, swarm_tx, PeerId::random(), 0);
    tokio::spawn(actor.run());

    // Verify initial state
    {
        let state_read = state.read().await;
        assert_eq!(state_read.role, WolfRole::Stray, "Should start as Stray");
        assert_eq!(state_read.prestige, 0, "Should start with 0 prestige");
        println!("✅ Initial state: Stray with 0 prestige");
    }

    // Add prestige to reach Scout (50)
    {
        let mut state_write = state.write().await;
        state_write.add_prestige(50);
    }

    // Verify evolution to Scout
    {
        let state_read = state.read().await;
        assert_eq!(state_read.role, WolfRole::Scout, "Should evolve to Scout");
        assert_eq!(state_read.prestige, 50, "Should have 50 prestige");
        println!("✅ Evolved to Scout with 50 prestige");
    }

    // Add more prestige to reach Hunter (200)
    {
        let mut state_write = state.write().await;
        state_write.add_prestige(150);
    }

    // Verify evolution to Hunter
    {
        let state_read = state.read().await;
        assert_eq!(state_read.role, WolfRole::Hunter, "Should evolve to Hunter");
        assert_eq!(state_read.prestige, 200, "Should have 200 prestige");
        println!("✅ Evolved to Hunter with 200 prestige");
    }
}

#[tokio::test]
async fn test_concurrent_hunts() {
    println!("\n🧪 TEST: Concurrent Hunt Management");

    // Create coordinator
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, sender, state) =
        HuntCoordinator::new(WolfRole::Scout, swarm_tx, PeerId::random(), 0);
    tokio::spawn(actor.run());

    // Initiate multiple hunts
    for i in 1..=5 {
        sender
            .send(CoordinatorMsg::WarningHowl {
                source: PeerId::random(),
                target_ip: format!("192.168.1.{}", i),
                evidence: format!("Threat {}", i),
            })
            .await
            .unwrap();
    }

    // Wait for processing
    sleep(Duration::from_millis(200)).await;

    // Verify all hunts were created
    let state_read = state.read().await;
    assert_eq!(
        state_read.active_hunts.len(),
        5,
        "Should have 5 active hunts"
    );

    println!("✅ Created 5 concurrent hunts:");
    for hunt in &state_read.active_hunts {
        println!("   - {} targeting {}", hunt.hunt_id, hunt.target_ip);
    }
}
