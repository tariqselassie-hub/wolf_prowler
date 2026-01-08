// Phase 3 Tests: P2P Communication Protocol
//
// Tests the Howl protocol implementation:
// - HowlMessage serialization/deserialization
// - Coordinator processing of P2P messages (HuntRequest, KillOrder, etc.)
// - Protocol flow from "network" to "coordinator"

//! Phase 3 Howl Protocol Tests
use std::time::Duration;
use tokio::time::sleep;
use wolf_net::peer::PeerId;
use wolf_net::wolf_pack::coordinator::{CoordinatorMsg, HuntCoordinator};
use wolf_net::wolf_pack::howl::{HowlMessage, HowlPayload, HowlPriority};
use wolf_net::wolf_pack::state::{HuntStatus, WolfRole};

#[test]
fn test_howl_serialization() {
    println!("\n🧪 TEST: Howl Message Serialization");

    let sender = PeerId::random();
    let payload = HowlPayload::KillOrder {
        target_ip: "10.0.0.1".to_string(),
        reason: "Malware distribution".to_string(),
        hunt_id: "hunt-123".to_string(),
    };

    let msg = HowlMessage::new(sender, HowlPriority::Alert, payload);

    // Serialize
    let bytes = msg.to_bytes().expect("Serialization failed");
    println!("✅ Serialized Alert message: {} bytes", bytes.len());

    // Deserialize
    let decoded = HowlMessage::from_bytes(&bytes).expect("Deserialization failed");

    assert_eq!(decoded.sender.to_string(), msg.sender.to_string());
    assert_eq!(decoded.priority, HowlPriority::Alert);

    if let HowlPayload::KillOrder { target_ip, .. } = decoded.payload {
        assert_eq!(target_ip, "10.0.0.1");
        println!("✅ Payload verified: KillOrder 10.0.0.1");
    } else {
        panic!("Wrong payload type decoded");
    }
}

#[tokio::test]
async fn test_coordinator_handles_p2p_messages() {
    println!("\n🧪 TEST: Coordinator P2P Message Handling");

    // Create coordinator
    let (swarm_tx, _swarm_rx) = tokio::sync::mpsc::channel(1);
    let (actor, sender, state) =
        HuntCoordinator::new(WolfRole::Beta, swarm_tx, PeerId::random(), 0, None);
    tokio::spawn(actor.run());

    // 1. Simulate receiving a HuntRequest
    println!("\n📥 Received HuntRequest (from P2P)");
    let hunt_id = "hunt-p2p-test";
    sender
        .send(CoordinatorMsg::HuntRequest {
            hunt_id: hunt_id.to_string(),
            source: PeerId::random(),
            target_ip: "192.168.1.50".to_string(),
            min_role: WolfRole::Hunter,
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(100)).await;

    // Verify hunt created
    {
        let state_read = state.read().await;
        let hunt = state_read
            .active_hunts
            .iter()
            .find(|h| h.hunt_id == hunt_id)
            .expect("Hunt not created");
        assert_eq!(hunt.status, HuntStatus::Scent);
        println!("✅ HuntRequest processed: Hunt {} created", hunt_id);
    }

    // 2. Simulate receiving a KillOrder
    println!("\n📥 Received KillOrder (from P2P)");
    sender
        .send(CoordinatorMsg::KillOrder {
            target_ip: "192.168.1.50".to_string(),
            authorizer: PeerId::random(),
            reason: "Confirmed threat".to_string(),
            hunt_id: hunt_id.to_string(),
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(100)).await;

    // Verify KillOrder execution (placeholder logs)
    // We can't verify logs easily here, but we can verify no panic/error
    println!("✅ KillOrder processed without error");

    // 3. Simulate receiving TerritoryUpdate
    println!("\n📥 Received TerritoryUpdate (from P2P)");
    let region = "10.0.0.0/24";
    sender
        .send(CoordinatorMsg::TerritoryUpdate {
            region: region.to_string(),
            owner: PeerId::random(),
            status: "Active".to_string(),
        })
        .await
        .unwrap();

    sleep(Duration::from_millis(100)).await;

    // Verify territory added
    {
        let state_read = state.read().await;
        assert!(state_read.territories.contains(&region.to_string()));
        println!("✅ TerritoryUpdate processed: {} added", region);
    }
}
