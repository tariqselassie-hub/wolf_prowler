//! Integration tests for WolfNet Election
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use wolf_net::peer::PeerId;
use wolf_net::swarm::SwarmCommand;
use wolf_net::wolf_pack::coordinator::{CoordinatorMsg, HuntCoordinator};
use wolf_net::wolf_pack::howl::{HowlMessage, HowlPayload};
use wolf_net::wolf_pack::state::WolfRole;

#[tokio::test]
async fn test_3_node_election_integration() {
    let mut nodes = HashMap::new();
    let mut swarm_receivers = HashMap::new();
    let mut states = HashMap::new();

    // Create 3 unique Peer IDs
    let peer_ids = vec![PeerId::new(), PeerId::new(), PeerId::new()];
    // Node 0 has highest prestige to ensure it wins the election
    let prestiges = vec![100, 50, 10];

    // 1. Initialize 3 HuntCoordinator instances
    for i in 0..3 {
        let (swarm_tx, swarm_rx) = mpsc::channel(100);
        let (coordinator, coord_tx, state) = HuntCoordinator::new(
            WolfRole::Stray,
            swarm_tx,
            peer_ids[i].clone(),
            prestiges[i],
            None,
        );

        nodes.insert(peer_ids[i].clone(), coord_tx);
        swarm_receivers.insert(peer_ids[i].clone(), swarm_rx);
        states.insert(peer_ids[i].clone(), state);

        // Start the coordinator actor loop
        tokio::spawn(async move {
            coordinator.run().await;
        });
    }

    // 2. Mock Network Router
    // This loop intercepts SwarmCommand::Broadcast from one node and
    // routes it as a CoordinatorMsg to the other two nodes.
    let nodes_clone = nodes.clone();
    for id in peer_ids.clone() {
        let mut rx = swarm_receivers.remove(&id).unwrap();
        let nodes_inner = nodes_clone.clone();
        let current_id = id.clone();

        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                if let SwarmCommand::Broadcast(bytes) = cmd {
                    let howl = HowlMessage::from_bytes(&bytes).expect("Failed to decode Howl");
                    for (target_id, target_tx) in &nodes_inner {
                        if *target_id != current_id {
                            let msg = match &howl.payload {
                                HowlPayload::ElectionRequest {
                                    term,
                                    candidate_id,
                                    prestige,
                                    ..
                                } => CoordinatorMsg::ElectionRequest {
                                    term: *term,
                                    candidate_id: candidate_id.clone(),
                                    prestige: *prestige,
                                },
                                HowlPayload::ElectionVote {
                                    term,
                                    voter_id,
                                    granted,
                                } => CoordinatorMsg::ElectionVote {
                                    term: *term,
                                    voter_id: voter_id.clone(),
                                    granted: *granted,
                                },
                                HowlPayload::AlphaHeartbeat { term, leader_id } => {
                                    CoordinatorMsg::AlphaHeartbeat {
                                        term: *term,
                                        leader_id: leader_id.clone(),
                                    }
                                }
                                _ => continue,
                            };
                            let _ = target_tx.send(msg).await;
                        }
                    }
                }
            }
        });
    }

    // 3. Trigger election on Node 0
    let node0_tx = nodes.get(&peer_ids[0]).unwrap();
    node0_tx
        .send(CoordinatorMsg::ElectionRequest {
            term: 1,
            candidate_id: peer_ids[0].clone(),
            prestige: prestiges[0],
        })
        .await
        .expect("Failed to trigger election");

    // 4. Wait for consensus to be reached
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 5. Verify that other nodes recognize Node 0 as the leader
    let state1 = states.get(&peer_ids[1]).unwrap().read().await;
    assert_eq!(
        state1.leader_id,
        Some(peer_ids[0].to_string()),
        "Node 1 should recognize Node 0 as leader"
    );

    let state2 = states.get(&peer_ids[2]).unwrap().read().await;
    assert_eq!(
        state2.leader_id,
        Some(peer_ids[0].to_string()),
        "Node 2 should recognize Node 0 as leader"
    );
}
