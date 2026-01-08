//! Peer Tracking Integration Tests
use wolf_net::peer::{EntityStatus, PeerId};
use wolf_net::swarm::{SwarmConfig, SwarmManager};
use std::time::Duration;

#[tokio::test]
async fn test_peer_tracking_lifecycle() {
    // Initialize two swarm managers
    let mut config1 = SwarmConfig::default();
    config1.keypair_path = "target/test_peer_tracking_1.key".into();
    config1.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    let mut swarm1 = SwarmManager::new(config1).unwrap();
    swarm1.start().unwrap();

    let mut config2 = SwarmConfig::default();
    config2.keypair_path = "target/test_peer_tracking_2.key".into();
    config2.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    let mut swarm2 = SwarmManager::new(config2).unwrap();
    swarm2.start().unwrap();

    let peer2_id = swarm2.local_peer_id.clone();

    // Get swarm2 address
    let mut listeners = Vec::new();
    for _ in 0..50 {
        if let Ok(l) = swarm2.get_listeners().await {
            if !l.is_empty() {
                listeners = l;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!listeners.is_empty(), "Swarm 2 failed to bind listeners");
    let addr2 = listeners[0].clone();

    // Swarm1 dials Swarm2
    swarm1.dial(peer2_id.clone(), addr2).await.unwrap();

    // Wait for connection to be reflected in registry
    let mut online = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(Some(info)) = swarm1.get_peer_info(peer2_id.clone()).await {
            if info.status == EntityStatus::Online {
                online = true;
                break;
            }
        }
    }
    assert!(online, "Peer 2 should be online in Swarm 1 registry");

    // Check identified info (protocol version, etc)
    let mut identified = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(Some(info)) = swarm1.get_peer_info(peer2_id.clone()).await {
            if info.protocol_version.is_some() {
                identified = true;
                break;
            }
        }
    }
    assert!(identified, "Peer 2 should have protocol version in Swarm 1 registry");

    // List peers
    let peers = swarm1.list_peers().await.unwrap();
    assert!(peers.iter().any(|p| p.entity_id.peer_id == peer2_id));

    // Shutdown swarm2 and check status change in swarm1
    swarm2.stop().await.unwrap();

    let mut offline = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(Some(info)) = swarm1.get_peer_info(peer2_id.clone()).await {
            if info.status == EntityStatus::Offline {
                offline = true;
                break;
            }
        }
    }
    assert!(offline, "Peer 2 should be offline in Swarm 1 registry after shutdown");

    swarm1.stop().await.unwrap();
}
