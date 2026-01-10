//! Discovery Integration Tests
//!
//! This module contains integration tests for peer discovery and management within the `SwarmManager`.
//! It verifies that nodes can discover each other and maintain correct connectivity state.

use anyhow::Result;
use std::time::Duration;
use wolf_net::{SwarmCommand, SwarmConfig, SwarmManager};

#[tokio::test]
async fn test_p2p_mdns_discovery() -> Result<()> {
    // Initialize logging
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Setup Alice
    let mut alice_config = SwarmConfig::default();
    alice_config.listen_addresses = vec!["/ip4/0.0.0.0/tcp/0".parse()?];
    alice_config.enable_mdns = true;
    let mut alice_path = std::env::temp_dir();
    alice_path.push("alice_disco.key");
    alice_config.keypair_path = alice_path;

    let mut alice_swarm = SwarmManager::new(alice_config)?;
    alice_swarm.start()?;
    let alice_peer_id = alice_swarm.local_peer_id.clone();

    // 2. Setup Bob
    let mut bob_config = SwarmConfig::default();
    bob_config.listen_addresses = vec!["/ip4/0.0.0.0/tcp/0".parse()?];
    bob_config.enable_mdns = true;
    let mut bob_path = std::env::temp_dir();
    bob_path.push("bob_disco.key");
    bob_config.keypair_path = bob_path;

    let mut bob_swarm = SwarmManager::new(bob_config)?;
    bob_swarm.start()?;
    let bob_peer_id = bob_swarm.local_peer_id.clone();

    println!("Alice: {}", alice_peer_id);
    println!("Bob: {}", bob_peer_id);

    // 3. Wait for Discovery
    // We poll both swarms until they see each other
    let mut discovered = false;
    for _ in 0..30 {
        // Wait up to 30 seconds
        tokio::time::sleep(Duration::from_secs(1)).await;

        let (tx_a, rx_a) = tokio::sync::oneshot::channel();
        alice_swarm
            .command_sender()
            .send(SwarmCommand::IsConnected {
                peer_id: bob_peer_id.clone(),
                responder: tx_a,
            })
            .await?;

        let (tx_b, rx_b) = tokio::sync::oneshot::channel();
        bob_swarm
            .command_sender()
            .send(SwarmCommand::IsConnected {
                peer_id: alice_peer_id.clone(),
                responder: tx_b,
            })
            .await?;

        let connected_a = rx_a.await?;
        let connected_b = rx_b.await?;

        if connected_a && connected_b {
            discovered = true;
            break;
        }
    }

    assert!(discovered, "Nodes failed to discover each other via mDNS");

    // 4. Cleanup
    alice_swarm.stop().await?;
    bob_swarm.stop().await?;

    println!("✅ mDNS Discovery Verified");
    Ok(())
}
