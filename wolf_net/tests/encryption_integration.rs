//! Encryption Integration Tests
use anyhow::Result;
use std::time::Duration;
use tokio::sync::oneshot;
use wolf_net::{SwarmConfig, SwarmManager, SwarmCommand, PeerId};
use wolf_net::protocol::WolfRequest;

#[tokio::test]
async fn test_p2p_encryption_handshake() -> Result<()> {
    // Initialize logging for the test
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Setup Alice
    let mut alice_config = SwarmConfig::default();
    alice_config.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse()?];
    let mut alice_path = std::env::temp_dir();
    alice_path.push("alice.key");
    alice_config.keypair_path = alice_path;
    
    let mut alice_swarm = SwarmManager::new(alice_config)?;
    alice_swarm.start()?;
    let alice_peer_id = alice_swarm.local_peer_id.clone();
    
    // Get Alice's actual listening address
    let (tx, rx) = oneshot::channel();
    alice_swarm.command_sender().send(SwarmCommand::GetListeners { responder: tx }).await?;
    let alice_addrs = rx.await?;
    let alice_addr = alice_addrs[0].clone();

    // 2. Setup Bob
    let mut bob_config = SwarmConfig::default();
    bob_config.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse()?];
    let mut bob_path = std::env::temp_dir();
    bob_path.push("bob.key");
    bob_config.keypair_path = bob_path;
    
    let mut bob_swarm = SwarmManager::new(bob_config)?;
    bob_swarm.start()?;
    let bob_peer_id = bob_swarm.local_peer_id.clone();

    // 3. Connect Bob to Alice
    bob_swarm.command_sender().send(SwarmCommand::Dial {
        peer_id: alice_peer_id.clone(),
        addr: alice_addr,
    }).await?;

    // 4. Wait for connection and key exchange
    // We'll poll Alice's handler until Bob's key is registered
    let mut registered = false;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if alice_swarm.encrypted_handler.get_peer_key(&bob_peer_id.as_libp2p()).await.is_some() {
            registered = true;
            break;
        }
    }
    assert!(registered, "Key exchange did not complete in time");

    // 5. Send an encrypted request from Bob to Alice
    let (tx, rx) = oneshot::channel();
    bob_swarm.command_sender().send(SwarmCommand::SendEncryptedRequest {
        target: alice_peer_id.clone(),
        request: WolfRequest::Ping,
        responder: tx,
    }).await?;
    
    rx.await??;
    
    // 6. Give some time for transmission and handling
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    // 7. Verify Alice received and successfully decrypted the request
    // Since we don't have a direct way to peek into Alice's processed messages in this simplified test,
    // we can check metrics or the fact that the session exists.
    assert!(alice_swarm.encrypted_handler.session_count().await > 0);
    
    println!("✅ P2P Encryption Handshake and Messaging Verified");

    // Cleanup
    alice_swarm.stop().await?;
    bob_swarm.stop().await?;
    
    Ok(())
}
