//! API Methods Tests
//!
//! This module contains integration tests for the public API methods of the `SwarmManager`.
//! It verifies that the high-level API calls correctly interface with the underlying networking logic.

#[allow(unused_imports)]
use wolf_net::peer::{EntityInfo, PeerId};
use wolf_net::{SwarmConfig, SwarmManager};

/// Verifies the functionality of `SwarmManager`'s backend API methods.
///
/// This test ensures that:
/// 1. `SwarmManager` initializes and starts correctly.
/// 2. `get_stats()` returns initial empty/default statistics.
/// 3. `list_peers()` returns an empty list initially.
/// 4. `get_metrics()` reflects the initial state.
/// 5. The manager successfully establishes listeners (bindings).
#[tokio::test]
async fn test_api_backend_methods() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    println!("Step 1: Initializing SwarmManager");

    // 1. Initialize SwarmManager
    let mut config = SwarmConfig::default();
    config.keypair_path = std::env::temp_dir().join("api_methods_test.key");
    println!("Keypair path: {:?}", config.keypair_path);

    let mut swarm = SwarmManager::new(config)?;
    println!("Step 2: Starting SwarmManager");
    swarm.start()?;
    println!("Step 3: SwarmManager started");

    // 2. Test get_stats()
    let stats = swarm.get_stats().await?;
    assert_eq!(stats.connected_peers, 0);
    assert_eq!(stats.connected_peers_list.len(), 0);
    // Metrics should be default
    assert_eq!(stats.metrics.total_messages_sent, 0);

    // 3. Test list_peers()
    let peers = swarm.list_peers().await?;
    assert_eq!(peers.len(), 0);

    // 4. Test get_metrics() directly
    let metrics = swarm.get_metrics().await;
    assert_eq!(metrics.active_connections, 0);

    // 5. Test command sender availability
    // Wait for listeners to be established (since we bind to port 0)
    let mut listeners = Vec::new();
    for _ in 0..10 {
        listeners = swarm.get_listeners().await?;
        if !listeners.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    println!("Listeners: {:?}", listeners);
    assert!(
        !listeners.is_empty(),
        "Listeners list should not be empty after start"
    );

    Ok(())
}
