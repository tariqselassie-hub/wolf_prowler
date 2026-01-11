//! Integration tests for dashboard data flow.

use std::sync::Arc;
use wolf_web::dashboard::api::server_fns::{get_fullstack_stats, get_wolfpack_data};
use wolf_web::globals;

// Use a specific test function to avoid collisions
#[tokio::test]
async fn test_dashboard_data_flow() {
    // 1. Setup WolfSec Global
    // We can't easily run a full WolfSecurity instance without a DB,
    // but the global is an Option, so we can test the "None" case or a mocked case if we had mocks.
    // For now, let's test that it handles the "None" case gracefully (simulating startup).

    // Ensure globals are None initially
    {
        let mut sec = globals::SECURITY_ENGINE.lock().await;
        *sec = None;
    }

    let stats_result = get_fullstack_stats().await;
    assert!(
        stats_result.is_ok(),
        "Should return stats even if components are offline"
    );
    let stats = stats_result.unwrap();
    assert_eq!(
        stats.threat_level, "UNKNOWN",
        "Threat level should be UNKNOWN when security engine is offline"
    );

    // 2. Setup WolfNet Global
    // Initialize a SwarmManager for testing
    let config = wolf_net::SwarmConfig::default();
    // SwarmManager::new starts background tasks, so we need to be careful.
    // Use a temp path for keypair to avoid messing with user data
    let mut test_config = config.clone();
    test_config.keypair_path = std::env::temp_dir().join("wolf_test_swarm.key");

    // We need to initialize the library first mainly for logging, but not strictly required for this test
    let _ = wolf_net::init();

    match wolf_net::SwarmManager::new(test_config) {
        Ok(swarm) => {
            let swarm_arc = Arc::new(swarm);

            // Set the global
            {
                let mut glob = globals::SWARM_MANAGER.lock().await;
                *glob = Some(swarm_arc.clone());
            }

            // Test get_wolfpack_data
            let data_result = get_wolfpack_data().await;
            assert!(data_result.is_ok(), "Should return wolfpack data");
            let data = data_result.unwrap();

            // Verify data matches the initialized swarm (it won't have peers, but should have specific initial state)
            assert_eq!(
                data.node_id,
                swarm_arc.local_peer_id.to_string(),
                "Node ID should match swarm"
            );
            assert_eq!(data.role, "Stray", "Initial role should be Stray"); // Logic in SwarmManager/HuntCoordinator

            // Clean up global
            {
                let mut glob = globals::SWARM_MANAGER.lock().await;
                *glob = None;
            }
        }
        Err(e) => {
            // If we can't create a swarm (e.g. port binding issue in CI), we skip this part but warn
            eprintln!(
                "Skipping SwarmManager test due to initialization failure: {}",
                e
            );
        }
    }
}
