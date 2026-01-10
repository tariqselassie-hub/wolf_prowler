use anyhow::Result;
use std::time::Duration;
use wolf_net::wolf_node::WolfNode;
use wolf_server::WolfConfig;

#[tokio::test]
async fn test_full_stack_initialization() -> Result<()> {
    // 1. Setup Configuration
    let mut config = WolfConfig::default();
    // Use random ports
    config.network.listen_port = 0;
    config.discovery.enable_mdns = false; // Disable for unit test to avoid noise

    // 2. Initialize Node (Full Stack: Net + Sec + DB)
    let node = WolfNode::new(config).await;

    assert!(node.is_ok(), "Failed to initialize WolfNode full stack");
    let mut node = node.unwrap();

    // 3. Start Node in background
    let node_handle = tokio::spawn(async move {
        // Run for a short time then shutdown
        let _ = node.run().await;
    });

    // 4. Wait for startup
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 5. Verify it's running (in a real test we'd hit the API or check metrics)
    assert!(
        !node_handle.is_finished(),
        "Node crashed immediately after startup"
    );

    // 6. Cleanup (abort task since node.run() blocks)
    node_handle.abort();

    println!("✅ Full Stack Initialization Verified");
    Ok(())
}
