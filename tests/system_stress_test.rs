use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;
use tower::ServiceExt;
use wolf_web::dashboard::api::create_api_router;
use wolf_web::dashboard::state::AppState;
use wolfsec::identity::iam::{AuthenticationManager, IAMConfig};

// Helper to create app state
async fn create_test_state() -> Arc<AppState> {
    let threat_repo = Arc::new(crate::MockThreatRepository);
    let config = wolfsec::threat_detection::ThreatDetectionConfig::default();

    let auth_manager: AuthenticationManager = AuthenticationManager::new(IAMConfig::default())
        .await
        .unwrap();

    Arc::new(AppState::new(
        wolfsec::threat_detection::ThreatDetector::new(config, threat_repo),
        wolfsec::threat_detection::BehavioralAnalyzer {
            baseline_window: 100,
            deviation_threshold: 2.0,
            patterns_detected: 0,
        },
        auth_manager,
    ))
}

// Mock Repository needed for ThreatDetector
struct MockThreatRepository;
#[async_trait::async_trait]
impl wolfsec::domain::repositories::ThreatRepository for MockThreatRepository {
    async fn save(
        &self,
        _threat: &wolfsec::domain::entities::Threat,
    ) -> anyhow::Result<(), wolfsec::domain::error::DomainError> {
        Ok(())
    }
    async fn find_by_id(
        &self,
        _id: &uuid::Uuid,
    ) -> anyhow::Result<
        Option<wolfsec::domain::entities::Threat>,
        wolfsec::domain::error::DomainError,
    > {
        Ok(None)
    }
}

#[tokio::test]
async fn stress_test_concurrent_request_spikes() {
    // 1. Setup System
    let state = create_test_state().await;
    let app = create_api_router(state.clone());

    // 2. Configuration
    let concurrency_levels = vec![10, 100, 500, 1000]; // Increasing load
    let requests_per_client = 10;

    for clients in concurrency_levels {
        println!(
            "\n=== Starting Stress Test: {} Concurrent Clients ===",
            clients
        );
        let barrier = Arc::new(Barrier::new(clients));
        let start_time = Instant::now();
        let mut handles = vec![];

        for _i in 0..clients {
            let c_barrier = barrier.clone();
            let c_app = app.clone();

            handles.push(tokio::spawn(async move {
                c_barrier.wait().await; // Synchronize start

                let mut successes = 0;
                let mut failures = 0;

                for _ in 0..requests_per_client {
                    // Simulate API call (Health Check is lightweight, good for throughput)
                    let req = Request::builder()
                        .uri("/health")
                        .body(Body::empty())
                        .unwrap();

                    // We clone the router service for each request to simulate fresh connections/handling
                    let response = c_app.clone().oneshot(req).await;

                    match response {
                        Ok(res) => {
                            if res.status() == StatusCode::OK {
                                successes += 1;
                            } else {
                                failures += 1; // Rate limited or Error
                            }
                        }
                        Err(_) => failures += 1,
                    }
                }
                (successes, failures)
            }));
        }

        // Aggregate results
        let mut total_success = 0;
        let mut total_fail = 0;

        for h in handles {
            let (ok, err) = h.await.unwrap();
            total_success += ok;
            total_fail += err;
        }

        let duration = start_time.elapsed();
        let total_reqs = clients * requests_per_client;
        let rps = total_reqs as f64 / duration.as_secs_f64();

        println!("Results for {} clients:", clients);
        println!("  Time: {:.2?}", duration);
        println!("  RPS:  {:.2}", rps);
        println!("  Success: {}/{}", total_success, total_reqs);
        println!("  Failures: {}/{}", total_fail, total_reqs);

        if total_fail > 0 {
            println!("  ⚠️ System started rejecting requests (Expected behavior for stress test)");
        } else {
            println!("  ✅ System handled load flawlessly");
        }
    }
}

#[tokio::test]
async fn stress_test_payload_exhaustion() {
    println!("\n=== Starting Stress Test: Payload Exhaustion ===");
    let state = create_test_state().await;
    let app = create_api_router(state);

    // Generate huge payload (10MB)
    let huge_payload = "A".repeat(10 * 1024 * 1024);

    let start_time = Instant::now();

    // Try to send it to an endpoint (e.g. login)
    let req = Request::builder()
        .uri("/auth/login")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(huge_payload))
        .unwrap();

    let response: axum::response::Response = app.oneshot(req).await.unwrap();

    println!("Payload Size: 10MB");
    println!("Status Code: {}", response.status());
    println!("Time: {:.2?}", start_time.elapsed());

    // We expect 413 Payload Too Large or timeout, but mostly we check it doesn't crash
    assert!(
        response.status().as_u16() != 500,
        "Server crashed on large payload"
    );
}

#[tokio::test]
async fn stress_test_connection_flood() {
    println!("\n=== Starting Stress Test: Connection Flood ===");
    use wolf_net::{SwarmConfig, SwarmManager};

    // 1. Setup Victim
    let mut victim_config = SwarmConfig::default();
    victim_config.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    victim_config.max_connections = 50; // Set limit to test rejection/handling
    let mut victim_path = std::env::temp_dir();
    victim_path.push("victim_stress.key");
    victim_config.keypair_path = victim_path;

    let mut victim_swarm = SwarmManager::new(victim_config).unwrap();
    victim_swarm.start().unwrap();

    // Wait for listener to be active
    let mut victim_addr = None;
    for _ in 0..10 {
        if let Ok(listeners) = victim_swarm.get_listeners().await {
            if !listeners.is_empty() {
                victim_addr = Some(listeners[0].clone());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let victim_addr = victim_addr.expect("Victim failed to start listening");

    println!("Victim listening on: {}", victim_addr);

    // 2. Spawn Attackers
    let attacker_count = 20; // Enough to stress, not enough to kill CI
    let barrier = Arc::new(Barrier::new(attacker_count));
    let mut handles = vec![];

    for i in 0..attacker_count {
        let v_addr = victim_addr.clone();
        let c_barrier = barrier.clone();

        handles.push(tokio::spawn(async move {
            let mut attacker_config = SwarmConfig::default();
            attacker_config.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
            let mut path = std::env::temp_dir();
            path.push(format!("attacker_{}.key", i));
            attacker_config.keypair_path = path;

            let mut attacker = SwarmManager::new(attacker_config).unwrap();
            attacker.start().unwrap();

            c_barrier.wait().await; // Synchronize attack

            // Dial
            let _ = attacker.dial_addr(v_addr).await;

            // Hold connection for a bit
            tokio::time::sleep(Duration::from_secs(2)).await;
            attacker.stop().await.ok();
        }));
    }

    // 3. Wait and Verify
    for h in handles {
        h.await.unwrap();
    }

    let stats = victim_swarm.get_stats().await.unwrap();
    println!("Victim Stats: {:?}", stats);

    // Victim should be alive
    assert!(stats.metrics.connection_attempts > 0);
    victim_swarm.stop().await.unwrap();
    println!("✅ Victim survived connection flood");
}

#[tokio::test]
async fn stress_test_protocol_anomaly() {
    println!("\n=== Starting Stress Test: Protocol Anomaly Injection ===");
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use wolf_net::{SwarmConfig, SwarmManager};

    // 1. Setup Victim
    let mut victim_config = SwarmConfig::default();
    victim_config.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    let mut victim_path = std::env::temp_dir();
    victim_path.push("victim_anomaly.key");
    victim_config.keypair_path = victim_path;

    let mut victim_swarm = SwarmManager::new(victim_config).unwrap();
    victim_swarm.start().unwrap();

    // Wait for listener to be active
    let mut victim_addr = None;
    for _ in 0..10 {
        if let Ok(listeners) = victim_swarm.get_listeners().await {
            if !listeners.is_empty() {
                victim_addr = Some(listeners[0].clone());
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let victim_addr = victim_addr.expect("Victim failed to start listening");

    // Extract port from multiaddr (assuming /ip4/127.0.0.1/tcp/PORT)
    let addr_str = victim_addr.to_string();
    let parts: Vec<&str> = addr_str.split('/').collect();
    let port = parts[4].parse::<u16>().unwrap();
    let target = format!("127.0.0.1:{}", port);

    println!("Victim target: {}", target);

    // 2. Attack: Garbage Data
    println!("  Sending garbage data...");
    let mut stream = TcpStream::connect(&target).await.unwrap();
    let garbage = [0xFFu8; 1024]; // 1KB of junk
    stream.write_all(&garbage).await.unwrap();
    drop(stream);

    // 3. Attack: Partial Handshake
    println!("  Sending partial handshake...");
    let mut stream = TcpStream::connect(&target).await.unwrap();
    stream
        .write_all(b"Noise_XX_25519_ChaChaPoly_SHA256")
        .await
        .unwrap(); // Valid preamble
                   // ... but nothing else
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(stream);

    // 4. Verify Liveness
    tokio::time::sleep(Duration::from_secs(1)).await;
    let stats = victim_swarm.get_stats().await;

    if stats.is_err() {
        panic!("Victim crashed after anomaly injection!");
    } else {
        println!("Victim stats: {:?}", stats.unwrap());
        println!("✅ Victim survived protocol anomalies");
    }

    victim_swarm.stop().await.unwrap();
}
