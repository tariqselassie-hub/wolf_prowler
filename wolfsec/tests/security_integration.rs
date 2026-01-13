//! Security Integration Tests
//!
//! Tests for WolfSecurity integration with WolfNet events

use anyhow::Result;
use wolf_net::event::{
    SecurityEvent as NetEvent, SecurityEventType as NetEventType, SecuritySeverity as NetSeverity,
};
use wolfsec::{
    SecurityEvent, SecurityEventType, SecuritySeverity, WolfSecurity, WolfSecurityConfig,
};

// Helper to convert Net types to Sec types
fn convert_severity(s: NetSeverity) -> SecuritySeverity {
    match s {
        NetSeverity::Low => SecuritySeverity::Low,
        NetSeverity::Medium => SecuritySeverity::Medium,
        NetSeverity::High => SecuritySeverity::High,
        NetSeverity::Critical => SecuritySeverity::Critical,
    }
}

// Simplified conversion for test
fn convert_event(net_event: NetEvent) -> SecurityEvent {
    let severity = convert_severity(net_event.severity);
    let event_type = match net_event.event_type {
        NetEventType::Authentication => SecurityEventType::AuthenticationFailure, // Mapping ex
        NetEventType::Authorization => SecurityEventType::AuthorizationFailure,
        NetEventType::Encryption => SecurityEventType::KeyCompromise, // Mapping ex
        NetEventType::Network => SecurityEventType::NetworkIntrusion,
        NetEventType::PolicyViolation => SecurityEventType::PolicyViolation,
        NetEventType::Other(s) => SecurityEventType::Other(s),
    };

    let mut event = SecurityEvent::new(event_type, severity, net_event.description);
    // Copy timestamp and id if possible, but new() creates fresh.
    // In real app we might want to preserve exact timestamp.

    if let Some(pid) = net_event.peer_id {
        event = event.with_peer(pid);
    }
    event
}

#[tokio::test]
async fn test_network_security_event_integration() -> Result<()> {
    // 1. Setup WolfSecurity
    let mut config = WolfSecurityConfig::default();
    config.db_path = std::env::temp_dir().join("wolfsec_integration_test.db");

    // Create and initialize
    let mut wolf_sec = WolfSecurity::create(config).await?;
    wolf_sec.initialize().await?;

    // 2. Simulate a Wolf Net Event (e.g. from Swarm)
    let peer_id = "12D3KooWSimulatedPeer".to_string();

    // Register the peer first so ThreatDetector knows about it (required for blocking)
    wolf_sec
        .threat_detector
        .register_peer(peer_id.clone(), 0.5)
        .await?;

    let net_event = NetEvent::new(
        NetEventType::PolicyViolation,
        NetSeverity::High,
        "Simulated firewall breach from integration test".to_string(),
    )
    .with_peer(peer_id);

    // 3. Convert (The Bridge)
    let sec_event = convert_event(net_event);

    // 4. Process
    wolf_sec.process_security_event(sec_event).await?;

    // 5. Verify Alert Generation
    // We check the monitor for active alerts
    let alerts = wolf_sec.monitor.get_alerts().await;

    // There should be at least one alert active now
    assert!(
        !alerts.is_empty(),
        "WolfSecurity failed to generate alert from High severity network event"
    );

    let alert = alerts.last().unwrap();
    // Verify alert properties
    assert!(alert.description.contains("Simulated firewall breach"));

    println!("✅ Security Integration Verified: Network Event -> Alert");

    Ok(())
}
