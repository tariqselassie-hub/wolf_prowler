//! Basic usage example for wolfsec
//!
//! Demonstrates the consolidated security module functionality

use anyhow::Result;
use tracing::{info, Level};
use wolfsec::{
    SecurityEvent, SecurityEventType, SecuritySeverity, WolfSecurity, WolfSecurityConfig,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("🛡️ Wolf Security Basic Usage Example");

    let config = WolfSecurityConfig::default();

    // Initialize WolfSecurity
    // Note: create() is async
    let mut wolf_security = WolfSecurity::create(config).await?;

    // Initialize components
    wolf_security.initialize().await?;

    // Display status
    let status = wolf_security.get_status().await?;
    info!("📊 Security Status:");
    info!(
        "  Network Security: {} keypairs",
        status.network_security.total_keypairs
    );
    info!("  Crypto: {} total keys", status.crypto.total_keys);
    info!(
        "  Threat Detection: {} peers",
        status.threat_detection.total_peers
    );
    info!(
        "  Authentication: {} users",
        status.authentication.total_users
    );
    info!(
        "  Key Management: {} keys",
        status.key_management.total_keys
    );
    info!("  Monitoring: {} events", status.monitoring.total_events);

    // Create a test security event
    let security_event = SecurityEvent::new(
        SecurityEventType::SuspiciousActivity,
        SecuritySeverity::Medium,
        "Test suspicious activity detected".to_string(),
    )
    .with_peer("test-peer-123".to_string())
    .with_metadata("source_ip".to_string(), "192.168.1.100".to_string());

    // Process the security event
    wolf_security.process_security_event(security_event).await?;

    info!("✅ Example completed successfully");
    Ok(())
}
