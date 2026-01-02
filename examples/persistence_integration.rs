//! Example integration of persistence layer with wolf_server
//!
//! This example demonstrates how to:
//! - Initialize the persistence manager
//! - Save peer data
//! - Store security events
//! - Query historical data

use anyhow::Result;
use std::sync::Arc;
use wolf_prowler::persistence::{
    DbAuditLog, DbPeer, DbSecurityAlert, DbSecurityEvent, DbSystemLog, PersistenceManager,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("info").init();

    println!("🐺 Wolf Prowler - Persistence Integration Example\n");

    // 1. Initialize Persistence Manager
    println!("📦 Initializing persistence manager...");
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler".to_string()
    });

    let persistence = Arc::new(PersistenceManager::new(&db_url).await?);
    println!("✓ Persistence manager initialized\n");

    // 2. Health Check
    println!("🏥 Checking database health...");
    if persistence.health_check().await? {
        println!("✓ Database is healthy\n");
    } else {
        println!("❌ Database health check failed\n");
        return Ok(());
    }

    // 3. Save a peer
    println!("👥 Saving peer data...");
    let peer = DbPeer {
        peer_id: "12D3KooWExample123".to_string(),
        service_type: "wolf_server".to_string(),
        system_type: "linux".to_string(),
        version: Some("2.0.0".to_string()),
        status: "online".to_string(),
        trust_score: Some(0.85),
        first_seen: Some(chrono::Utc::now()),
        last_seen: Some(chrono::Utc::now()),
        protocol_version: Some("1.0".to_string()),
        agent_version: Some("wolf/2.0.0".to_string()),
        capabilities: Some(serde_json::json!(["encryption", "routing", "discovery"])),
        metadata: Some(serde_json::json!({"node_name": "CAP", "region": "us-east"})),
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
    };

    persistence.save_peer(&peer).await?;
    println!("✓ Peer saved: {}\n", peer.peer_id);

    // 4. Save a security event
    println!("🔒 Saving security event...");
    let event = DbSecurityEvent {
        id: None,
        event_id: None,
        timestamp: None,
        event_type: "suspicious_activity".to_string(),
        severity: "medium".to_string(),
        source: Some("intrusion_detection".to_string()),
        peer_id: Some(peer.peer_id.clone()),
        description: "Multiple failed connection attempts detected".to_string(),
        details: serde_json::json!({
            "attempts": 5,
            "time_window": "5 minutes",
            "source_ip": "192.168.1.100"
        }),
        resolved: Some(false),
        resolved_at: None,
        resolved_by: None,
    };

    persistence.save_security_event(&event).await?;
    println!("✓ Security event saved\n");

    // 5. Save a security alert
    println!("🚨 Saving security alert...");
    let alert = DbSecurityAlert {
        id: None,
        alert_id: None,
        timestamp: None,
        severity: "high".to_string(),
        status: "active".to_string(),
        title: "Potential DDoS Attack".to_string(),
        message: Some("High volume of requests from single source".to_string()),
        category: "network_attack".to_string(),
        source: "traffic_analyzer".to_string(),
        escalation_level: Some(2),
        acknowledged_by: None,
        acknowledged_at: None,
        resolved_by: None,
        resolved_at: None,
        metadata: serde_json::json!({
            "request_count": 10000,
            "time_window": "1 minute",
            "source_ip": "10.0.0.50"
        }),
    };

    persistence.save_security_alert(&alert).await?;
    println!("✓ Security alert saved\n");

    // 6. Save an audit log
    println!("📝 Saving audit log...");
    let audit_log = DbAuditLog {
        id: None,
        timestamp: None,
        action: "peer_connected".to_string(),
        actor: Some("system".to_string()),
        resource: Some(peer.peer_id.clone()),
        resource_type: Some("peer".to_string()),
        result: "success".to_string(),
        details: serde_json::json!({
            "connection_type": "inbound",
            "protocol": "tcp"
        }),
        ip_address: None,
        user_agent: None,
    };

    persistence.save_audit_log(&audit_log).await?;
    println!("✓ Audit log saved\n");

    // 7. Save a system log
    println!("📋 Saving system log...");
    let system_log = DbSystemLog::new(
        "info".to_string(),
        "Wolf server started successfully".to_string(),
        Some("wolf_server".to_string()),
    );

    persistence.save_system_log(&system_log).await?;
    println!("✓ System log saved\n");

    // 8. Query data
    println!("🔍 Querying saved data...\n");

    // Get active peers
    let active_peers = persistence.get_active_peers().await?;
    println!("📊 Active Peers: {}", active_peers.len());
    for peer in &active_peers {
        println!("  - {} ({})", peer.peer_id, peer.status);
    }
    println!();

    // Get recent alerts
    let recent_alerts = persistence.get_recent_alerts(10).await?;
    println!("🚨 Recent Alerts: {}", recent_alerts.len());
    for alert in &recent_alerts {
        println!("  - [{}] {}", alert.severity, alert.title);
    }
    println!();

    // Get recent logs
    let recent_logs = persistence.get_recent_logs(10).await?;
    println!("📋 Recent Logs: {}", recent_logs.len());
    for log in &recent_logs {
        println!("  - [{}] {}", log.level, log.message);
    }
    println!();

    // 9. Configuration operations
    println!("⚙️ Testing configuration operations...");

    persistence
        .set_config(
            "test.setting",
            serde_json::json!("test_value"),
            Some("example_script"),
        )
        .await?;

    if let Some(value) = persistence.get_config("test.setting").await? {
        println!("✓ Config retrieved: {:?}\n", value);
    }

    println!("✅ All persistence operations completed successfully!");
    println!("\n💡 Next steps:");
    println!("  1. Integrate persistence into wolf_server main.rs");
    println!("  2. Add periodic metrics collection");
    println!("  3. Implement API endpoints for historical queries");
    println!("  4. Set up automated backups");

    Ok(())
}
