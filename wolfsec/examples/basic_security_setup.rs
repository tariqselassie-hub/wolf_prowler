//! Basic Security Setup Example
//!
//! Demonstrates how to initialize and configure the core security components.

use anyhow::Result;
use wolfsec::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🐺 Wolf Prowler Security - Basic Setup Example\n");

    // 1. Initialize Network Security
    println!("1️⃣ Initializing Network Security...");
    let security_config = SecurityConfig {
        default_security_level: HIGH_SECURITY,
        max_sessions_per_peer: 10,
        session_cleanup_interval: 3600,
        token_ttl_hours: 24,
    };

    let security_manager = NetworkSecurityManager::new(security_config).await?;
    println!("   ✅ Network Security Manager initialized\n");

    // 2. Set up Identity Management
    println!("2️⃣ Setting up Identity Management...");
    let identity_config = IdentityConfig::default();
    let identity_manager = IdentityManager::new(identity_config).await?;
    println!("   ✅ Identity Manager initialized\n");

    // 3. Initialize Authentication
    println!("3️⃣ Initializing Authentication...");
    let auth_manager = AuthManager::new(Default::default()).await?;

    // Create a test user
    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        email: "admin@wolfprowler.local".to_string(),
        roles: vec![Role {
            id: "admin".to_string(),
            name: "Administrator".to_string(),
            permissions: vec![
                Permission {
                    id: "security:read".to_string(),
                    resource: "security".to_string(),
                    action: "read".to_string(),
                },
                Permission {
                    id: "security:write".to_string(),
                    resource: "security".to_string(),
                    action: "write".to_string(),
                },
            ],
        }],
        created_at: chrono::Utc::now(),
        last_login: None,
        mfa_enabled: false,
        metadata: Default::default(),
    };

    println!("   ✅ Created user: {}", user.username);
    println!(
        "   ✅ Roles: {:?}",
        user.roles.iter().map(|r| &r.name).collect::<Vec<_>>()
    );
    println!();

    // 4. Display Security Configuration
    println!("4️⃣ Security Configuration:");
    println!("   • Security Level: HIGH");
    println!("   • Max Sessions: 10");
    println!("   • Session Timeout: 1 hour");
    println!("   • Token TTL: 24 hours");
    println!();

    println!("✅ Basic security setup complete!");
    println!("\n🐺 Wolf Pack is ready to protect your system!");

    Ok(())
}
