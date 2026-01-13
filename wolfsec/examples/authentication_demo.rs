//! Authentication Demo
//!
//! Demonstrates user authentication, role-based access control, and session management.

use anyhow::Result;
use wolfsec::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🐺 Wolf Prowler - Authentication Demo\n");

    // Initialize authentication manager
    println!("1️⃣ Initializing Authentication Manager...");
    let auth_manager = AuthManager::new(Default::default()).await?;
    println!("   ✅ Authentication Manager initialized\n");

    // Create roles with permissions
    println!("2️⃣ Setting up Roles and Permissions...");

    let admin_role = Role {
        id: "admin".to_string(),
        name: "Administrator".to_string(),
        permissions: vec![Permission {
            id: "all:all".to_string(),
            resource: "*".to_string(),
            action: "*".to_string(),
        }],
    };

    let user_role = Role {
        id: "user".to_string(),
        name: "Standard User".to_string(),
        permissions: vec![Permission {
            id: "data:read".to_string(),
            resource: "data".to_string(),
            action: "read".to_string(),
        }],
    };

    println!("   ✅ Created role: {} (full access)", admin_role.name);
    println!("   ✅ Created role: {} (read-only)", user_role.name);
    println!();

    // Create users
    println!("3️⃣ Creating Users...");

    let admin_user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username: "alice".to_string(),
        email: "alice@wolfprowler.local".to_string(),
        roles: vec![admin_role.clone()],
        created_at: chrono::Utc::now(),
        last_login: None,
        mfa_enabled: true,
        metadata: Default::default(),
    };

    let standard_user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username: "bob".to_string(),
        email: "bob@wolfprowler.local".to_string(),
        roles: vec![user_role.clone()],
        created_at: chrono::Utc::now(),
        last_login: None,
        mfa_enabled: false,
        metadata: Default::default(),
    };

    println!(
        "   ✅ Created user: {} (Administrator, MFA enabled)",
        admin_user.username
    );
    println!(
        "   ✅ Created user: {} (Standard User)",
        standard_user.username
    );
    println!();

    // Simulate authentication flow
    println!("4️⃣ Authentication Flow:");
    println!("   👤 User 'alice' attempting login...");
    println!("      ✓ Credentials validated");
    println!("      ✓ MFA challenge sent");
    println!("      ✓ MFA code verified");
    println!("      ✓ Session created (expires in 24h)");
    println!("      ✅ Login successful!");
    println!();

    // Demonstrate permission checking
    println!("5️⃣ Permission Checks:");

    // Check admin permissions
    let can_admin_write = admin_user.roles.iter().any(|role| {
        role.permissions.iter().any(|p| {
            (p.resource == "*" || p.resource == "data") && (p.action == "*" || p.action == "write")
        })
    });
    println!(
        "   • Can 'alice' write data? {}",
        if can_admin_write { "✅ Yes" } else { "❌ No" }
    );

    // Check standard user permissions
    let can_user_write = standard_user.roles.iter().any(|role| {
        role.permissions
            .iter()
            .any(|p| p.resource == "data" && p.action == "write")
    });
    println!(
        "   • Can 'bob' write data? {}",
        if can_user_write {
            "✅ Yes"
        } else {
            "❌ No (read-only)"
        }
    );

    let can_user_read = standard_user.roles.iter().any(|role| {
        role.permissions
            .iter()
            .any(|p| p.resource == "data" && p.action == "read")
    });
    println!(
        "   • Can 'bob' read data? {}",
        if can_user_read { "✅ Yes" } else { "❌ No" }
    );
    println!();

    println!("✅ Authentication demo complete!");
    println!("\n🐺 Wolf Pack is securing your authentication!");

    Ok(())
}
