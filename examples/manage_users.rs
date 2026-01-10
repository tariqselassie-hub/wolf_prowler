//! Example: User Management
//!
//! This script demonstrates how to programmatically add a user to the WolfSec authentication system.
//! In a real deployment, this would be part of an admin CLI or setup wizard.

use wolfsec::authentication::{AuthManager, AuthConfig, User, Role, Permission};
use wolfsec::infrastructure::persistence::WolfDbAuthRepository;
use wolf_db::storage::WolfDbStorage;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize Storage (In-memory for this example, or point to real DB)
    let db_path = std::env::temp_dir().join("wolfsec_user_mgmt_demo");
    let storage = WolfDbStorage::open(&db_path)?;
    let storage = Arc::new(RwLock::new(storage));
    
    // Initialize keystore for the example
    {
        let mut s = storage.write().await;
        if !s.is_initialized() {
            s.initialize_keystore("admin_secret", None)?;
        }
        s.unlock("admin_secret", None)?;
    }

    let auth_repo = Arc::new(WolfDbAuthRepository::new(storage.clone()));
    let mut auth_manager = AuthManager::new(AuthConfig::default(), auth_repo);
    auth_manager.initialize().await?;

    // 2. Define a New User
    let username = "sysadmin_01";
    let password = "CorrectHorseBatteryStaple!"; // Strong password example
    
    println!("Creating user '{}'...", username);

    // 3. Create User with Admin Role
    // Note: In a real CLI, we would check if user exists first.
    let user_id = auth_manager.create_user(
        username,
        password,
        Role::Admin,
        vec![Permission::SystemManage, Permission::ViewSensitiveData]
    ).await?;

    println!("✅ User created successfully!");
    println!("User ID: {}", user_id);
    println!("Role: {:?}", Role::Admin);

    // 4. Verify Login
    println!("\nVerifying login...");
    let session = auth_manager.authenticate(username, password).await?;
    println!("✅ Login successful! Session Token: {}", session.token);

    Ok(())
}
