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
    let _security_config = SecurityConfig {
        default_security_level: HIGH_SECURITY,
        max_sessions_per_peer: 10,
        session_cleanup_interval: 3600,
        token_ttl_hours: 24,
    };

    let _security_manager =
        NetworkSecurityManager::new("wolf_node_alpha".to_string(), HIGH_SECURITY);
    println!("   ✅ Network Security Manager initialized\n");

    // 2. Set up Identity Management
    println!("2️⃣ Setting up Identity Management...");
    let identity_config = IdentityConfig::default();
    let mut identity_manager = IdentityManager::new(identity_config);
    identity_manager.initialize()?;
    println!("   ✅ Identity Manager initialized\n");

    // 3. Initialize Authentication
    println!("3️⃣ Initializing Authentication...");
    // For the example, we'd need a repository. In a real app we'd use WolfDbAuthRepository.
    // Since we don't want to setup a whole DB here, we'll just mock it or skip it for this display.
    // But to make it compile, we need a real or mock implementation.
    // I specify a mock below.

    struct MockAuthRepo;
    #[async_trait::async_trait]
    impl wolfsec::domain::repositories::AuthRepository for MockAuthRepo {
        async fn save_user(
            &self,
            _u: &wolfsec::domain::entities::auth::User,
        ) -> Result<(), wolfsec::domain::error::DomainError> {
            Ok(())
        }
        async fn find_user_by_id(
            &self,
            _id: &uuid::Uuid,
        ) -> Result<
            Option<wolfsec::domain::entities::auth::User>,
            wolfsec::domain::error::DomainError,
        > {
            Ok(None)
        }
        async fn find_user_by_username(
            &self,
            _u: &str,
        ) -> Result<
            Option<wolfsec::domain::entities::auth::User>,
            wolfsec::domain::error::DomainError,
        > {
            Ok(None)
        }
        async fn save_role(
            &self,
            _r: &wolfsec::domain::entities::auth::Role,
        ) -> Result<(), wolfsec::domain::error::DomainError> {
            Ok(())
        }
        async fn find_role_by_name(
            &self,
            _n: &str,
        ) -> Result<
            Option<wolfsec::domain::entities::auth::Role>,
            wolfsec::domain::error::DomainError,
        > {
            Ok(None)
        }
    }

    let _auth_manager = AuthManager::new(Default::default(), std::sync::Arc::new(MockAuthRepo));

    // Create a test user
    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        roles: vec![Role::Admin],
        permissions: vec![Permission::Read, Permission::Write, Permission::Admin],
    };

    println!("   ✅ Created user: {}", user.username);
    println!("   ✅ Roles: {:?}", user.roles);
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
