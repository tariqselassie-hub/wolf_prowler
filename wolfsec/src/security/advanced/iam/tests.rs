//! Comprehensive Authentication System Tests
//!
//! Tests for OAuth2/OIDC, JWT, RBAC, MFA, Session Management, and PQC components.

use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::security::advanced::iam::{
    authentication::AuthenticationManager,
    iam::{IAMConfig, IAMIntegrationManager},
    jwt_auth::{JWTAuthenticationManager, JWTAuthenticationRequest, TokenType},
    mfa::{MFAManager, MFAmethod},
    rbac::{RBACManager, RBACQuery, ResourceAction, ResourceType, WolfRoleType},
    session::{SessionManager, SessionRequest, SessionType},
    sso::{SSOIntegrationManager, SSOProvider},
    user_management::UserManagementManager,
};

/// Test configuration
fn test_config() -> IAMConfig {
    IAMConfig {
        enabled_identity_providers: vec![],
        session_timeout_minutes: 60,
        mfa_requirements: Default::default(),
        password_policy: Default::default(),
        access_control: Default::default(),
        audit_settings: Default::default(),
    }
}

/// Test JWT authentication
#[tokio::test]
async fn test_jwt_authentication() -> Result<()> {
    let config = test_config();
    let jwt_manager = JWTAuthenticationManager::new(config).await?;

    let request = JWTAuthenticationRequest {
        user_id: Uuid::new_v4(),
        username: "test_user".to_string(),
        roles: vec!["admin".to_string()],
        permissions: vec!["dashboard:read".to_string(), "dashboard:write".to_string()],
        client_info: Default::default(),
        token_type: TokenType::Access,
        remember_me: false,
        mfa_verified: true,
    };

    let result = jwt_manager.generate_token(request).await?;
    assert!(result.success);
    assert!(!result.token.is_empty());

    // Validate the token
    let validation = jwt_manager.validate_token(&result.token).await?;
    assert!(validation.valid);

    Ok(())
}

/// Test RBAC authorization
#[tokio::test]
async fn test_rbac_authorization() -> Result<()> {
    let config = test_config();
    let rbac_manager = RBACManager::new(config).await?;

    let query = RBACQuery {
        user_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222")?, // Delta user
        resource_type: ResourceType::Dashboard,
        action: ResourceAction::Read,
        resource_id: None,
        client_info: None,
    };

    let decision = rbac_manager.check_access(query).await?;
    assert!(decision.decision == crate::security::advanced::iam::AccessDecisionType::Allow);

    // Test denied access
    let query = RBACQuery {
        user_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333")?, // Omega user
        resource_type: ResourceType::UserManagement,
        action: ResourceAction::Admin,
        resource_id: None,
        client_info: None,
    };

    let decision = rbac_manager.check_access(query).await?;
    assert!(decision.decision == crate::security::advanced::iam::AccessDecisionType::Deny);

    Ok(())
}

/// Test MFA enrollment and verification
#[tokio::test]
async fn test_mfa_enrollment() -> Result<()> {
    let config = test_config();
    let mfa_manager = MFAManager::new(config).await?;

    let user_id = Uuid::new_v4();

    // Enroll user in TOTP
    let enrollment = mfa_manager
        .enroll_user(user_id, MFAmethod::TOTP, None, None, None)
        .await?;

    assert_eq!(enrollment.method, MFAmethod::TOTP);
    assert!(enrollment.active);
    assert!(enrollment.secret.is_some());

    // Get user enrollments
    let enrollments = mfa_manager.get_user_enrollments(user_id).await;
    assert_eq!(enrollments.len(), 1);

    Ok(())
}

/// Test session management
#[tokio::test]
async fn test_session_management() -> Result<()> {
    let config = test_config();
    let session_manager = SessionManager::new(config).await?;

    let request = SessionRequest {
        ip_address: "192.168.1.100".to_string(),
        user_agent: "Test Agent".to_string(),
        remember_me: false,
    };

    let session = session_manager
        .create_session(Uuid::new_v4(), request)
        .await?;
    assert_eq!(
        session.status,
        crate::security::advanced::iam::SessionStatus::Active
    );
    assert_eq!(session.session_type, SessionType::Regular);

    // Validate session
    let validation = session_manager.validate_session(session.id).await?;
    assert!(validation.valid);

    // Update session activity
    let update_request = crate::security::advanced::iam::session::SessionUpdateRequest {
        session_id: session.id,
        client_info: Some(Default::default()),
        activity_type: crate::security::advanced::iam::session::SessionActivityType::APIRequest,
        context: None,
    };

    let updated_session = session_manager
        .update_session_activity(session.id, update_request)
        .await?;
    assert_eq!(updated_session.id, session.id);

    // Terminate session
    session_manager.terminate_session(session.id).await?;

    // Validate terminated session
    let validation = session_manager.validate_session(session.id).await?;
    assert!(!validation.valid);

    Ok(())
}

/// Test SSO integration
#[tokio::test]
async fn test_sso_integration() -> Result<()> {
    let config = test_config();
    let sso_manager = SSOIntegrationManager::new(config).await?;

    // List configured providers
    let providers = sso_manager.list_providers().await;
    assert!(providers.contains(&SSOProvider::AzureAD));
    assert!(providers.contains(&SSOProvider::Okta));
    assert!(providers.contains(&SSOProvider::Auth0));

    // Get provider configuration
    let azure_config = sso_manager.get_provider_config(SSOProvider::AzureAD).await;
    assert!(azure_config.is_some());

    Ok(())
}

/// Test comprehensive authentication flow
#[tokio::test]
async fn test_comprehensive_auth_flow() -> Result<()> {
    let config = test_config();
    let mut iam_manager = IAMIntegrationManager::new(config).await?;

    // Create test user
    let user_request = crate::security::advanced::iam::user_management::CreateUserRequest {
        username: "test_user".to_string(),
        email: "test@example.com".to_string(),
        full_name: "Test User".to_string(),
        password: "TestPassword123!".to_string(),
        roles: vec!["delta".to_string()],
        groups: vec![],
        attributes: Default::default(),
    };

    let user = iam_manager.create_user(user_request).await?;
    assert_eq!(user.username, "test_user");

    // Test authentication
    let auth_request = crate::security::advanced::iam::authentication::AuthenticationRequest {
        username: "test_user".to_string(),
        password: Some("TestPassword123!".to_string()),
        mfa_token: None,
        identity_provider: None,
        client_info: Default::default(),
    };

    let auth_result = iam_manager.authenticate_user(auth_request).await?;
    assert!(auth_result.success);

    // Test session creation
    let session_request = SessionRequest {
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Test Agent".to_string(),
        remember_me: false,
    };

    let session = iam_manager.create_session(user.id, session_request).await?;
    assert_eq!(
        session.status,
        crate::security::advanced::iam::SessionStatus::Active
    );

    // Test session validation
    let validation = iam_manager.validate_session(session.id).await?;
    assert!(validation.valid);

    // Test authorization
    let authz_request = crate::security::advanced::iam::authorization::AuthorizationRequest {
        user_id: user.id,
        resource: "dashboard".to_string(),
        action: "read".to_string(),
        context: Default::default(),
    };

    let decision = iam_manager.authorize_access(authz_request).await?;
    assert!(decision.decision == crate::security::advanced::iam::Effect::Allow);

    // Clean up
    iam_manager.terminate_session(session.id).await?;
    iam_manager.delete_user(user.id).await?;

    Ok(())
}

/// Test JWT token lifecycle
#[tokio::test]
async fn test_jwt_token_lifecycle() -> Result<()> {
    let config = test_config();
    let jwt_manager = JWTAuthenticationManager::new(config).await?;

    let user_id = Uuid::new_v4();

    // Generate access token
    let access_request = JWTAuthenticationRequest {
        user_id,
        username: "test_user".to_string(),
        roles: vec!["admin".to_string()],
        permissions: vec!["dashboard:read".to_string()],
        client_info: Default::default(),
        token_type: TokenType::Access,
        remember_me: false,
        mfa_verified: true,
    };

    let access_token = jwt_manager.generate_token(access_request).await?;
    assert!(access_token.success);

    // Validate access token
    let validation = jwt_manager.validate_token(&access_token.token).await?;
    assert!(validation.valid);

    // Generate refresh token
    let refresh_request = JWTAuthenticationRequest {
        user_id,
        username: "test_user".to_string(),
        roles: vec!["admin".to_string()],
        permissions: vec!["dashboard:read".to_string()],
        client_info: Default::default(),
        token_type: TokenType::Refresh,
        remember_me: false,
        mfa_verified: true,
    };

    let refresh_token = jwt_manager.generate_token(refresh_request).await?;
    assert!(refresh_token.success);

    // Refresh access token
    let new_access_token = jwt_manager.refresh_token(&refresh_token.token).await?;
    assert!(new_access_token.success);

    // Revoke refresh token
    jwt_manager.revoke_token(&refresh_token.token).await?;

    // Try to use revoked token
    let revoked_validation = jwt_manager.validate_token(&refresh_token.token).await?;
    assert!(!revoked_validation.valid);

    Ok(())
}

/// Test RBAC role hierarchy
#[tokio::test]
async fn test_rbac_role_hierarchy() -> Result<()> {
    let config = test_config();
    let rbac_manager = RBACManager::new(config).await?;

    // Test Alpha role (highest privileges)
    let alpha_query = RBACQuery {
        user_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111")?, // Alpha user
        resource_type: ResourceType::UserManagement,
        action: ResourceAction::Admin,
        resource_id: None,
        client_info: None,
    };

    let alpha_decision = rbac_manager.check_access(alpha_query).await?;
    assert!(alpha_decision.decision == crate::security::advanced::iam::AccessDecisionType::Allow);

    // Test Omega role (lowest privileges)
    let omega_query = RBACQuery {
        user_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333")?, // Omega user
        resource_type: ResourceType::Audit,
        action: ResourceAction::Read,
        resource_id: None,
        client_info: None,
    };

    let omega_decision = rbac_manager.check_access(omega_query).await?;
    assert!(omega_decision.decision == crate::security::advanced::iam::AccessDecisionType::Allow);

    // Test Omega trying to access admin resources
    let omega_admin_query = RBACQuery {
        user_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333")?, // Omega user
        resource_type: ResourceType::UserManagement,
        action: ResourceAction::Admin,
        resource_id: None,
        client_info: None,
    };

    let omega_admin_decision = rbac_manager.check_access(omega_admin_query).await?;
    assert!(
        omega_admin_decision.decision == crate::security::advanced::iam::AccessDecisionType::Deny
    );

    Ok(())
}

/// Test session security features
#[tokio::test]
async fn test_session_security() -> Result<()> {
    let config = test_config();
    let session_manager = SessionManager::new(config).await?;

    let user_id = Uuid::new_v4();

    // Create session with initial client info
    let initial_request = SessionRequest {
        ip_address: "192.168.1.100".to_string(),
        user_agent: "Initial Agent".to_string(),
        remember_me: false,
    };

    let session = session_manager
        .create_session(user_id, initial_request)
        .await?;

    // Update session with different IP (should trigger security violation)
    let malicious_request = crate::security::advanced::iam::session::SessionUpdateRequest {
        session_id: session.id,
        client_info: Some(crate::security::advanced::iam::ClientInfo {
            ip_address: "10.0.0.1".to_string(), // Different IP
            user_agent: "Initial Agent".to_string(),
            device_id: None,
            location: None,
        }),
        activity_type: crate::security::advanced::iam::session::SessionActivityType::APIRequest,
        context: None,
    };

    let updated_session = session_manager
        .update_session_activity(session.id, malicious_request)
        .await?;

    // Check that security violations were detected
    assert!(updated_session.security_context.ip_changes.len() > 0);
    assert!(updated_session.security_context.risk_score > 0);

    // Update session with same IP but different user agent
    let user_agent_request = crate::security::advanced::iam::session::SessionUpdateRequest {
        session_id: session.id,
        client_info: Some(crate::security::advanced::iam::ClientInfo {
            ip_address: "192.168.1.100".to_string(),   // Same IP
            user_agent: "Different Agent".to_string(), // Different user agent
            device_id: None,
            location: None,
        }),
        activity_type: crate::security::advanced::iam::session::SessionActivityType::APIRequest,
        context: None,
    };

    let updated_session = session_manager
        .update_session_activity(session.id, user_agent_request)
        .await?;

    // Check that user agent change was detected
    assert!(updated_session.security_context.user_agent_changes.len() > 0);

    Ok(())
}

/// Test MFA backup codes
#[tokio::test]
async fn test_mfa_backup_codes() -> Result<()> {
    let config = test_config();
    let mfa_manager = MFAManager::new(config).await?;

    let user_id = Uuid::new_v4();

    // Enroll user in MFA
    let enrollment = mfa_manager
        .enroll_user(user_id, MFAmethod::TOTP, None, None, None)
        .await?;

    let backup_codes = enrollment.backup_codes;
    assert_eq!(backup_codes.len(), 10);

    // Use first backup code
    let first_code = &backup_codes[0];
    let verification = mfa_manager.verify_backup_code(user_id, first_code).await?;
    assert!(verification.success);

    // Try to use the same backup code again (should fail)
    let verification = mfa_manager.verify_backup_code(user_id, first_code).await;
    assert!(verification.is_err());

    // Try to use a different backup code
    let second_code = &backup_codes[1];
    let verification = mfa_manager.verify_backup_code(user_id, second_code).await?;
    assert!(verification.success);

    Ok(())
}

/// Test concurrent session limits
#[tokio::test]
async fn test_concurrent_session_limits() -> Result<()> {
    let config = test_config();
    let session_manager = SessionManager::new(config).await?;

    let user_id = Uuid::new_v4();

    // Create multiple sessions for the same user
    let mut session_ids = Vec::new();
    for i in 0..6 {
        let request = SessionRequest {
            ip_address: format!("192.168.1.{}", 100 + i),
            user_agent: format!("Agent {}", i),
            remember_me: false,
        };

        let session = session_manager.create_session(user_id, request).await?;
        session_ids.push(session.id);
    }

    // Get user sessions
    let user_sessions = session_manager.get_user_sessions(user_id).await;

    // Should only have 5 sessions (limit enforced)
    assert_eq!(user_sessions.len(), 5);

    // Clean up
    for session_id in session_ids {
        session_manager.terminate_session(session_id).await.ok();
    }

    Ok(())
}

/// Test authentication statistics
#[tokio::test]
async fn test_authentication_statistics() -> Result<()> {
    let config = test_config();
    let jwt_manager = JWTAuthenticationManager::new(config.clone()).await?;
    let rbac_manager = RBACManager::new(config.clone()).await?;
    let session_manager = SessionManager::new(config.clone()).await?;
    let mfa_manager = MFAManager::new(config.clone()).await?;
    let sso_manager = SSOIntegrationManager::new(config).await?;

    // Generate some activity
    let user_id = Uuid::new_v4();

    // JWT tokens
    let request = JWTAuthenticationRequest {
        user_id,
        username: "test_user".to_string(),
        roles: vec!["admin".to_string()],
        permissions: vec!["dashboard:read".to_string()],
        client_info: Default::default(),
        token_type: TokenType::Access,
        remember_me: false,
        mfa_verified: true,
    };

    let _token = jwt_manager.generate_token(request).await?;

    // Session
    let session_request = SessionRequest {
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Test Agent".to_string(),
        remember_me: false,
    };

    let session = session_manager
        .create_session(user_id, session_request)
        .await?;

    // RBAC check
    let query = RBACQuery {
        user_id,
        resource_type: ResourceType::Dashboard,
        action: ResourceAction::Read,
        resource_id: None,
        client_info: None,
    };

    let _decision = rbac_manager.check_access(query).await?;

    // MFA enrollment
    let _enrollment = mfa_manager
        .enroll_user(user_id, MFAmethod::TOTP, None, None, None)
        .await?;

    // Get statistics
    let jwt_count = jwt_manager.get_active_token_count().await;
    let session_count = session_manager.get_stats().await.total_sessions;
    let rbac_stats = rbac_manager.get_stats().await;
    let mfa_stats = mfa_manager.get_stats().await;
    let sso_providers = sso_manager.list_providers().await;

    assert!(jwt_count > 0);
    assert!(session_count > 0);
    assert!(rbac_stats.total_permissions > 0);
    assert!(mfa_stats.total_enrollments > 0);
    assert!(sso_providers.len() > 0);

    // Clean up
    session_manager.terminate_session(session.id).await?;

    Ok(())
}
