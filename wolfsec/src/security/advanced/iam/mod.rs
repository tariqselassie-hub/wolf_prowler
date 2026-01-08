//! IAM Integration Module
//!
//! Identity and Access Management with wolf pack hierarchy principles.
//! Wolves maintain strict pack hierarchy with clear access controls and roles.

pub mod authentication;
pub mod authorization;
pub mod identity_providers;
pub mod jwt_auth;
pub mod mfa;
pub mod pqc;
pub mod privileged_access;
pub mod rbac;
pub mod session;
pub mod single_sign_on;
pub mod sso;
pub mod user_management;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

pub use authentication::AuthenticationManager;
pub use authentication::{ApiKey, ApiKeyStatus, ApiKeyValidationResult};
pub use authorization::AuthorizationManager;
/// Re-export main components
pub use identity_providers::IdentityProviderManager;
pub use jwt_auth::{JWTAuthenticationManager, JWTAuthenticationRequest, JWTValidationResult};
pub use mfa::{MFAEnrollment, MFAManager, MFAVerificationResult, MFAMethod};
pub use pqc::{PQCAlgorithm, PQCKeyPair, PQCManager, PQCVerificationResult};
pub use privileged_access::PrivilegedAccessManager;
pub use rbac::{AccessDecision, RBACManager, RBACQuery, WolfRoleType};
pub use session::{Session, SessionManager, SessionStatus, SessionType, SessionValidationResult};
pub use single_sign_on::SingleSignOnManager;
pub use sso::{
    SSOAuthenticationResult, SSOCallbackRequest, SSOIntegrationManager, SSOProvider,
    SSOProviderConfig,
};
pub use user_management::UserManagementManager;

/// Orchestrates all Identity and Access Management (IAM) operations across the Wolf Prowler ecosystem
pub struct IAMIntegrationManager {
    /// Manager for federated and local identity providers (SAML, OAuth, etc.)
    pub identity_providers: IdentityProviderManager,
    /// Core engine for verifying user and service identities
    pub authentication: AuthenticationManager,
    /// Engine for enforcing pack hierarchy and role-based access controls
    pub authorization: AuthorizationManager,
    /// Service for managing wolf identity lifecycle and profile data
    pub user_management: UserManagementManager,
    /// Specialized manager for elevated/emergency access requests
    pub privileged_access: PrivilegedAccessManager,
    /// Manager for unified cross-domain authentication
    pub single_sign_on: SingleSignOnManager,
    /// Active IAM configuration settings
    pub config: IAMConfig,
    /// Aggregated real-time metrics for IAM operations
    pub statistics: IAMStats,
}

/// Global configuration for the Identity and Access Management system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAMConfig {
    /// List of identity providers allowed for authentication
    pub enabled_identity_providers: Vec<IdentityProviderType>,
    /// Duration of a valid session before re-authentication is required (in minutes)
    pub session_timeout_minutes: u32,
    /// Rigorous multi-factor authentication requirements and grace periods
    pub mfa_requirements: MFARequirements,
    /// Complexity, history, and expiration rules for passwords
    pub password_policy: PasswordPolicy,
    /// High-level engine settings for RBAC, ABAC, and JIT access
    pub access_control: AccessControlConfig,
    /// Granular settings for what events are recorded in the security audit trail
    pub audit_settings: AuditSettings,
}

/// Supported external and internal identity provider protocols
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IdentityProviderType {
    /// Security Assertion Markup Language (XML-based)
    SAML,
    /// Open Authorization 2.0
    OAuth2,
    /// OpenID Connect identity layer on top of OAuth 2.0
    OpenIDConnect,
    /// Lightweight Directory Access Protocol
    LDAP,
    /// Microsoft Active Directory (On-premise)
    ActiveDirectory,
    /// Microsoft Azure Active Directory (Cloud-native)
    AzureAD,
    /// Okta Identity Cloud
    Okta,
    /// Auth0 Identity Management
    Auth0,
    /// Integration with a proprietary or legacy identity provider
    Custom(String),
}

/// Defines the triggers and methods for Multi-Factor Authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFARequirements {
    /// Global toggle for MFA enforcement
    pub enabled: bool,
    /// If true, all admin-level roles must use MFA
    pub required_for_admin: bool,
    /// If true, sensitive "privileged" operations always trigger an MFA challenge
    pub required_for_privileged: bool,
    /// Time window allowed to enroll in MFA after account creation
    pub grace_period_hours: u32,
    /// Whitelist of cryptographically signed or verified authentication methods
    pub allowed_methods: Vec<MFAMethod>,
}

/// Security constraints for local user passwords
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum character count
    pub min_length: u32,
    /// Maximum character count to prevent DoS via hashing
    pub max_length: u32,
    /// Requires at least one [A-Z] character
    pub require_uppercase: bool,
    /// Requires at least one [a-z] character
    pub require_lowercase: bool,
    /// Requires at least one [0-9] character
    pub require_numbers: bool,
    /// Requires at least one non-alphanumeric character
    pub require_special_chars: bool,
    /// Number of previous passwords that cannot be reused
    pub password_history: u32,
    /// Number of days before a user is forced to rotate their password
    pub expiration_days: u32,
    /// Failed attempts allowed before account lock
    pub lockout_threshold: u32,
    /// Duration of an automated account lock (in minutes)
    pub lockout_duration_minutes: u32,
}

/// Settings for access control engines and methodologies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    /// Initial trust level assigned to new or unclassified entities
    pub default_access_level: AccessLevel,
    /// Toggle for pack hierarchy enforcement
    pub rbac_enabled: bool,
    /// Toggle for contextual/attribute-based enforcement
    pub abac_enabled: bool,
    /// Toggle for ephemeral, request-based access
    pub jit_enabled: bool,
    /// Number of days between mandatory access review cycles
    pub access_review_frequency_days: u32,
}

/// Defines which IAM-related operations are captured in the security audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSettings {
    /// Master toggle for IAM audit logging
    pub enabled: bool,
    /// Record all login and logout attempts
    pub log_authentication: bool,
    /// Record all access decisions (allow/deny)
    pub log_authorization: bool,
    /// Record all profile and account changes
    pub log_user_management: bool,
    /// Record all elevated privilege grants and usages
    pub log_privileged_access: bool,
    /// Number of days to retain audit logs before rotation/deletion
    pub retention_days: u32,
}

/// Statistical overview of the IAM system's health and activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAMStats {
    /// Aggregate count of all registered wolf identities.
    pub total_users: u64,
    /// Number of wolves with active, non-suspended profiles.
    pub active_users: u64,
    /// Total number of identity verification attempts.
    pub authentication_events: u64,
    /// Number of failed verification attempts.
    pub failed_authentications: u64,
    /// Total number of access requests evaluated.
    pub authorization_decisions: u64,
    /// Number of access requests that were denied.
    pub denied_access_attempts: u64,
    /// Number of times elevated privileges were requested.
    pub privileged_access_requests: u64,
    /// Total number of MFA verification steps triggered.
    pub mfa_challenges: u64,
    /// Exact time when these statistics were last recalculated.
    pub last_update: DateTime<Utc>,
}

/// Represents a single wolf identity within the pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique internal identifier for the user.
    pub id: Uuid,
    /// Human-readable unique identifier for the user.
    pub username: String,
    /// Primary contact and notification address.
    pub email: String,
    /// Legal or preferred full name of the user.
    pub full_name: String,
    /// Current lifecycle state of the user account.
    pub status: UserStatus,
    /// List of assigned roles determining baseline access.
    pub roles: Vec<String>,
    /// Logical groupings for bulk policy application.
    pub groups: Vec<String>,
    /// Extensible key-value pairs for additional identity data.
    pub attributes: HashMap<String, serde_json::Value>,
    /// Time when the user profile was first instantiated.
    pub created_at: DateTime<Utc>,
    /// Last recorded time of successful identity verification.
    pub last_login: Option<DateTime<Utc>>,
    /// Last time the user's password was successfully updated.
    pub password_last_changed: Option<DateTime<Utc>>,
    /// Flag indicating if Multi-Factor Authentication is set up.
    pub mfa_enrolled: bool,
    /// List of specifically configured MFA methods for this user.
    pub mfa_methods: Vec<MFAMethod>,
}

/// Possible states for a wolf identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum UserStatus {
    /// Account is fully operational.
    #[default]
    Active,
    /// Account is temporarily disabled by an administrator.
    Inactive,
    /// Account is suspended due to security concerns.
    Suspended,
    /// Account is locked due to consecutive failed logins.
    Locked,
    /// Account is awaiting initial verification or approval.
    Pending,
    /// Account has been permanently retired.
    Deactivated,
}

/// Defines a set of permissions and a relative rank within the pack hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique internal identifier for the role
    pub id: Uuid,
    /// Human-readable name for the role (e.g., "Alpha", "Sentinel")
    pub name: String,
    /// Detailed explanation of the role's purpose and scope
    pub description: String,
    /// List of explicit permissions granted to this role
    pub permissions: Vec<Permission>,
    /// Numerical rank (lower is usually more privileged)
    pub hierarchy_level: u32,
    /// High-level classification of the role type
    pub role_type: WolfRoleType,
    /// Time when the role was first defined
    pub created_at: DateTime<Utc>,
    /// Time of the most recent modification to this role
    pub updated_at: DateTime<Utc>,
}

/// Standardized definition of an allowable or prohibited action on a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Unique identifier for this specific permission entry.
    pub id: Uuid,
    /// Human-readable label for the permission.
    pub name: String,
    /// The target object or system component.
    pub resource: String,
    /// The operation being performed.
    pub action: String,
    /// Whether the action is explicitly permitted or forbidden.
    pub effect: Effect,
    /// Logical constraints that must be met for this permission to apply.
    pub conditions: Vec<Condition>,
}

/// Final outcome of an access control evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect {
    /// Access is explicitly granted.
    Allow,
    /// Access is explicitly prohibited.
    Deny,
}

/// A dynamic rule that evaluates environmental context or attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    /// The category or key of the data to evaluate (e.g., "time_of_day", "ip_range")
    pub condition_type: String,
    /// The logic to apply (e.g., "Between", "Equals", "Matches")
    pub operator: String,
    /// The literal or pattern to compare against the context
    pub value: serde_json::Value,
}

/// Primitive tiers of system access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessLevel {
    /// No permissions granted.
    NoAccess = 0,
    /// View-only access.
    Read = 1,
    /// Modification and creation rights.
    Write = 2,
    /// Administrative control over a scope.
    Admin = 3,
    /// Absolute control over the entire IAM system.
    SuperAdmin = 4,
}

/// Detailed output from a single identity verification event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    /// Unique identifier for the audit of this attempt.
    pub id: Uuid,
    /// The wolf identity associated with the attempt.
    pub user_id: Uuid,
    /// The specific protocol or method used for verification.
    pub method: AuthenticationMethod,
    /// True if the identity was successfully proven.
    pub success: bool,
    /// Exact system time of the attempt.
    pub timestamp: DateTime<Utc>,
    /// Network origin of the request.
    pub ip_address: String,
    /// Software identifier of the requesting client.
    pub user_agent: String,
    /// Indicates if a secondary factor is still required.
    pub mfa_required: bool,
    /// Indicates if the secondary factor was already provided.
    pub mfa_completed: bool,
    /// Identifier for the resulting session, if successful.
    pub session_id: Option<Uuid>,
    /// Human-readable explanation of why verification failed.
    pub error_message: Option<String>,
}

/// Methods used to prove identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationMethod {
    /// Verified via local or remote password.
    Password,
    /// Verified via external Single Sign-On provider.
    SSO,
    /// Verified via multi-factor authentication.
    MFA,
    /// Verified via X.509 certificate.
    Certificate,
    /// Verified via physical characteristics.
    Biometric,
    /// Verified via pre-shared secret key.
    APIKey,
    /// Verified via JSON Web Token.
    JWT,
    /// Verified via role-based credentials.
    RBAC,
    /// Verified via an existing valid session.
    Session,
}

/// Formal output from an access control policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    /// Unique identifier for the audit of this decision.
    pub id: Uuid,
    /// Subject of the access request.
    pub user_id: Uuid,
    /// Target of the access request.
    pub resource: String,
    /// Requested operation.
    pub action: String,
    /// Final verdict (Allow/Deny).
    pub decision: Effect,
    /// Exact system time of the evaluation.
    pub timestamp: DateTime<Utc>,
    /// Narrative or justification for the decision.
    pub reason: String,
    /// Identifiers of the policies that influenced this result.
    pub applied_policies: Vec<String>,
}

impl IAMIntegrationManager {
    /// Initializes a new `IAMIntegrationManager` with all constituent security services.
    ///
    /// # Errors
    /// Returns an error if any of the underlying managers fail to initialize.
    pub async fn new(config: IAMConfig) -> Result<Self> {
        info!("🔐 Initializing IAM Integration Manager");

        let manager = Self {
            identity_providers: IdentityProviderManager::new(config.clone())?,
            authentication: AuthenticationManager::new(config.clone()).await?,
            authorization: AuthorizationManager::new(config.clone())?,
            user_management: UserManagementManager::new(config.clone())?,
            privileged_access: PrivilegedAccessManager::new(config.clone())?,
            single_sign_on: SingleSignOnManager::new(config.clone())?,
            config,
            statistics: IAMStats::default(),
        };

        info!("✅ IAM Integration Manager initialized successfully");
        Ok(manager)
    }

    /// Asynchronously verifies a user's identity based on provided credentials.
    ///
    /// # Errors
    /// Returns an error if the primary or secondary authentication provider fails.
    pub async fn authenticate_user(
        &mut self,
        auth_request: AuthenticationRequest,
    ) -> Result<AuthenticationResult> {
        debug!("🔐 Authenticating user: {}", auth_request.username);

        let result = self.authentication.authenticate(auth_request).await?;

        // Update statistics
        self.statistics.authentication_events += 1;
        if !result.success {
            self.statistics.failed_authentications += 1;
        }

        // Log authentication event
        if self.config.audit_settings.log_authentication {
            self.log_authentication_event(&result).await?;
        }

        debug!("✅ Authentication completed: {}", result.success);
        Ok(result)
    }

    /// Evaluates if a subject is authorized to perform an action on a resource.
    ///
    /// # Errors
    /// Returns an error if the authorization engine encounters a systemic failure.
    pub async fn authorize_access(
        &mut self,
        authz_request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision> {
        debug!(
            "🔓 Authorizing access: {} -> {}",
            authz_request.user_id, authz_request.action
        );

        let decision = self.authorization.authorize(authz_request).await?;

        // Update statistics
        self.statistics.authorization_decisions += 1;
        if decision.decision == Effect::Deny {
            self.statistics.denied_access_attempts += 1;
        }

        // Log authorization event
        if self.config.audit_settings.log_authorization {
            self.log_authorization_event(&decision).await?;
        }

        debug!("✅ Authorization completed: {:?}", decision.decision);
        Ok(decision)
    }

    /// Registers a new user within the system and assigns baseline roles.
    ///
    /// # Errors
    /// Returns an error if the user profile creation or storage fails.
    pub async fn create_user(&mut self, user_request: CreateUserRequest) -> Result<User> {
        info!("👤 Creating user: {}", user_request.username);

        let user = self.user_management.create_user(user_request).await?;

        // Update statistics
        self.statistics.total_users += 1;
        if user.status == UserStatus::Active {
            self.statistics.active_users += 1;
        }

        // Log user management event
        if self.config.audit_settings.log_user_management {
            self.log_user_management_event("USER_CREATED", &user)
                .await?;
        }

        info!("✅ User created: {}", user.username);
        Ok(user)
    }

    /// Updates an existing user's attributes, roles, or operational status.
    ///
    /// # Errors
    /// Returns an error if the user profile cannot be found or modification fails.
    pub async fn update_user(
        &mut self,
        user_id: Uuid,
        update_request: UpdateUserRequest,
    ) -> Result<User> {
        debug!("👤 Updating user: {}", user_id);

        let user = self
            .user_management
            .update_user(user_id, update_request)
            .await?;

        // Log user management event
        if self.config.audit_settings.log_user_management {
            self.log_user_management_event("USER_UPDATED", &user)
                .await?;
        }

        info!("✅ User updated: {}", user.username);
        Ok(user)
    }

    /// Removes a user and all associated security metadata from the IAM system.
    ///
    /// # Errors
    /// Returns an error if user deletion or audit logging fails.
    pub async fn delete_user(&mut self, user_id: Uuid) -> Result<()> {
        info!("🗑️ Deleting user: {}", user_id);

        self.user_management.delete_user(user_id).await?;

        // Update statistics
        self.statistics.total_users = self.statistics.total_users.saturating_sub(1);
        self.statistics.active_users = self.statistics.active_users.saturating_sub(1);

        // Log user management event
        if self.config.audit_settings.log_user_management {
            self.log_user_management_event("USER_DELETED", &User::default())
                .await?;
        }

        info!("✅ User deleted: {}", user_id);
        Ok(())
    }

    /// Evaluates and potentially grants elevated permissions for sensitive operations.
    ///
    /// # Errors
    /// Returns an error if the request is malformed or the privileged engine fails.
    pub async fn request_privileged_access(
        &mut self,
        request: PrivilegedAccessRequest,
    ) -> Result<PrivilegedAccessGrant> {
        info!("🔑 Requesting privileged access: {}", request.user_id);

        let grant = self.privileged_access.request_access(request).await?;

        // Update statistics
        self.statistics.privileged_access_requests += 1;

        // Log privileged access event
        if self.config.audit_settings.log_privileged_access {
            self.log_privileged_access_event("PRIVILEGE_REQUESTED", &grant)
                .await?;
        }

        info!("✅ Privileged access granted: {}", grant.id);
        Ok(grant)
    }

    /// Instantiates a new authenticated session for a verified user.
    ///
    /// # Errors
    /// Returns an error if session creation or secure storage fails.
    pub async fn create_session(
        &mut self,
        user_id: Uuid,
        session_request: SessionRequest,
    ) -> Result<Session> {
        debug!("🔐 Creating session for user: {}", user_id);

        let session = self
            .authentication
            .create_session(user_id, session_request)
            .await?;

        info!("✅ Session created: {}", session.id);
        Ok(session)
    }

    /// Determines if a session identifier is currently active and secure.
    ///
    /// # Errors
    /// Returns an error if the validation logic encounters a systemic issue.
    pub async fn validate_session(&mut self, session_id: Uuid) -> Result<SessionValidationResult> {
        debug!("🔍 Validating session: {}", session_id);

        let result = self.authentication.validate_session(session_id).await?;

        debug!("✅ Session validation: {}", result.valid);
        Ok(result)
    }

    /// Explicitly revokes a session, invalidating any future requests using its ID.
    ///
    /// # Errors
    /// Returns an error if session termination or revocation fails.
    pub async fn terminate_session(&mut self, session_id: Uuid) -> Result<()> {
        info!("🔐 Terminating session: {}", session_id);

        self.authentication.terminate_session(session_id).await?;

        info!("✅ Session terminated: {}", session_id);
        Ok(())
    }

    /// Retrieves a single user profile via its unique internal UUID.
    ///
    /// # Errors
    /// Returns an error if profile retrieval or database access fails.
    pub async fn get_user(&self, user_id: Uuid) -> Result<Option<User>> {
        self.user_management.get_user(user_id).await
    }

    /// Retrieves a single user profile via its human-readable pack identifier.
    ///
    /// # Errors
    /// Returns an error if profile retrieval or database access fails.
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.user_management.get_user_by_username(username).await
    }

    /// Fetches a list of wolf identities filtered by roles, status, or groups.
    ///
    /// # Errors
    /// Returns an error if filtered retrieval or database access fails.
    pub async fn list_users(&self, filters: UserListFilters) -> Result<Vec<User>> {
        self.user_management.list_users(filters).await
    }

    /// Returns a reference to the active IAM statistics.
    pub fn get_statistics(&self) -> &IAMStats {
        &self.statistics
    }

    /// Records a successful or failed authentication event in the persistent audit log.
    ///
    /// # Errors
    /// Returns an error if audit log persistence fails.
    async fn log_authentication_event(&self, _result: &AuthenticationResult) -> Result<()> {
        debug!("📝 Logging authentication event");
        // In a real implementation, this would log to audit system
        Ok(())
    }

    /// Records an access control decision and its justification in the persistent audit log.
    ///
    /// # Errors
    /// Returns an error if audit log persistence fails.
    async fn log_authorization_event(&self, _decision: &AuthorizationDecision) -> Result<()> {
        debug!("📝 Logging authorization event");
        // In a real implementation, this would log to audit system
        Ok(())
    }

    /// Records lifecycle events (creation, update, deletion) for wolf identities.
    ///
    /// # Errors
    /// Returns an error if audit log persistence fails.
    async fn log_user_management_event(&self, event_type: &str, _user: &User) -> Result<()> {
        debug!("📝 Logging user management event: {}", event_type);
        // In a real implementation, this would log to audit system
        Ok(())
    }

    /// Records requests and grants for elevated system privileges.
    ///
    /// # Errors
    /// Returns an error if audit log persistence fails.
    async fn log_privileged_access_event(
        &self,
        event_type: &str,
        _grant: &PrivilegedAccessGrant,
    ) -> Result<()> {
        debug!("📝 Logging privileged access event: {}", event_type);
        // In a real implementation, this would log to audit system
        Ok(())
    }
}

/// request for identity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    /// Human-readable unique identifier for the subject.
    pub username: String,
    /// Cryptographic secret or passphrase.
    pub password: Option<String>,
    /// Secondary verification token (OTP, etc.).
    pub mfa_token: Option<String>,
    /// Optional external provider to use for verification.
    pub identity_provider: Option<IdentityProviderType>,
    /// Metadata about the client making the request.
    pub client_info: ClientInfo,
}

/// request for access authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Identifier of the subject requesting access.
    pub user_id: Uuid,
    /// Target resource of the request.
    pub resource: String,
    /// Operation requested (read, write, etc.).
    pub action: String,
    /// Additional context used for evaluation (IP, time, etc.).
    pub context: HashMap<String, serde_json::Value>,
}

/// request to establish a new wolf identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    /// Human-readable unique identifier.
    pub username: String,
    /// Primary contact address.
    pub email: String,
    /// Full biological or preferred name.
    pub full_name: String,
    /// Initial cryptographic password.
    pub password: String,
    /// Identifiers of roles to assign.
    pub roles: Vec<String>,
    /// Identifier of groups to join.
    pub groups: Vec<String>,
    /// Supplemental identity attributes.
    pub attributes: HashMap<String, serde_json::Value>,
}

/// Update user request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    /// New email address.
    pub email: Option<String>,
    /// New full name.
    pub full_name: Option<String>,
    /// New account status.
    pub status: Option<UserStatus>,
    /// New set of role identifiers.
    pub roles: Option<Vec<String>>,
    /// New set of group identifiers.
    pub groups: Option<Vec<String>>,
    /// Updated attributes map.
    pub attributes: Option<HashMap<String, serde_json::Value>>,
}

/// Privileged access request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedAccessRequest {
    /// The user requesting elevated privileges.
    pub user_id: Uuid,
    /// The specific resource or scope requested.
    pub resource: String,
    /// The type of privilege requested.
    pub access_type: PrivilegedAccessType,
    /// Requested duration in minutes.
    pub duration_minutes: u32,
    /// Business reason for the request.
    pub justification: String,
    /// Optional identifier of the approver.
    pub approver_id: Option<Uuid>,
}

/// Types of elevated access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegedAccessType {
    /// Full administrative privileges.
    Admin,
    /// Unrestricted system-wide privileges.
    SuperAdmin,
    /// Emergency "break-glass" access.
    Emergency,
    /// Time-bound access for a specific task.
    Temporary,
}

/// Privileged access grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedAccessGrant {
    /// Unique identifier for the grant.
    pub id: Uuid,
    /// User granted the privileges.
    pub user_id: Uuid,
    /// Resource or scope granted.
    pub resource: String,
    /// Type of privilege granted.
    pub access_type: PrivilegedAccessType,
    /// Timestamp when access was granted.
    pub granted_at: DateTime<Utc>,
    /// Timestamp when access expires.
    pub expires_at: DateTime<Utc>,
    /// User identifier of the grantor.
    pub granted_by: Uuid,
    /// Recorded justification.
    pub justification: String,
}

/// Session request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    /// Client IP address.
    pub ip_address: String,
    /// Client user agent string.
    pub user_agent: String,
    /// Whether to persist the session across browser restarts.
    pub remember_me: bool,
}

/// User list filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListFilters {
    /// Filter by user status.
    pub status: Option<UserStatus>,
    /// Filter by assigned roles.
    pub roles: Option<Vec<String>>,
    /// Filter by group membership.
    pub groups: Option<Vec<String>>,
    /// Filter by creation date.
    pub created_after: Option<DateTime<Utc>>,
    /// Filter by creation date.
    pub created_before: Option<DateTime<Utc>>,
    /// Maximum number of users to return.
    pub limit: Option<usize>,
    /// Number of users to skip for pagination.
    pub offset: Option<usize>,
}

/// Metadata about a client application or device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Network address of the client.
    pub ip_address: String,
    /// Software identifier of the client.
    pub user_agent: String,
    /// Unique hardware or platform identifier.
    pub device_id: Option<String>,
    /// Estimated geographic location of the client.
    pub location: Option<String>,
}

impl Default for IAMConfig {
    fn default() -> Self {
        Self {
            enabled_identity_providers: vec![
                IdentityProviderType::SAML,
                IdentityProviderType::OAuth2,
            ],
            session_timeout_minutes: 480, // 8 hours
            mfa_requirements: MFARequirements::default(),
            password_policy: PasswordPolicy::default(),
            access_control: AccessControlConfig::default(),
            audit_settings: AuditSettings::default(),
        }
    }
}

impl Default for MFARequirements {
    fn default() -> Self {
        Self {
            enabled: true,
            required_for_admin: true,
            required_for_privileged: true,
            grace_period_hours: 24,
            allowed_methods: vec![MFAMethod::TOTP, MFAMethod::SMS, MFAMethod::PushNotification],
        }
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            password_history: 12,
            expiration_days: 90,
            lockout_threshold: 5,
            lockout_duration_minutes: 30,
        }
    }
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            default_access_level: AccessLevel::Read,
            rbac_enabled: true,
            abac_enabled: false,
            jit_enabled: true,
            access_review_frequency_days: 90,
        }
    }
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            log_authentication: true,
            log_authorization: true,
            log_user_management: true,
            log_privileged_access: true,
            retention_days: 2555, // 7 years
        }
    }
}

impl Default for IAMStats {
    fn default() -> Self {
        Self {
            total_users: 0,
            active_users: 0,
            authentication_events: 0,
            failed_authentications: 0,
            authorization_decisions: 0,
            denied_access_attempts: 0,
            privileged_access_requests: 0,
            mfa_challenges: 0,
            last_update: Utc::now(),
        }
    }
}

impl Default for User {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            username: String::new(),
            email: String::new(),
            full_name: String::new(),
            status: UserStatus::Inactive,
            roles: Vec::new(),
            groups: Vec::new(),
            attributes: HashMap::new(),
            created_at: Utc::now(),
            last_login: None,
            password_last_changed: None,
            mfa_enrolled: false,
            mfa_methods: Vec::new(),
        }
    }
}
