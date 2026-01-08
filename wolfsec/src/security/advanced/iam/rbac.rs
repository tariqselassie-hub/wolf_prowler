//! Role-Based Access Control (RBAC) System
//!
//! Fine-grained permission system with wolf pack hierarchy principles.
//! Wolves maintain strict pack hierarchy with clear access controls and roles.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;

use crate::security::advanced::iam::{
    AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig,
};

/// Definitive set of operations that can be performed on protected system resources
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceAction {
    /// Capability to view or retrieve resource state
    Read,
    /// Capability to modify or update existing resource state
    Write,
    /// Capability to remove or destroy resource state
    Delete,
    /// Full management capabilities within a specific resource scope
    Admin,
    /// Absolute administrative control over all aspects of a resource
    SuperAdmin,
    /// Proprietary action string for domain-specific security rules
    Custom(String),
}

/// Classification of assets and functional areas protected by the IAM system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceType {
    /// Central command and monitoring interface
    Dashboard,
    /// P2P networking and swarm communication layer
    Network,
    /// Threat detection and cryptographic sub-systems
    Security,
    /// Core operating system and hardware interactions
    System,
    /// Identity lifecycles, roles, and credential management
    UserManagement,
    /// Immutable record of system events and security decisions
    Audit,
    /// Global and module-specific settings registry
    Configuration,
    /// Specialized or extended resource type defined by an integration
    Custom(String),
}

/// An atomic unit of authorization defining an allowable action on a specific resource type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Permission {
    /// Unique internal identifier for the permission definition
    pub id: Uuid,
    /// The category of resource this permission applies to
    pub resource_type: ResourceType,
    /// The specific operation permitted by this definition
    pub action: ResourceAction,
    /// Optional specific resource instance ID for fine-grained object-level access
    pub resource_id: Option<String>,
    /// Human-readable name for the permission
    pub name: String,
    /// Detailed explanation of what this permission enables
    pub description: String,
    /// Point in time when the permission was initially defined
    pub created_at: DateTime<Utc>,
    /// Most recent update to the name or description of this permission
    pub updated_at: DateTime<Utc>,
}

/// A logical collection of permissions assigned to users, adhering to the wolf pack hierarchy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    /// Unique internal identifier for the role
    pub id: Uuid,
    /// Descriptive name (e.g., "Security Auditor")
    pub name: String,
    /// Detailed purpose and scope of the role
    pub description: String,
    /// numeric hierarchy level (0-100) where higher values allow inheritance and override
    pub hierarchy_level: u8,
    /// The wolf pack tier this role occupies
    pub wolf_role_type: WolfRoleType,
    /// Set of unique permission IDs directly granted to this role
    pub permissions: HashSet<Uuid>,
    /// IDs of roles from which this role inherits additional permissions
    pub inherited_roles: HashSet<Uuid>,
    /// When the role was first defined
    pub created_at: DateTime<Utc>,
    /// When the role's definition or permissions were last altered
    pub updated_at: DateTime<Utc>,
    /// If false, users assigned this role will not receive its permissions during evaluation
    pub active: bool,
}

/// Categorization of roles according to the traditional Wolf Pack hierarchy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WolfRoleType {
    /// Command tier: Absolute administrative control over the entire ecosystem
    Alpha,
    /// Executive tier: High-level administration for senior personnel and leads
    Beta,
    /// Engineering tier: Professional administrators and dedicated security analysts
    Gamma,
    /// Operator tier: Standard authenticated users and system operators
    Delta,
    /// Observation tier: Fundamental restricted access for read-only viewing
    Omega,
    /// Reconnaissance tier: Specialized access for auditing and external monitoring
    Scout,
    /// Tactical tier: Operational access for incident responders and SOC personnel
    Hunter,
    /// Defense tier: Specialized security engineering and DevSecOps access
    Sentinel,
    /// Unclassified or dynamically defined pack role
    Custom,
}

/// Records the granting of a role to a specific identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRole {
    /// The identity receiving the permissions
    pub user_id: Uuid,
    /// The role metadata being applied
    pub role_id: Uuid,
    /// Documented justification for the assignment
    pub reason: String,
    /// The identity that authorized this assignment
    pub assigned_by: Uuid,
    /// Precise point in time when the assignment was authorized
    pub assigned_at: DateTime<Utc>,
    /// Optional deadline after which the assignment naturally expires
    pub expires_at: Option<DateTime<Utc>>,
    /// If false, the assignment is administratively suspended
    pub active: bool,
}

/// The finalized outcome and justification of an access control evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDecision {
    /// Unique internal identifier for the decision record
    pub id: Uuid,
    /// The identity for whom the decision was rendered
    pub user_id: Uuid,
    /// The category of resource targeted in the request
    pub resource_type: ResourceType,
    /// The specific action evaluated
    pub action: ResourceAction,
    /// Precise instance identifier of the resource, if object-level access was checked
    pub resource_id: Option<String>,
    /// Formal grant or denial of access
    pub decision: AccessDecisionType,
    /// Detailed policy-driven explanation for the decision
    pub reason: String,
    /// List of role identifiers that influenced this evaluation
    pub applied_roles: Vec<Uuid>,
    /// List of specific permission identifiers that satisfied the request
    pub applied_permissions: Vec<Uuid>,
    /// Precise point in time when the evaluation occurred
    pub timestamp: DateTime<Utc>,
    /// requester environment snapshot at time of decision
    pub client_info: Option<ClientInfo>,
}

/// Primary outcomes of an access control evaluation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessDecisionType {
    /// Access is formally authorized
    Allow,
    /// Access is formally rejected
    Deny,
}

/// Central engine for managing and evaluating role-based permissions and hierarchies
pub struct RBACManager {
    /// Thread-safe localized registry of all system-defined roles
    roles: Arc<Mutex<HashMap<Uuid, Role>>>,
    /// Thread-safe localized registry of all atomic permissions
    permissions: Arc<Mutex<HashMap<Uuid, Permission>>>,
    /// Multi-map of active role assignments for each user identity
    user_roles: Arc<Mutex<HashMap<Uuid, Vec<UserRole>>>>,
    /// Global IAM configuration settings
    config: IAMConfig,
    /// Thread-safe cache of recent evaluation outcomes to improve performance
    access_cache: Arc<Mutex<HashMap<String, AccessDecision>>>,
}

/// Encapsulated parameters for a formal authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBACQuery {
    /// The user identity requesting authorization
    pub user_id: Uuid,
    /// The target resource category
    pub resource_type: ResourceType,
    /// The specific operation being attempted
    pub action: ResourceAction,
    /// Identifier for a specific resource instance if required for the check
    pub resource_id: Option<String>,
    /// Environmental context of the requester
    pub client_info: Option<ClientInfo>,
}

/// System-wide summary of the RBAC engine's current state and workload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBACStats {
    /// Count of distinctly defined roles in the registry
    pub total_roles: usize,
    /// Count of distinctly defined permissions in the registry
    pub total_permissions: usize,
    /// Count of active user-role assignments across the ecosystem
    pub total_user_roles: usize,
    /// Current number of entries reside in the evaluation cache
    pub active_decisions: usize,
    /// Timestamp of the most recent statistics calculation
    pub last_update: DateTime<Utc>,
}

impl RBACManager {
    /// Initializes a new `RBACManager` and establishes the default system-level roles and permissions.
    ///
    /// # Errors
    /// Returns an error if initialization or default role creation fails.
    pub async fn new(config: IAMConfig) -> Result<Self> {
        info!("🔐 Initializing RBAC Manager");

        let manager = Self {
            roles: Arc::new(Mutex::new(HashMap::new())),
            permissions: Arc::new(Mutex::new(HashMap::new())),
            user_roles: Arc::new(Mutex::new(HashMap::new())),
            config,
            access_cache: Arc::new(Mutex::new(HashMap::new())),
        };

        // Initialize default roles and permissions
        manager.initialize_default_roles().await?;

        info!("✅ RBAC Manager initialized successfully");
        Ok(manager)
    }

    /// Initialize default roles and permissions
    async fn initialize_default_roles(&self) -> Result<()> {
        info!("🔐 Initializing default RBAC roles and permissions");

        // Create default permissions
        let permissions = vec![
            Permission {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000001")?,
                resource_type: ResourceType::Dashboard,
                action: ResourceAction::Read,
                resource_id: None,
                name: "dashboard:read".to_string(),
                description: "Read access to dashboard".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Permission {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000002")?,
                resource_type: ResourceType::Dashboard,
                action: ResourceAction::Write,
                resource_id: None,
                name: "dashboard:write".to_string(),
                description: "Write access to dashboard".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Permission {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000003")?,
                resource_type: ResourceType::Network,
                action: ResourceAction::Read,
                resource_id: None,
                name: "network:read".to_string(),
                description: "Read access to network resources".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Permission {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000004")?,
                resource_type: ResourceType::Network,
                action: ResourceAction::Write,
                resource_id: None,
                name: "network:write".to_string(),
                description: "Write access to network resources".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Permission {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000005")?,
                resource_type: ResourceType::Security,
                action: ResourceAction::Read,
                resource_id: None,
                name: "security:read".to_string(),
                description: "Read access to security resources".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Permission {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000006")?,
                resource_type: ResourceType::Security,
                action: ResourceAction::Admin,
                resource_id: None,
                name: "security:admin".to_string(),
                description: "Admin access to security resources".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Permission {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000007")?,
                resource_type: ResourceType::UserManagement,
                action: ResourceAction::Admin,
                resource_id: None,
                name: "user:admin".to_string(),
                description: "Admin access to user management".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Permission {
                id: Uuid::parse_str("00000000-0000-0000-0000-000000000008")?,
                resource_type: ResourceType::Audit,
                action: ResourceAction::Read,
                resource_id: None,
                name: "audit:read".to_string(),
                description: "Read access to audit logs".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ];

        // Store permissions
        let mut permissions_store = self.permissions.lock().await;
        for permission in permissions {
            permissions_store.insert(permission.id, permission);
        }

        // Create default roles
        let alpha_role = Role {
            id: Uuid::parse_str("11111111-1111-1111-1111-111111111111")?,
            name: "Alpha Admin".to_string(),
            description: "Super administrator with full access".to_string(),
            hierarchy_level: 100,
            wolf_role_type: WolfRoleType::Alpha,
            permissions: permissions_store.keys().cloned().collect(),
            inherited_roles: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            active: true,
        };

        let delta_role = Role {
            id: Uuid::parse_str("22222222-2222-2222-2222-222222222222")?,
            name: "Delta User".to_string(),
            description: "Standard user with basic access".to_string(),
            hierarchy_level: 50,
            wolf_role_type: WolfRoleType::Delta,
            permissions: vec![
                Uuid::parse_str("00000000-0000-0000-0000-000000000001")?, // dashboard:read
                Uuid::parse_str("00000000-0000-0000-0000-000000000003")?, // network:read
                Uuid::parse_str("00000000-0000-0000-0000-000000000005")?, // security:read
            ]
            .into_iter()
            .collect(),
            inherited_roles: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            active: true,
        };

        let omega_role = Role {
            id: Uuid::parse_str("33333333-3333-3333-3333-333333333333")?,
            name: "Omega Viewer".to_string(),
            description: "Read-only access for monitoring".to_string(),
            hierarchy_level: 25,
            wolf_role_type: WolfRoleType::Omega,
            permissions: vec![
                Uuid::parse_str("00000000-0000-0000-0000-000000000001")?, // dashboard:read
                Uuid::parse_str("00000000-0000-0000-0000-000000000003")?, // network:read
                Uuid::parse_str("00000000-0000-0000-0000-000000000005")?, // security:read
                Uuid::parse_str("00000000-0000-0000-0000-000000000008")?, // audit:read
            ]
            .into_iter()
            .collect(),
            inherited_roles: HashSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            active: true,
        };

        // Store roles
        let mut roles_store = self.roles.lock().await;
        roles_store.insert(alpha_role.id, alpha_role);
        roles_store.insert(delta_role.id, delta_role);
        roles_store.insert(omega_role.id, omega_role);

        info!("✅ Default RBAC roles and permissions initialized");
        Ok(())
    }

    /// Formally registers a new atomic permission in the global registry.
    ///
    /// # Errors
    /// Returns an error if storage fails.
    pub async fn create_permission(&self, permission: Permission) -> Result<Permission> {
        debug!("🔐 Creating permission: {}", permission.name);

        let mut permissions = self.permissions.lock().await;
        permissions.insert(permission.id, permission.clone());

        info!("✅ Permission created: {}", permission.name);
        Ok(permission)
    }

    /// Formally registers a new collection of permissions and attributes as a role.
    ///
    /// # Errors
    /// Returns an error if storage fails.
    pub async fn create_role(&self, role: Role) -> Result<Role> {
        debug!("🔐 Creating role: {}", role.name);

        let mut roles = self.roles.lock().await;
        roles.insert(role.id, role.clone());

        info!("✅ Role created: {}", role.name);
        Ok(role)
    }

    /// Grants a role to an identity, establishing a link for permission evaluation.
    ///
    /// # Errors
    /// Returns an error if the role is not found, inactive, or assignment fails.
    pub async fn assign_role(
        &self,
        user_id: Uuid,
        role_id: Uuid,
        assigned_by: Uuid,
        reason: String,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRole> {
        debug!("🔐 Assigning role {} to user {}", role_id, user_id);

        // Check if role exists and is active
        let roles = self.roles.lock().await;
        let role = roles
            .get(&role_id)
            .ok_or_else(|| anyhow!("Role not found"))?;
        if !role.active {
            return Err(anyhow!("Role is not active"));
        }
        drop(roles);

        let user_role = UserRole {
            user_id,
            role_id,
            reason,
            assigned_by,
            assigned_at: Utc::now(),
            expires_at,
            active: true,
        };

        let mut user_roles = self.user_roles.lock().await;
        let user_role_list = user_roles.entry(user_id).or_insert_with(Vec::new);
        user_role_list.push(user_role.clone());

        info!("✅ Role {} assigned to user {}", role_id, user_id);
        Ok(user_role)
    }

    /// administratively removes a role from an identity's active permission set.
    ///
    /// # Errors
    /// Returns an error if revocation fails.
    pub async fn revoke_role(&self, user_id: Uuid, role_id: Uuid) -> Result<()> {
        debug!("🔐 Revoking role {} from user {}", role_id, user_id);

        let mut user_roles = self.user_roles.lock().await;
        if let Some(user_role_list) = user_roles.get_mut(&user_id) {
            user_role_list.retain(|ur| ur.role_id != role_id);
        }

        info!("✅ Role {} revoked from user {}", role_id, user_id);
        Ok(())
    }

    /// Evaluates a user request against their assigned roles and effective permission set.
    ///
    /// # Errors
    /// Returns an error if evaluation fails.
    pub async fn check_access(&self, query: RBACQuery) -> Result<AccessDecision> {
        debug!(
            "🔐 Checking access for user {} to {:?} {:?}",
            query.user_id, query.resource_type, query.action
        );

        let user_roles = self.get_user_roles(query.user_id).await?;
        let effective_permissions = self.get_effective_permissions(&user_roles).await?;

        let mut applied_permissions = Vec::new();
        let mut decision = AccessDecisionType::Deny;
        let mut reason = "No matching permissions found".to_string();

        // Check for exact permission match
        for permission in &effective_permissions {
            if permission.resource_type == query.resource_type
                && permission.action == query.action
                && (permission.resource_id.is_none() || permission.resource_id == query.resource_id)
            {
                decision = AccessDecisionType::Allow;
                reason = format!("Permission {} granted", permission.name);
                applied_permissions.push(permission.id);
                break;
            }
        }

        // Check for admin permissions (supercede specific permissions)
        if decision == AccessDecisionType::Deny {
            for permission in &effective_permissions {
                if permission.resource_type == query.resource_type
                    && (permission.action == ResourceAction::Admin
                        || permission.action == ResourceAction::SuperAdmin)
                    && (permission.resource_id.is_none()
                        || permission.resource_id == query.resource_id)
                {
                    decision = AccessDecisionType::Allow;
                    reason = format!("Admin permission {} granted", permission.name);
                    applied_permissions.push(permission.id);
                    break;
                }
            }
        }

        let applied_roles: Vec<Uuid> = user_roles.iter().map(|ur| ur.role_id).collect();

        // Generate cache key before moving fields
        let cache_key = self.generate_cache_key(&query);

        let access_decision = AccessDecision {
            id: Uuid::new_v4(),
            user_id: query.user_id,
            resource_type: query.resource_type,
            action: query.action,
            resource_id: query.resource_id,
            decision,
            reason,
            applied_roles,
            applied_permissions,
            timestamp: Utc::now(),
            client_info: query.client_info,
        };

        // Cache the decision
        let mut cache = self.access_cache.lock().await;
        cache.insert(cache_key, access_decision.clone());

        debug!("✅ Access decision: {:?}", access_decision.decision);
        Ok(access_decision)
    }

    /// Get user roles
    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<UserRole>> {
        let user_roles = self.user_roles.lock().await;
        let user_role_list = user_roles.get(&user_id).cloned().unwrap_or_default();

        // Filter active and non-expired roles
        let now = Utc::now();
        let active_roles: Vec<UserRole> = user_role_list
            .into_iter()
            .filter(|ur| ur.active && ur.expires_at.map_or(true, |exp| exp > now))
            .collect();

        Ok(active_roles)
    }

    /// Get effective permissions for user roles
    async fn get_effective_permissions(&self, user_roles: &[UserRole]) -> Result<Vec<Permission>> {
        let roles = self.roles.lock().await;
        let permissions = self.permissions.lock().await;

        let mut effective_permissions = HashSet::new();

        for user_role in user_roles {
            if let Some(role) = roles.get(&user_role.role_id) {
                // Add direct permissions
                for permission_id in &role.permissions {
                    if let Some(permission) = permissions.get(permission_id) {
                        effective_permissions.insert(permission.clone());
                    }
                }

                // Add inherited role permissions
                for inherited_role_id in &role.inherited_roles {
                    if let Some(inherited_role) = roles.get(inherited_role_id) {
                        for permission_id in &inherited_role.permissions {
                            if let Some(permission) = permissions.get(permission_id) {
                                effective_permissions.insert(permission.clone());
                            }
                        }
                    }
                }
            }
        }

        Ok(effective_permissions.into_iter().collect())
    }

    /// Generate cache key for access decision
    fn generate_cache_key(&self, query: &RBACQuery) -> String {
        format!(
            "{}:{:?}:{:?}:{:?}",
            query.user_id,
            query.resource_type,
            query.action,
            query.resource_id.as_deref().unwrap_or("any")
        )
    }

    /// Retrieves current system-wide metrics and workload information for the RBAC engine.
    pub async fn get_stats(&self) -> RBACStats {
        let roles = self.roles.lock().await;
        let permissions = self.permissions.lock().await;
        let user_roles = self.user_roles.lock().await;
        let access_cache = self.access_cache.lock().await;

        let total_user_roles = user_roles.values().map(|ur| ur.len()).sum();

        RBACStats {
            total_roles: roles.len(),
            total_permissions: permissions.len(),
            total_user_roles,
            active_decisions: access_cache.len(),
            last_update: Utc::now(),
        }
    }

    /// Aggregates all atomic permissions granted to a user via their active direct and inherited roles.
    pub async fn list_user_permissions(&self, user_id: Uuid) -> Result<Vec<Permission>> {
        let user_roles = self.get_user_roles(user_id).await?;
        self.get_effective_permissions(&user_roles).await
    }

    /// Convenience method to perform a single-permission authorization check for a user.
    pub async fn user_has_permission(
        &self,
        user_id: Uuid,
        resource_type: ResourceType,
        action: ResourceAction,
        resource_id: Option<String>,
    ) -> Result<bool> {
        let query = RBACQuery {
            user_id,
            resource_type,
            action,
            resource_id,
            client_info: None,
        };

        let decision = self.check_access(query).await?;
        Ok(decision.decision == AccessDecisionType::Allow)
    }

    /// Scans the assignment registry and removes role links that have passed their expiration deadline.
    pub async fn cleanup_expired_roles(&self) -> Result<()> {
        let mut user_roles = self.user_roles.lock().await;
        let now = Utc::now();

        for user_role_list in user_roles.values_mut() {
            user_role_list.retain(|ur| ur.expires_at.map_or(true, |exp| exp > now));
        }

        info!("✅ Expired role assignments cleaned up");
        Ok(())
    }

    /// Retrieves a complete role definition snapshot from the registry.
    pub async fn get_role(&self, role_id: Uuid) -> Option<Role> {
        let roles = self.roles.lock().await;
        roles.get(&role_id).cloned()
    }

    /// Retrieves a specific permission definition snapshot from the registry.
    pub async fn get_permission(&self, permission_id: Uuid) -> Option<Permission> {
        let permissions = self.permissions.lock().await;
        permissions.get(&permission_id).cloned()
    }
}

impl From<AccessDecision> for AuthenticationResult {
    fn from(decision: AccessDecision) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: decision.user_id,
            method: AuthenticationMethod::RBAC,
            success: decision.decision == AccessDecisionType::Allow,
            timestamp: decision.timestamp,
            ip_address: decision
                .client_info
                .as_ref()
                .map(|ci| ci.ip_address.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            user_agent: decision
                .client_info
                .as_ref()
                .map(|ci| ci.user_agent.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            mfa_required: false,
            mfa_completed: true,
            session_id: None,
            error_message: if decision.decision == AccessDecisionType::Deny {
                Some(decision.reason)
            } else {
                None
            },
        }
    }
}
