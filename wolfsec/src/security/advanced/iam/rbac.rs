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
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::security::advanced::iam::{
    AuthenticationManager, AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig,
    SessionRequest, UserStatus,
};

/// Resource action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceAction {
    /// Read access
    Read,
    /// Write access
    Write,
    /// Delete access
    Delete,
    /// Admin access
    Admin,
    /// Super admin access
    SuperAdmin,
    /// Custom action
    Custom(String),
}

/// Resource type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceType {
    /// Dashboard access
    Dashboard,
    /// Network resources
    Network,
    /// Security resources
    Security,
    /// System resources
    System,
    /// User management
    UserManagement,
    /// Audit logs
    Audit,
    /// Configuration
    Configuration,
    /// Custom resource
    Custom(String),
}

/// Permission entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Permission {
    /// Permission ID
    pub id: Uuid,
    /// Resource type
    pub resource_type: ResourceType,
    /// Resource action
    pub action: ResourceAction,
    /// Resource ID (optional, for specific resource access)
    pub resource_id: Option<String>,
    /// Permission name
    pub name: String,
    /// Permission description
    pub description: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub updated_at: DateTime<Utc>,
}

/// Role entity with wolf pack hierarchy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    /// Role ID
    pub id: Uuid,
    /// Role name
    pub name: String,
    /// Role description
    pub description: String,
    /// Wolf pack hierarchy level (0-100, higher = more privileges)
    pub hierarchy_level: u8,
    /// Wolf-themed role type
    pub wolf_role_type: WolfRoleType,
    /// Permissions
    pub permissions: HashSet<Uuid>,
    /// Inherited roles
    pub inherited_roles: HashSet<Uuid>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub updated_at: DateTime<Utc>,
    /// Active status
    pub active: bool,
}

/// Wolf-themed role types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WolfRoleType {
    /// Alpha wolf - highest privileges (CEO, CTO, Security Admin)
    Alpha,
    /// Beta wolves - high privileges (Senior Admins, Team Leads)
    Beta,
    /// Gamma wolves - medium privileges (Regular Admins, Security Analysts)
    Gamma,
    /// Delta wolves - standard privileges (Regular Users, Operators)
    Delta,
    /// Omega wolves - basic privileges (Read-only users, Viewers)
    Omega,
    /// Scout wolves - reconnaissance privileges (Auditors, Monitors)
    Scout,
    /// Hunter wolves - operational privileges (Incident Responders, SOC)
    Hunter,
    /// Sentinel wolves - security privileges (Security Engineers, DevSecOps)
    Sentinel,
    /// Custom role
    Custom,
}

/// User role assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRole {
    /// User ID
    pub user_id: Uuid,
    /// Role ID
    pub role_id: Uuid,
    /// Assignment reason
    pub reason: String,
    /// Assigned by
    pub assigned_by: Uuid,
    /// Assigned at
    pub assigned_at: DateTime<Utc>,
    /// Expires at (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Active status
    pub active: bool,
}

/// Access control decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDecision {
    /// Decision ID
    pub id: Uuid,
    /// User ID
    pub user_id: Uuid,
    /// Resource type
    pub resource_type: ResourceType,
    /// Resource action
    pub action: ResourceAction,
    /// Resource ID
    pub resource_id: Option<String>,
    /// Decision (allow/deny)
    pub decision: AccessDecisionType,
    /// Reason for decision
    pub reason: String,
    /// Applied roles
    pub applied_roles: Vec<Uuid>,
    /// Applied permissions
    pub applied_permissions: Vec<Uuid>,
    /// Decision timestamp
    pub timestamp: DateTime<Utc>,
    /// Client info
    pub client_info: Option<ClientInfo>,
}

/// Access decision type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessDecisionType {
    /// Access granted
    Allow,
    /// Access denied
    Deny,
}

/// RBAC manager
pub struct RBACManager {
    /// Roles storage
    roles: Arc<Mutex<HashMap<Uuid, Role>>>,
    /// Permissions storage
    permissions: Arc<Mutex<HashMap<Uuid, Permission>>>,
    /// User roles storage
    user_roles: Arc<Mutex<HashMap<Uuid, Vec<UserRole>>>>,
    /// Configuration
    config: IAMConfig,
    /// Access decisions cache
    access_cache: Arc<Mutex<HashMap<String, AccessDecision>>>,
}

/// RBAC query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBACQuery {
    /// User ID
    pub user_id: Uuid,
    /// Resource type
    pub resource_type: ResourceType,
    /// Resource action
    pub action: ResourceAction,
    /// Resource ID (optional)
    pub resource_id: Option<String>,
    /// Client info (for context-based decisions)
    pub client_info: Option<ClientInfo>,
}

/// RBAC statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RBACStats {
    /// Total roles
    pub total_roles: usize,
    /// Total permissions
    pub total_permissions: usize,
    /// Total user-role assignments
    pub total_user_roles: usize,
    /// Active access decisions
    pub active_decisions: usize,
    /// Last update
    pub last_update: DateTime<Utc>,
}

impl RBACManager {
    /// Create new RBAC manager
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

    /// Create permission
    pub async fn create_permission(&self, permission: Permission) -> Result<Permission> {
        debug!("🔐 Creating permission: {}", permission.name);

        let mut permissions = self.permissions.lock().await;
        permissions.insert(permission.id, permission.clone());

        info!("✅ Permission created: {}", permission.name);
        Ok(permission)
    }

    /// Create role
    pub async fn create_role(&self, role: Role) -> Result<Role> {
        debug!("🔐 Creating role: {}", role.name);

        let mut roles = self.roles.lock().await;
        roles.insert(role.id, role.clone());

        info!("✅ Role created: {}", role.name);
        Ok(role)
    }

    /// Assign role to user
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

    /// Revoke role from user
    pub async fn revoke_role(&self, user_id: Uuid, role_id: Uuid) -> Result<()> {
        debug!("🔐 Revoking role {} from user {}", role_id, user_id);

        let mut user_roles = self.user_roles.lock().await;
        if let Some(user_role_list) = user_roles.get_mut(&user_id) {
            user_role_list.retain(|ur| ur.role_id != role_id);
        }

        info!("✅ Role {} revoked from user {}", role_id, user_id);
        Ok(())
    }

    /// Check access
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

    /// Get RBAC statistics
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

    /// List user permissions
    pub async fn list_user_permissions(&self, user_id: Uuid) -> Result<Vec<Permission>> {
        let user_roles = self.get_user_roles(user_id).await?;
        self.get_effective_permissions(&user_roles).await
    }

    /// Check if user has specific permission
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

    /// Clean up expired role assignments
    pub async fn cleanup_expired_roles(&self) -> Result<()> {
        let mut user_roles = self.user_roles.lock().await;
        let now = Utc::now();

        for user_role_list in user_roles.values_mut() {
            user_role_list.retain(|ur| ur.expires_at.map_or(true, |exp| exp > now));
        }

        info!("✅ Expired role assignments cleaned up");
        Ok(())
    }

    /// Get role by ID
    pub async fn get_role(&self, role_id: Uuid) -> Option<Role> {
        let roles = self.roles.lock().await;
        roles.get(&role_id).cloned()
    }

    /// Get permission by ID
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
