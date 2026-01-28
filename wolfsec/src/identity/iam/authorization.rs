use crate::identity::iam::{
    AuthorizationDecision, AuthorizationRequest, Effect, IAMConfig, Permission,
};
use crate::wolf_pack::hierarchy::PackRank;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tracing::{debug, warn};
use uuid::Uuid;

/// Manages access control logic and evaluates authorization requests across ecosystem
pub struct AuthorizationManager {
    /// Global configuration for IAM system
    config: IAMConfig,
    /// In-memory role to permission mappings
    role_permissions: HashMap<String, Vec<Permission>>,
    /// User role cache for performance
    user_roles: HashMap<String, Vec<String>>,
}

impl AuthorizationManager {
    /// Creates a new instance of `AuthorizationManager` with the given configuration.
    ///
    /// # Errors
    /// Returns an error if initialization fails.
    pub fn new(config: IAMConfig) -> Result<Self> {
        let mut manager = Self {
            config,
            role_permissions: HashMap::new(),
            user_roles: HashMap::new(),
        };
        manager.initialize_default_roles()?;
        Ok(manager)
    }

    /// Evaluates an authorization request to determine if an action should be permitted.
    ///
    /// # Errors
    /// Returns an error if authorization check fails or request is invalid.
    pub async fn authorize(&self, request: AuthorizationRequest) -> Result<AuthorizationDecision> {
        debug!("Authorization request: user={}, resource={}, action={}", 
               request.user_id, request.resource, request.action);

        // Get user roles from cache or request context
        let user_roles = self.get_user_roles(&request.user_id.to_string()).await?;
        
        // Check if user has any roles (anonymous users get no access)
        if user_roles.is_empty() {
            warn!("Unauthorized access attempt by user: {}", request.user_id);
            return Ok(AuthorizationDecision {
                id: Uuid::new_v4(),
                user_id: request.user_id,
                resource: request.resource,
                action: request.action,
                decision: Effect::Deny,
                timestamp: Utc::now(),
                reason: "User has no assigned roles".to_string(),
                applied_policies: Vec::new(),
            });
        }

        // Check each role for required permissions
        for role in &user_roles {
            if let Some(permissions) = self.role_permissions.get(role) {
                for permission in permissions {
                    if self.matches_permission(&request, permission) {
                        debug!("Access granted to {} via role {}", request.user_id, role);
                        return Ok(AuthorizationDecision {
                            id: Uuid::new_v4(),
                            user_id: request.user_id,
                            resource: request.resource,
                            action: request.action,
                            decision: Effect::Allow,
                            timestamp: Utc::now(),
                            reason: format!("Granted via role: {}", role),
                            applied_policies: vec![permission.name.clone()],
                        });
                    }
                }
            }
        }

        // No matching permission found - deny access
        warn!("Access denied for user {} to {} on {}", 
              request.user_id, request.action, request.resource);
        
        Ok(AuthorizationDecision {
            id: Uuid::new_v4(),
            user_id: request.user_id,
            resource: request.resource,
            action: request.action,
            decision: Effect::Deny,
            timestamp: Utc::now(),
            reason: "No matching permission found".to_string(),
            applied_policies: Vec::new(),
        })
    }

    /// Derives a set of effective permissions for a wolf based on their rank within the pack hierarchy.
    ///
    /// This follows a cascading permission model:
    /// - **Omega**: Read-only access to base non-sensitive resources.
    /// - **Scout**: Read/Write access to standard project and job resources.
    /// - **Hunter**: Control over infrastructure resources and pipelines.
    /// - **Beta**: Full administrative control over security, users, and audit logs.
    /// - **Alpha**: Absolute "Super Admin" power over the entire system.
    pub fn get_effective_permissions(&self, rank: PackRank) -> Vec<Permission> {
        let mut permissions = Vec::new();

        // Base permissions for everyone (Omega+)
        permissions.push(self.create_permission("base_read", "*", "read"));

        if rank >= PackRank::Scout {
            permissions.push(self.create_permission("standard_write", "projects/*", "write"));
            permissions.push(self.create_permission("standard_execute", "jobs/*", "execute"));
        }

        if rank >= PackRank::Hunter {
            permissions.push(self.create_permission("infra_read", "infrastructure/*", "read"));
            permissions.push(self.create_permission("pipeline_control", "pipelines/*", "manage"));
        }

        if rank >= PackRank::Beta {
            permissions.push(self.create_permission("security_admin", "security/*", "*"));
            permissions.push(self.create_permission("user_admin", "users/*", "manage"));
            permissions.push(self.create_permission("audit_log", "audit/*", "read"));
        }

        if rank >= PackRank::Alpha {
            permissions.push(self.create_permission("super_admin", "*", "*"));
        }

        permissions
    }

    fn create_permission(&self, name: &str, resource: &str, action: &str) -> Permission {
        Permission {
            id: Uuid::new_v4(),
            name: name.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            effect: Effect::Allow,
            conditions: Vec::new(),
        }
    }

    /// Initialize default role-based permissions
    fn initialize_default_roles(&mut self) -> Result<()> {
        // Omega role - basic read access
        self.role_permissions.insert("omega".to_string(), vec![
            self.create_permission("base_read", "public/*", "read"),
            self.create_permission("profile_read", "profile/*", "read"),
        ]);

        // Scout role - standard user permissions
        self.role_permissions.insert("scout".to_string(), vec![
            self.create_permission("base_read", "public/*", "read"),
            self.create_permission("profile_read", "profile/*", "read"),
            self.create_permission("project_read", "projects/*", "read"),
            self.create_permission("job_execute", "jobs/*", "execute"),
        ]);

        // Hunter role - infrastructure control
        self.role_permissions.insert("hunter".to_string(), vec![
            self.create_permission("base_read", "public/*", "read"),
            self.create_permission("profile_read", "profile/*", "read"),
            self.create_permission("project_manage", "projects/*", "*"),
            self.create_permission("infra_read", "infrastructure/*", "read"),
            self.create_permission("job_manage", "jobs/*", "*"),
            self.create_permission("network_basic", "network/*", "read"),
        ]);

        // Beta role - security administrator
        self.role_permissions.insert("beta".to_string(), vec![
            self.create_permission("base_read", "public/*", "read"),
            self.create_permission("profile_manage", "profile/*", "*"),
            self.create_permission("project_manage", "projects/*", "*"),
            self.create_permission("infra_manage", "infrastructure/*", "*"),
            self.create_permission("job_manage", "jobs/*", "*"),
            self.create_permission("security_admin", "security/*", "*"),
            self.create_permission("user_manage", "users/*", "manage"),
            self.create_permission("audit_read", "audit/*", "read"),
            self.create_permission("network_manage", "network/*", "*"),
        ]);

        // Alpha role - super administrator
        self.role_permissions.insert("alpha".to_string(), vec![
            self.create_permission("super_admin", "*", "*"),
        ]);

        debug!("Initialized {} role permission mappings", self.role_permissions.len());
        Ok(())
    }

    /// Get roles assigned to a user
    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<String>> {
        // In a real implementation, this would query a database or directory service
        // For now, use simple in-memory cache with default fallback
        Ok(self.user_roles
            .get(user_id)
            .cloned()
            .unwrap_or_else(|| {
                // Default to omega role for all authenticated users
                vec!["omega".to_string()]
            }))
    }

    /// Check if a request matches a permission pattern
    fn matches_permission(&self, request: &AuthorizationRequest, permission: &Permission) -> bool {
        // Wildcard resource matching
        let resource_match = permission.resource == "*" 
            || self.matches_pattern(&request.resource, &permission.resource);
        
        // Wildcard action matching
        let action_match = permission.action == "*" 
            || self.matches_pattern(&request.action, &permission.action);
        
        resource_match && action_match
    }

    /// Simple pattern matching for wildcards
    fn matches_pattern(&self, value: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2];
            return value.starts_with(prefix);
        }
        value == pattern
    }

    /// Assign role to user (for administration)
    pub async fn assign_role(&mut self, user_id: &str, role: &str) -> Result<()> {
        if !self.role_permissions.contains_key(role) {
            return Err(anyhow::anyhow!("Unknown role: {}", role));
        }
        
        self.user_roles
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(role.to_string());
        
        debug!("Assigned role '{}' to user '{}'", role, user_id);
        Ok(())
    }
}
