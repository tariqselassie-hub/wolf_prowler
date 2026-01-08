use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

/// Represents a permission in the system.
/// This is a pure domain entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Permission(String);

impl Permission {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Represents a role that groups multiple permissions for simplified management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique identifier for the role.
    pub id: Uuid,
    /// Human-readable name of the role (e.g., "admin", "operator").
    pub name: String,
    /// Set of specific functional permissions granted to this role.
    pub permissions: HashSet<Permission>,
}

/// Represents a user identity within the security system.
///
/// Note: The `password_hash` field should contain a cryptographically secure hash,
/// never plaintext. Password hashing is handled at the infrastructure layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user.
    pub id: Uuid,
    /// Unique login name for the user.
    pub username: String,
    /// Securely hashed representation of the user's password.
    pub password_hash: String,
    /// Set of role names assigned to the user, controlling system access.
    pub roles: HashSet<String>,
    /// Whether the user is currently permitted to log in.
    pub is_active: bool,
    /// Point in time when the user account was created.
    pub created_at: DateTime<Utc>,
    /// Last time the user account details were modified.
    pub updated_at: DateTime<Utc>,
}
