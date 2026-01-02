use crate::domain::entities::auth::{Role, User};
use crate::domain::error::DomainError;
use async_trait::async_trait;
use uuid::Uuid;

/// A port for storing and retrieving user and role data.
#[async_trait]
pub trait AuthRepository: Send + Sync {
    // --- User Methods ---
    async fn save_user(&self, user: &User) -> Result<(), DomainError>;
    async fn find_user_by_id(&self, id: &Uuid) -> Result<Option<User>, DomainError>;
    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, DomainError>;

    // --- Role Methods ---
    async fn save_role(&self, role: &Role) -> Result<(), DomainError>;
    async fn find_role_by_name(&self, name: &str) -> Result<Option<Role>, DomainError>;
}
