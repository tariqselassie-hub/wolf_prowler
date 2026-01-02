// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/infrastructure/persistence/postgres_auth_repository.rs
use crate::domain::entities::auth::{Permission, Role, User};
use crate::domain::error::DomainError;
use crate::domain::repositories::AuthRepository;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use uuid::Uuid;

pub struct PostgresAuthRepository {
    pool: PgPool,
}

impl PostgresAuthRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthRepository for PostgresAuthRepository {
    async fn save_user(&self, user: &User) -> Result<(), DomainError> {
        let roles_json = serde_json::to_value(&user.roles)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, roles, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
                username = $2,
                password_hash = $3,
                roles = $4,
                is_active = $5,
                updated_at = $7
            "#,
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(roles_json)
        .bind(user.is_active)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        Ok(())
    }

    async fn find_user_by_id(&self, id: &Uuid) -> Result<Option<User>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, roles, is_active, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        if let Some(row) = row {
            let roles: HashSet<String> = serde_json::from_value(row.try_get("roles")?)?;

            Ok(Some(User {
                id: row.try_get("id")?,
                username: row.try_get("username")?,
                password_hash: row.try_get("password_hash")?,
                roles,
                is_active: row.try_get("is_active")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            }))
        } else {
            Ok(None)
        }
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, roles, is_active, created_at, updated_at
            FROM users
            WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        if let Some(row) = row {
            let roles: HashSet<String> = serde_json::from_value(row.try_get("roles")?)?;

            Ok(Some(User {
                id: row.try_get("id")?,
                username: row.try_get("username")?,
                password_hash: row.try_get("password_hash")?,
                roles,
                is_active: row.try_get("is_active")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            }))
        } else {
            Ok(None)
        }
    }

    async fn save_role(&self, role: &Role) -> Result<(), DomainError> {
        let permissions_json = serde_json::to_value(&role.permissions)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO roles (id, name, permissions)
            VALUES ($1, $2, $3)
            ON CONFLICT (id) DO UPDATE SET
                name = $2,
                permissions = $3
            "#,
        )
        .bind(role.id)
        .bind(&role.name)
        .bind(permissions_json)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        Ok(())
    }

    async fn find_role_by_name(&self, name: &str) -> Result<Option<Role>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, permissions
            FROM roles
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        if let Some(row) = row {
            let permissions: HashSet<Permission> =
                serde_json::from_value(row.try_get("permissions")?)?;

            Ok(Some(Role {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                permissions,
            }))
        } else {
            Ok(None)
        }
    }
}
