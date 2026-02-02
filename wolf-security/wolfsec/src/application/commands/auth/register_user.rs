use crate::application::error::ApplicationError;
use crate::application::services::password_hasher::PasswordHasher;
use crate::domain::entities::User;
use crate::domain::repositories::AuthRepository;
use anyhow::Context;
use chrono::Utc;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

/// Command to register a new user.
pub struct RegisterUserCommand<'a> {
    pub username: Cow<'a, str>,
    pub password: Cow<'a, str>,
    pub initial_roles: Option<HashSet<String>>,
}

/// Handler for the RegisterUserCommand.
pub struct RegisterUserHandler {
    auth_repo: Arc<dyn AuthRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
}

impl RegisterUserHandler {
    pub fn new(
        auth_repo: Arc<dyn AuthRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
    ) -> Self {
        Self {
            auth_repo,
            password_hasher,
        }
    }

    /// Executes the command to register a new user.
    #[instrument(skip(self, command), fields(username = %command.username))]
    pub async fn handle(&self, command: RegisterUserCommand<'_>) -> Result<Uuid, ApplicationError> {
        // Check if user already exists
        if self
            .auth_repo
            .find_user_by_username(&command.username)
            .await?
            .is_some()
        {
            return Err(ApplicationError::Domain(
                crate::domain::error::DomainError::InvalidInput {
                    field: "username",
                    reason: "A user with this username already exists.".to_string(),
                },
            ));
        }

        let password_hash = self
            .password_hasher
            .hash(&command.password)
            .await
            .context("Failed to hash password")?;

        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            username: command.username.into_owned(),
            password_hash,
            roles: command.initial_roles.unwrap_or_default(),
            is_active: true,
            created_at: now,
            updated_at: now,
        };

        let user_id = user.id;

        self.auth_repo
            .save_user(&user)
            .await
            .context("Failed to save new user in repository")?;

        Ok(user_id)
    }
}
