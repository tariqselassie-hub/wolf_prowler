// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/application/dtos/auth_dto.rs
use crate::domain::entities::User;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashSet;
use uuid::Uuid;

/// Data Transfer Object for a User, for safe exposure via APIs.
#[derive(Debug, Serialize)]
pub struct UserDto<'a> {
    pub id: Uuid,
    pub username: Cow<'a, str>,
    pub roles: HashSet<String>,
    pub is_active: bool,
}

impl From<User> for UserDto<'static> {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: Cow::Owned(user.username),
            roles: user.roles,
            is_active: user.is_active,
        }
    }
}

impl<'a> From<&'a User> for UserDto<'a> {
    fn from(user: &'a User) -> Self {
        Self {
            id: user.id,
            username: Cow::Borrowed(&user.username),
            roles: user.roles.clone(),
            is_active: user.is_active,
        }
    }
}
