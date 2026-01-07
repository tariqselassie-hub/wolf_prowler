//! Dashboard Middleware Module
//!
//! This module provides middleware for the dashboard API.

pub mod auth;

pub use auth::{api_key_auth_middleware, combined_auth_middleware, session_auth_middleware};
