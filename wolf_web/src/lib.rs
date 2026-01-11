//! Wolf Web Dashboard
//!
//! This crate provides the web dashboard for Wolf Prowler, including REST APIs,
//! WebSocket connections, and visualization of security metrics and network status.

pub mod dashboard;
/// Shared types for dashboard and API
pub mod types;
pub use types::*;
// pub use dashboard::api::ApiError;
pub mod globals;
