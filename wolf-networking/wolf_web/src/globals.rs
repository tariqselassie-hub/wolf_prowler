//! Global state module for Wolf Web
//!
//! This module contains global static variables that hold the application state.
//! They are exposed to allow integration tests to inject mock or real instances.

use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

#[cfg(feature = "server")]
use crate::dashboard::state::AppState;
#[cfg(feature = "server")]
use lock_prowler::headless::HeadlessWolfProwler;
#[cfg(feature = "server")]
use wolfsec::identity::iam::SSOIntegrationManager;

// Global state variables
// These are lazy-initialized static mutexes that hold the application state.
// They are pub so they can be accessed by both the main application and integration tests.

/// Global Headless Wolf Prowler instance
#[cfg(feature = "server")]
pub static PROWLER: Lazy<AsyncMutex<Option<HeadlessWolfProwler>>> =
    Lazy::new(|| AsyncMutex::new(None));

/// Global SSO Manager instance
#[cfg(feature = "server")]
pub static SSO_MANAGER: Lazy<AsyncMutex<Option<SSOIntegrationManager>>> =
    Lazy::new(|| AsyncMutex::new(None));

/// Global Application State
#[cfg(feature = "server")]
pub static APP_STATE: Lazy<AsyncMutex<Option<AppState>>> = Lazy::new(|| AsyncMutex::new(None));

use tokio::sync::RwLock;

/// Global Wolf Security Engine
#[cfg(feature = "server")]
pub static SECURITY_ENGINE: Lazy<AsyncMutex<Option<Arc<RwLock<wolfsec::WolfSecurity>>>>> =
    Lazy::new(|| AsyncMutex::new(None));

/// Global Swarm Manager
#[cfg(feature = "server")]
pub static SWARM_MANAGER: Lazy<AsyncMutex<Option<Arc<wolf_net::SwarmManager>>>> =
    Lazy::new(|| AsyncMutex::new(None));
