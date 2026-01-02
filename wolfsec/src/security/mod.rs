//! The top-level security module for Wolf Prowler.
//!
//! This module acts as a container and orchestrator for the various security
//! sub-modules, providing a unified and hierarchical structure. It separates
//! foundational security components from more advanced, layered security features.

pub mod advanced;
pub mod network_security;
pub mod threat_detection;
