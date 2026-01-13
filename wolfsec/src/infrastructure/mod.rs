//! Infrastructure Module
//!
//! Infrastructure layer providing implementations of domain repositories,
//! external service adapters, and persistence mechanisms.
//!
//! # Components
//!
//! - **Adapters**: External service integrations (threat intel feeds, SIEM, etc.)
//! - **Persistence**: Database and storage implementations
//! - **Services**: Infrastructure services and utilities
//!
//! # Architecture
//!
//! This module implements the Hexagonal Architecture (Ports and Adapters) pattern:
//! - Domain defines the ports (repository traits)
//! - Infrastructure provides the adapters (implementations)
//!
//! # Example
//!
//! ```rust
//! use wolfsec::infrastructure::{
//!     persistence::ThreatRepository,
//!     adapters::threat_intel::ThreatIntelAdapter,
//! };
//! ```

pub mod adapters;
pub mod persistence;
pub mod services;
