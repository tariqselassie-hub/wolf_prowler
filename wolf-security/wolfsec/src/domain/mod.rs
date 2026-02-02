//! Domain Module
//!
//! Core domain logic, entities, and business rules for Wolf Security.
//!
//! This module follows Domain-Driven Design (DDD) principles and contains:
//!
//! # Components
//!
//! - **Entities**: Core domain entities (User, Threat, Alert, etc.)
//! - **Events**: Domain events for event-driven architecture
//! - **Repositories**: Repository trait definitions (ports)
//! - **Error**: Domain-specific error types
//!
//! # Architecture
//!
//! The domain layer is independent of infrastructure concerns and defines
//! the business logic and rules. Infrastructure adapters implement the
//! repository traits defined here.
//!
//! # Example
//!
//! ```rust
//! use wolfsec::domain::{
//!     events::AuditEventType,
//!     entities::SecurityEntity,
//! };
//! ```

pub mod entities;
pub mod error;
pub mod events;
pub mod repositories;
pub mod services;
