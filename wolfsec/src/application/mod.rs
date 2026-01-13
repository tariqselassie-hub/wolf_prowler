//! High-level application services for Wolf Security.
//! This module implements the Command-Query Responsibilty Segregation (CQRS) pattern.

pub mod commands;
pub mod dtos;
pub mod error;
/// Integration bridges for third-party security systems.
pub mod queries;
pub mod services;
