//! `WolfDb` - The Neural Core of Wolf Prowler
//!
//! # Overview
//! `WolfDb` is a high-performance, embedded database designed for the Wolf Prowler ecosystem.
//! It serves as the central storage engine, providing:
//! - **Post-Quantum Cryptography (PQC)**: Native support for ML-KEM and ML-DSA encryption and signing.
//! - **Vector Search**: Integrated vector database capabilities for AI/ML workloads.
//! - **High-Performance Batching**: Parallel record retrieval and PQC processing using `JoinSet` and `Rayon`.
//! - **Sled-based Storage**: Built on top of `sled` for reliable, transactional storage.
//! - **Multi-Model Support**: Key-Value, Document, and Vector data access patterns.
//!
//! # Architecture
//! The crate is organized into several modules:
//! - [`api`]: REST API integration (Axum-based).
//! - [`backup`]: Backup and Restore functionality.
//! - [`crypto`]: Cryptographic primitives and key management.
//! - [`engine`]: Query engine and CLI interface.
//! - [`import`]: Data import utilities (e.g., `SQLite`, JSON).
//! - [`storage`]: Core storage implementation (`WolfDbStorage`).
//! - [`vector`]: Vector search implementation.

/// REST API implementation
pub mod api;
/// Backup and recovery services
pub mod backup;
/// Cryptographic primitives and key management
pub mod crypto;
/// Query engine and execution (requires 'cli' feature)
#[cfg(feature = "cli")]
pub mod engine;
/// Custom error types
pub mod error;
/// Data import utilities
pub mod import;
/// Core storage implementation
pub mod storage;
/// Vector search implementation (requires 'ml' feature)
#[cfg(feature = "ml")]
pub mod vector;
