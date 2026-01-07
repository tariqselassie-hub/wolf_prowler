//! Secrets Management Module
//!
//! This module provides secure secrets management using Wolf Den's cryptographic capabilities.
//! It includes a vault for storing and retrieving encrypted secrets with automatic rotation
//! and memory protection.

pub mod vault;

pub use vault::{EncryptedSecret, SecretMetadata, SecretsVault, VaultConfig, VaultError};
