//! Service implementations for the wolfsec infrastructure.
//!
//! This module contains concrete implementations of application-level services
//! such as password hashing, cryptography, and adapters for legacy components.

pub mod argon2_password_hasher;
pub mod legacy_threat_detector_adapter;
pub mod wolf_den_cryptography_provider;

/// A password hashing service that uses the Argon2id algorithm.
///
/// This implementation provides secure password hashing and verification
/// using parameters optimized for security and performance.
pub struct Argon2PasswordHasher;
pub use legacy_threat_detector_adapter::LegacyThreatDetectorAdapter;
pub use wolf_den_cryptography_provider::WolfDenCryptographyProvider;
