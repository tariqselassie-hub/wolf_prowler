//! Wolf Den - Pure Cryptographic Library

// #![allow(missing_docs)]

use serde::{Deserialize, Serialize};

// Core modules
pub mod asymmetric;
pub mod builder;
/// Certificate generation utilities
pub mod certs;
/// Unified cryptographic engine
pub mod engine;
/// Error handling types
pub mod error;
/// Hash functions
pub mod hash;
/// Key derivation functions
pub mod kdf;
/// MAC algorithms
pub mod mac;
/// Secure memory handling
pub mod memory;
/// Random number generation
pub mod random;
/// Constant-time operations
pub mod security;
/// Symmetric encryption algorithms
pub mod symmetric;

// Re-exports
pub use crate::asymmetric::Ed25519Keypair;
// Re-export ed25519 types for convenience
pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub use crate::builder::{CryptoEngineBuilder, CryptoEngineExt};
pub use crate::engine::CryptoEngine;
pub use crate::error::{Error, Result};
pub use crate::hash::HashFunction;
pub use crate::kdf::KdfType;
pub use crate::mac::MacType;
pub use crate::symmetric::{create_cipher, Cipher};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the crypto engine with default settings
///
/// # Errors
///
/// Returns an error if initialization fails.
pub fn init() -> Result<CryptoEngine> {
    CryptoEngine::builder().build()
}

/// Security level for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum SecurityLevel {
    /// Minimum security level (128-bit)
    Minimum = 128,
    /// Standard security level (192-bit)
    Standard = 192,
    /// Maximum security level (256-bit)
    #[default]
    Maximum = 256,
}

/// Supported cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305 (Preferred)
    ChaCha20Poly1305,
    /// AES-256-GCM
    Aes256Gcm,
    /// AES-128-GCM
    Aes128Gcm,
}
