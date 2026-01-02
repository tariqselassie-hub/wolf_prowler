//! Wolf Den - Pure Cryptographic Library

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

// Core modules
pub mod asymmetric;
pub mod builder;
pub mod certs;
pub mod engine;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod mac;
pub mod memory;
pub mod random;
pub mod security;
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

/// Initialize Wolf Den with default configuration
pub fn init() -> Result<CryptoEngine> {
    CryptoEngine::builder().build()
}

/// Security level for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum SecurityLevel {
    Minimum = 128,
    Standard = 192,
    #[default]
    Maximum = 256,
}

/// Supported cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305 (Preferred)
    ChaCha20Poly1305,
    /// AES-256-GCM
    Aes256Gcm,
    /// AES-128-GCM
    Aes128Gcm,
}
