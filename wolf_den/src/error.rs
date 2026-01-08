//! Comprehensive Error System for Wolf Den

use std::error::Error as StdError;
use std::fmt;
use thiserror::Error;

/// Result type for Wolf Den operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error codes for programmatic error handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Cryptographic operation failed
    CryptoOperationFailed = 1000,
    /// Invalid key format
    InvalidKeyFormat = 1001,
    /// Key generation failed
    KeyGenerationFailed = 1002,
    /// Encryption failed
    EncryptionFailed = 1003,
    /// Decryption failed
    DecryptionFailed = 1004,
    /// Signature verification failed
    SignatureVerificationFailed = 1005,
    /// Hash operation failed
    HashOperationFailed = 1100,
    /// MAC operation failed
    MacOperationFailed = 1200,
    /// Key derivation failed
    KeyDerivationFailed = 1300,
    /// Random generation failed
    RandomGenerationFailed = 1400,
    /// Configuration error
    ConfigurationError = 1500,
    /// I/O error
    IoError = 1600,
    /// Protocol error
    ProtocolError = 1700,
    /// Internal error
    InternalError = 9000,
    /// Feature not implemented
    NotImplemented = 9001,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self as u32)
    }
}

/// Main error type for Wolf Den
#[derive(Debug, Error)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("[{code}] {operation}: {message}")]
    Crypto {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// Operation that failed
        operation: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Hash operation failed
    #[error("[{code}] Hash ({algorithm}) failed: {message}")]
    Hash {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// Algorithm name
        algorithm: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// MAC operation failed
    #[error("[{code}] MAC ({algorithm}) failed: {message}")]
    Mac {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// Algorithm name
        algorithm: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Key derivation failed
    #[error("[{code}] KDF ({function}) failed: {message}")]
    KeyDerivation {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// Reference to KDF function
        function: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Random number generation failed
    #[error("[{code}] Random ({random_source}) failed: {message}")]
    Random {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// Source of randomness
        random_source: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Configuration error
    #[error("[{code}] Configuration ({parameter}) error: {message}")]
    Configuration {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// Parameter that was misconfigured
        parameter: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// System error
    #[error("[{code}] System ({operation}) error: {message}")]
    System {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// System operation that failed
        operation: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Protocol error
    #[error("[{code}] Protocol ({protocol}) error: {message}")]
    Protocol {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// Protocol name
        protocol: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Signature verification failed
    #[error("[{code}] Signature verification failed: {message}")]
    SignatureVerification {
        /// Error code
        code: ErrorCode,
        /// Detail message
        message: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Internal error
    #[error("[{code}] Internal error: {message}")]
    Internal {
        /// Error code
        code: ErrorCode,
        /// Error message
        message: String,
        /// Source error
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl Error {
    /// Get the error code
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Crypto { code, .. }
            | Self::Hash { code, .. }
            | Self::Mac { code, .. }
            | Self::KeyDerivation { code, .. }
            | Self::Random { code, .. }
            | Self::Configuration { code, .. }
            | Self::System { code, .. }
            | Self::Protocol { code, .. }
            | Self::SignatureVerification { code, .. }
            | Self::Internal { code, .. } => *code,
        }
    }

    /// Create a new cryptographic error
    #[must_use]
    pub fn crypto(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::CryptoOperationFailed,
            message: message.into(),
            operation: operation.into(),
            source: None,
        }
    }

    /// Create a new key generation error
    #[must_use]
    pub fn key_generation(message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::KeyGenerationFailed,
            message: message.into(),
            operation: "key generation".to_string(),
            source: None,
        }
    }

    /// Create a new encryption error
    #[must_use]
    pub fn encryption(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::EncryptionFailed,
            message: message.into(),
            operation: operation.into(),
            source: None,
        }
    }

    /// Create a new decryption error
    #[must_use]
    pub fn decryption(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::DecryptionFailed,
            message: message.into(),
            operation: operation.into(),
            source: None,
        }
    }

    /// Create a new signature verification error
    #[must_use]
    pub fn signature_verification(message: impl Into<String>) -> Self {
        Self::SignatureVerification {
            code: ErrorCode::SignatureVerificationFailed,
            message: message.into(),
            source: None,
        }
    }

    /// Create a new hash error
    #[must_use]
    pub fn hash(algorithm: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Hash {
            code: ErrorCode::HashOperationFailed,
            message: message.into(),
            algorithm: algorithm.into(),
            source: None,
        }
    }

    /// Create a new MAC error
    #[must_use]
    pub fn mac(algorithm: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Mac {
            code: ErrorCode::MacOperationFailed,
            message: message.into(),
            algorithm: algorithm.into(),
            source: None,
        }
    }

    /// Create a new key derivation error
    #[must_use]
    pub fn key_derivation(function: impl Into<String>, message: impl Into<String>) -> Self {
        Self::KeyDerivation {
            code: ErrorCode::KeyDerivationFailed,
            message: message.into(),
            function: function.into(),
            source: None,
        }
    }

    /// Create a new random generation error
    #[must_use]
    pub fn random(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Random {
            code: ErrorCode::RandomGenerationFailed,
            message: message.into(),
            random_source: source.into(),
            source: None,
        }
    }

    /// Create a new configuration error
    #[must_use]
    pub fn configuration(parameter: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Configuration {
            code: ErrorCode::ConfigurationError,
            message: message.into(),
            parameter: parameter.into(),
            source: None,
        }
    }

    /// Create a new system error
    #[must_use]
    pub fn system(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::System {
            code: ErrorCode::IoError,
            message: message.into(),
            operation: operation.into(),
            source: None,
        }
    }

    /// Create a new internal error
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            code: ErrorCode::InternalError,
            message: message.into(),
            source: None,
        }
    }

    /// Create a new not implemented error
    #[must_use]
    pub fn not_implemented(feature: impl Into<String>) -> Self {
        Self::Internal {
            code: ErrorCode::NotImplemented,
            message: format!("Feature not implemented: {}", feature.into()),
            source: None,
        }
    }

    /// Add context to an existing error
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        let ctx = context.into();
        match &mut self {
            Self::Crypto { message, .. }
            | Self::Hash { message, .. }
            | Self::Mac { message, .. }
            | Self::KeyDerivation { message, .. }
            | Self::Random { message, .. }
            | Self::Configuration { message, .. }
            | Self::System { message, .. }
            | Self::Protocol { message, .. }
            | Self::SignatureVerification { message, .. }
            | Self::Internal { message, .. } => *message = format!("{ctx}: {message}"),
        }
        self
    }

    /// Add source error to this error
    #[must_use]
    pub fn with_source(mut self, source: Box<dyn StdError + Send + Sync>) -> Self {
        match &mut self {
            Self::Crypto { source: src, .. }
            | Self::Hash { source: src, .. }
            | Self::Mac { source: src, .. }
            | Self::KeyDerivation { source: src, .. }
            | Self::Random { source: src, .. }
            | Self::Configuration { source: src, .. }
            | Self::System { source: src, .. }
            | Self::Protocol { source: src, .. }
            | Self::SignatureVerification { source: src, .. }
            | Self::Internal { source: src, .. } => *src = Some(source),
        }
        self
    }
}

// Standard error conversions
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::system("I/O", err.to_string()).with_source(Box::new(err))
    }
}

impl From<fmt::Error> for Error {
    fn from(err: fmt::Error) -> Self {
        Self::system("formatting", err.to_string()).with_source(Box::new(err))
    }
}

// Cryptographic library error conversions
impl From<argon2::Error> for Error {
    fn from(err: argon2::Error) -> Self {
        Self::key_derivation("Argon2", err.to_string())
    }
}

impl From<scrypt::errors::InvalidParams> for Error {
    fn from(_err: scrypt::errors::InvalidParams) -> Self {
        Self::key_derivation("scrypt", "Invalid parameters")
    }
}

impl From<rcgen::Error> for Error {
    fn from(err: rcgen::Error) -> Self {
        Self::key_generation(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_error_codes() {
        let error = Error::crypto("test", "operation failed");
        assert_eq!(error.code(), ErrorCode::CryptoOperationFailed);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_error_creation() {
        let hash_error = Error::hash("SHA256", "failed");
        assert!(matches!(hash_error, Error::Hash { .. }));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_error_context() {
        let error = Error::hash("SHA256", "failed").with_context("during file verification");

        assert!(error.to_string().contains("during file verification"));
    }
}
