//! Comprehensive Error System for Wolf Den

use std::error::Error as StdError;
use std::fmt;
use thiserror::Error;

/// Result type for Wolf Den operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error codes for programmatic error handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    CryptoOperationFailed = 1000,
    InvalidKeyFormat = 1001,
    KeyGenerationFailed = 1002,
    EncryptionFailed = 1003,
    DecryptionFailed = 1004,
    SignatureVerificationFailed = 1005,
    HashOperationFailed = 1100,
    MacOperationFailed = 1200,
    KeyDerivationFailed = 1300,
    RandomGenerationFailed = 1400,
    ConfigurationError = 1500,
    IoError = 1600,
    ProtocolError = 1700,
    InternalError = 9000,
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
        code: ErrorCode,
        message: String,
        operation: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Hash operation failed
    #[error("[{code}] Hash ({algorithm}) failed: {message}")]
    Hash {
        code: ErrorCode,
        message: String,
        algorithm: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// MAC operation failed
    #[error("[{code}] MAC ({algorithm}) failed: {message}")]
    Mac {
        code: ErrorCode,
        message: String,
        algorithm: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Key derivation failed
    #[error("[{code}] KDF ({function}) failed: {message}")]
    KeyDerivation {
        code: ErrorCode,
        message: String,
        function: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Random number generation failed
    #[error("[{code}] Random ({random_source}) failed: {message}")]
    Random {
        code: ErrorCode,
        message: String,
        random_source: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Configuration error
    #[error("[{code}] Configuration ({parameter}) error: {message}")]
    Configuration {
        code: ErrorCode,
        message: String,
        parameter: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// System error
    #[error("[{code}] System ({operation}) error: {message}")]
    System {
        code: ErrorCode,
        message: String,
        operation: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Protocol error
    #[error("[{code}] Protocol ({protocol}) error: {message}")]
    Protocol {
        code: ErrorCode,
        message: String,
        protocol: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Signature verification failed
    #[error("[{code}] Signature verification failed: {message}")]
    SignatureVerification {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// Internal error
    #[error("[{code}] Internal error: {message}")]
    Internal {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

impl Error {
    /// Get the error code
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Crypto { code, .. } => *code,
            Error::Hash { code, .. } => *code,
            Error::Mac { code, .. } => *code,
            Error::KeyDerivation { code, .. } => *code,
            Error::Random { code, .. } => *code,
            Error::Configuration { code, .. } => *code,
            Error::System { code, .. } => *code,
            Error::Protocol { code, .. } => *code,
            Error::SignatureVerification { code, .. } => *code,
            Error::Internal { code, .. } => *code,
        }
    }

    /// Create a new cryptographic error
    pub fn crypto(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::CryptoOperationFailed,
            message: message.into(),
            operation: operation.into(),
            source: None,
        }
    }

    /// Create a new key generation error
    pub fn key_generation(message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::KeyGenerationFailed,
            message: message.into(),
            operation: "key generation".to_string(),
            source: None,
        }
    }

    /// Create a new encryption error
    pub fn encryption(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::EncryptionFailed,
            message: message.into(),
            operation: operation.into(),
            source: None,
        }
    }

    /// Create a new decryption error
    pub fn decryption(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Crypto {
            code: ErrorCode::DecryptionFailed,
            message: message.into(),
            operation: operation.into(),
            source: None,
        }
    }

    /// Create a new signature verification error
    pub fn signature_verification(message: impl Into<String>) -> Self {
        Self::SignatureVerification {
            code: ErrorCode::SignatureVerificationFailed,
            message: message.into(),
            source: None,
        }
    }

    /// Create a new hash error
    pub fn hash(algorithm: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Hash {
            code: ErrorCode::HashOperationFailed,
            message: message.into(),
            algorithm: algorithm.into(),
            source: None,
        }
    }

    /// Create a new MAC error
    pub fn mac(algorithm: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Mac {
            code: ErrorCode::MacOperationFailed,
            message: message.into(),
            algorithm: algorithm.into(),
            source: None,
        }
    }

    /// Create a new key derivation error
    pub fn key_derivation(function: impl Into<String>, message: impl Into<String>) -> Self {
        Self::KeyDerivation {
            code: ErrorCode::KeyDerivationFailed,
            message: message.into(),
            function: function.into(),
            source: None,
        }
    }

    /// Create a new random generation error
    pub fn random(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Random {
            code: ErrorCode::RandomGenerationFailed,
            message: message.into(),
            random_source: source.into(),
            source: None,
        }
    }

    /// Create a new configuration error
    pub fn configuration(parameter: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Configuration {
            code: ErrorCode::ConfigurationError,
            message: message.into(),
            parameter: parameter.into(),
            source: None,
        }
    }

    /// Create a new system error
    pub fn system(operation: impl Into<String>, message: impl Into<String>) -> Self {
        Self::System {
            code: ErrorCode::IoError,
            message: message.into(),
            operation: operation.into(),
            source: None,
        }
    }

    /// Create a new internal error
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            code: ErrorCode::InternalError,
            message: message.into(),
            source: None,
        }
    }

    /// Create a new not implemented error
    pub fn not_implemented(feature: impl Into<String>) -> Self {
        Self::Internal {
            code: ErrorCode::NotImplemented,
            message: format!("Feature not implemented: {}", feature.into()),
            source: None,
        }
    }

    /// Add context to an existing error
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        match &mut self {
            Error::Crypto { message, .. } => *message = format!("{}: {}", context.into(), *message),
            Error::Hash { message, .. } => *message = format!("{}: {}", context.into(), *message),
            Error::Mac { message, .. } => *message = format!("{}: {}", context.into(), *message),
            Error::KeyDerivation { message, .. } => {
                *message = format!("{}: {}", context.into(), *message)
            }
            Error::Random { message, .. } => *message = format!("{}: {}", context.into(), *message),
            Error::Configuration { message, .. } => {
                *message = format!("{}: {}", context.into(), *message)
            }
            Error::System { message, .. } => *message = format!("{}: {}", context.into(), *message),
            Error::Protocol { message, .. } => {
                *message = format!("{}: {}", context.into(), *message)
            }
            Error::SignatureVerification { message, .. } => {
                *message = format!("{}: {}", context.into(), *message)
            }
            Error::Internal { message, .. } => {
                *message = format!("{}: {}", context.into(), *message)
            }
        }
        self
    }

    /// Add source error to this error
    pub fn with_source(mut self, source: Box<dyn StdError + Send + Sync>) -> Self {
        match &mut self {
            Error::Crypto { source: src, .. } => *src = Some(source),
            Error::Hash { source: src, .. } => *src = Some(source),
            Error::Mac { source: src, .. } => *src = Some(source),
            Error::KeyDerivation { source: src, .. } => *src = Some(source),
            Error::Random { source: src, .. } => *src = Some(source),
            Error::Configuration { source: src, .. } => *src = Some(source),
            Error::System { source: src, .. } => *src = Some(source),
            Error::Protocol { source: src, .. } => *src = Some(source),
            Error::SignatureVerification { source: src, .. } => *src = Some(source),
            Error::Internal { source: src, .. } => *src = Some(source),
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
    fn test_error_codes() {
        let error = Error::crypto("test", "operation failed");
        assert_eq!(error.code(), ErrorCode::CryptoOperationFailed);
    }

    #[test]
    fn test_error_creation() {
        let hash_error = Error::hash("SHA256", "failed");
        assert!(matches!(hash_error, Error::Hash { .. }));
    }

    #[test]
    fn test_error_context() {
        let error = Error::hash("SHA256", "failed").with_context("during file verification");

        assert!(error.to_string().contains("during file verification"));
    }
}
