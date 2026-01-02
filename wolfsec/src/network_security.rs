//! Network Security Module
//!
//! Consolidated network security functionality from wolf_net

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Cryptographic algorithms supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoAlgorithm {
    AES256GCM,         // AES-256 in GCM mode
    ChaCha20Poly1305,  // ChaCha20-Poly1305
    XChaCha20Poly1305, // XChaCha20-Poly1305
}

/// Hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    Blake3,
}

/// Key exchange protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyExchange {
    X25519, // Diffie-Hellman using Curve25519
    P256,   // NIST P-256 curve
    P384,   // NIST P-384 curve
}

/// Signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Ed25519,   // Edwards curve Digital Signature Algorithm
    EcdsaP256, // ECDSA with P-256
    EcdsaP384, // ECDSA with P-384
    RSA2048,   // RSA with 2048-bit keys
    RSA4096,   // RSA with 4096-bit keys
}

/// Security level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLevel {
    /// Encryption algorithm
    pub encryption: CryptoAlgorithm,
    /// Hash algorithm
    pub hash: HashAlgorithm,
    /// Key exchange protocol
    pub key_exchange: KeyExchange,
    /// Signature algorithm
    pub signature: SignatureAlgorithm,
    /// Key size in bits
    pub key_size: u16,
    /// Session timeout in seconds
    pub session_timeout: u64,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self {
            encryption: CryptoAlgorithm::AES256GCM,
            hash: HashAlgorithm::SHA256,
            key_exchange: KeyExchange::X25519,
            signature: SignatureAlgorithm::Ed25519,
            key_size: 256,
            session_timeout: 3600, // 1 hour
        }
    }
}

/// High security configuration
pub const HIGH_SECURITY: SecurityLevel = SecurityLevel {
    encryption: CryptoAlgorithm::XChaCha20Poly1305,
    hash: HashAlgorithm::SHA512,
    key_exchange: KeyExchange::X25519,
    signature: SignatureAlgorithm::Ed25519,
    key_size: 256,
    session_timeout: 1800, // 30 minutes
};

/// Medium security configuration
pub const MEDIUM_SECURITY: SecurityLevel = SecurityLevel {
    encryption: CryptoAlgorithm::AES256GCM,
    hash: HashAlgorithm::SHA256,
    key_exchange: KeyExchange::X25519,
    signature: SignatureAlgorithm::Ed25519,
    key_size: 256,
    session_timeout: 3600, // 1 hour
};

/// Low security configuration (for testing)
pub const LOW_SECURITY: SecurityLevel = SecurityLevel {
    encryption: CryptoAlgorithm::ChaCha20Poly1305,
    hash: HashAlgorithm::SHA256,
    key_exchange: KeyExchange::X25519,
    signature: SignatureAlgorithm::Ed25519,
    key_size: 128,
    session_timeout: 7200, // 2 hours
};

/// Cryptographic key pair
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Public key (bytes)
    pub public_key: Vec<u8>,
    /// Private key (bytes, encrypted at rest)
    pub private_key: Vec<u8>,
    /// Key algorithm
    pub algorithm: KeyExchange,
    /// Key creation timestamp
    pub created_at: DateTime<Utc>,
    /// Key expiration
    pub expires_at: Option<DateTime<Utc>>,
}

impl KeyPair {
    /// Generate new key pair
    pub fn new(algorithm: KeyExchange) -> Result<Self> {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::days(365); // 1 year expiry

        // In a real implementation, this would use actual cryptographic libraries
        // For now, we'll create placeholder keys
        let key_size = match algorithm {
            KeyExchange::X25519 => 32,
            KeyExchange::P256 => 32,
            KeyExchange::P384 => 48,
        };

        let public_key = vec![0u8; key_size];
        let private_key = vec![1u8; key_size];

        Ok(Self {
            public_key,
            private_key,
            algorithm,
            created_at: now,
            expires_at: Some(expires_at),
        })
    }

    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expiry) => Utc::now() > expiry,
            None => false,
        }
    }

    /// Get key fingerprint
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.public_key);
        let result = hasher.finalize();
        hex::encode(result)
    }
}

/// Digital signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    /// Signature data
    pub signature: Vec<u8>,
    /// Algorithm used
    pub algorithm: SignatureAlgorithm,
    /// Signing timestamp
    pub timestamp: DateTime<Utc>,
    /// Signer's public key fingerprint
    pub signer_fingerprint: String,
}

/// Encrypted message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Encrypted payload
    pub ciphertext: Vec<u8>,
    /// Nonce/IV used for encryption
    pub nonce: Vec<u8>,
    /// Authentication tag
    pub tag: Vec<u8>,
    /// Encryption algorithm
    pub algorithm: CryptoAlgorithm,
    /// Sender's entity ID
    pub sender_id: String,
    /// Recipient's entity ID
    pub recipient_id: String,
    /// Message timestamp
    pub timestamp: DateTime<Utc>,
    /// Message ID for deduplication
    pub message_id: String,
}

/// Security session between two entities
#[derive(Debug, Clone)]
pub struct SecuritySession {
    /// Session ID
    pub session_id: String,
    /// Local entity ID
    pub local_id: String,
    /// Remote entity ID
    pub remote_id: String,
    /// Shared secret
    pub shared_secret: Vec<u8>,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Session expiration
    pub expires_at: DateTime<Utc>,
    /// Security level
    pub security_level: SecurityLevel,
}

impl SecuritySession {
    /// Create new security session
    pub fn new(
        local_id: String,
        remote_id: String,
        shared_secret: Vec<u8>,
        security_level: SecurityLevel,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(security_level.session_timeout as i64);

        Self {
            session_id: uuid::Uuid::new_v4().to_string(),
            local_id,
            remote_id,
            shared_secret,
            created_at: now,
            last_activity: now,
            expires_at,
            security_level,
        }
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Update last activity time
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Token value
    pub token: String,
    /// Entity ID
    pub entity_id: String,
    /// Permissions granted
    pub permissions: Vec<String>,
    /// Token scope
    pub scope: String,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Expiration time
    pub expires_at: DateTime<Utc>,
    /// Whether token is revoked
    pub revoked: bool,
}

impl AuthToken {
    /// Create new authentication token
    pub fn new(entity_id: String, permissions: Vec<String>, scope: String, ttl_hours: u64) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(ttl_hours as i64);

        Self {
            token: format!("token_{}", uuid::Uuid::new_v4()),
            entity_id,
            permissions,
            scope,
            created_at: now,
            expires_at,
            revoked: false,
        }
    }

    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        !self.revoked && Utc::now() < self.expires_at
    }

    /// Check if token has specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
}

/// Network Security Manager
pub struct SecurityManager {
    /// Entity ID
    entity_id: String,
    /// Key pairs
    key_pairs: Arc<RwLock<HashMap<String, KeyPair>>>,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<String, SecuritySession>>>,
    /// Known public keys
    public_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Authentication tokens
    auth_tokens: Arc<RwLock<HashMap<String, AuthToken>>>,
    /// Default security level
    security_level: SecurityLevel,
}

impl SecurityManager {
    /// Get session secret for a given session ID
    pub async fn get_session_secret(&self, session_id: &str) -> Option<Vec<u8>> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|s| s.shared_secret.clone())
    }

    /// Create new security manager
    pub fn new(entity_id: String, security_level: SecurityLevel) -> Self {
        Self {
            entity_id,
            key_pairs: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            auth_tokens: Arc::new(RwLock::new(HashMap::new())),
            security_level,
        }
    }

    /// Initialize security manager with default keys
    pub async fn initialize(&self) -> Result<()> {
        info!("🔐 Initializing security manager for {}", self.entity_id);

        // Generate default key pair
        let default_keypair = KeyPair::new(self.security_level.key_exchange)?;
        let fingerprint = default_keypair.fingerprint();

        let mut key_pairs = self.key_pairs.write().await;
        key_pairs.insert("default".to_string(), default_keypair);

        // Register our own public key
        let mut public_keys = self.public_keys.write().await;
        public_keys.insert(
            self.entity_id.clone(),
            key_pairs["default"].public_key.clone(),
        );

        info!("🔑 Generated default key pair: {}", fingerprint);
        Ok(())
    }

    /// Get security statistics
    pub async fn get_stats(&self) -> SecurityStats {
        let key_pairs = self.key_pairs.read().await;
        let sessions = self.sessions.read().await;
        let public_keys = self.public_keys.read().await;
        let auth_tokens = self.auth_tokens.read().await;

        let active_sessions = sessions.values().filter(|s| !s.is_expired()).count();
        let expired_sessions = sessions.len() - active_sessions;
        let valid_tokens = auth_tokens.values().filter(|t| t.is_valid()).count();
        let expired_tokens = auth_tokens.len() - valid_tokens;

        SecurityStats {
            total_keypairs: key_pairs.len(),
            known_public_keys: public_keys.len(),
            active_sessions,
            expired_sessions,
            valid_tokens,
            expired_tokens,
            security_level: self.security_level.clone(),
        }
    }

    /// Shutdown security manager
    pub async fn shutdown(&self) -> Result<()> {
        info!("🔐 Shutting down security manager");
        // Clean up sensitive data
        let mut key_pairs = self.key_pairs.write().await;
        key_pairs.clear();

        let mut sessions = self.sessions.write().await;
        sessions.clear();

        let mut auth_tokens = self.auth_tokens.write().await;
        auth_tokens.clear();

        info!("🔐 Security manager shutdown complete");
        Ok(())
    }
}

/// Security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStats {
    /// Total key pairs
    pub total_keypairs: usize,
    /// Known public keys
    pub known_public_keys: usize,
    /// Active sessions
    pub active_sessions: usize,
    /// Expired sessions
    pub expired_sessions: usize,
    /// Valid tokens
    pub valid_tokens: usize,
    /// Expired tokens
    pub expired_tokens: usize,
    /// Current security level
    pub security_level: SecurityLevel,
}

/// Configuration for network security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub default_security_level: SecurityLevel,
    pub max_sessions_per_peer: usize,
    pub session_cleanup_interval: u64,
    pub token_ttl_hours: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_security_level: MEDIUM_SECURITY,
            max_sessions_per_peer: 10,
            session_cleanup_interval: 3600, // 1 hour
            token_ttl_hours: 24,
        }
    }
}
