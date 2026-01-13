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

/// symmetric encryption algorithms supported for packet and payload protection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoAlgorithm {
    /// NIST-compliant 256-bit AES in Galois/Counter Mode
    AES256GCM,
    /// High-performance stream cipher with Poly1305 MAC
    ChaCha20Poly1305,
    /// Extended-nonce variant of ChaCha20 for improved security
    XChaCha20Poly1305,
}

/// cryptographic hash functions for integrity and fingerprinting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// 256-bit Secure Hash Algorithm
    SHA256,
    /// 384-bit Secure Hash Algorithm
    SHA384,
    /// 512-bit Secure Hash Algorithm
    SHA512,
    /// efficient and secure keyed hash function
    Blake3,
}

/// protocols for establishing authenticated shared secrets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyExchange {
    /// Elliptic-curve Diffie-Hellman using Curve25519
    X25519,
    /// prime-field elliptic curve (NIST P-256)
    P256,
    /// prime-field elliptic curve (NIST P-384)
    P384,
}

/// algorithms for identity verification and non-repudiation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// high-performance Edwards-curve signature scheme
    Ed25519,
    /// Elliptic Curve Digital Signature Algorithm (P-256)
    EcdsaP256,
    /// Elliptic Curve Digital Signature Algorithm (P-384)
    EcdsaP384,
    /// classic signature scheme with 2048-bit modulus
    RSA2048,
    /// classic signature scheme with 4096-bit modulus
    RSA4096,
}

/// Complete cryptographic suite definition for a security tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLevel {
    /// encryption primitive for payload confidentiality
    pub encryption: CryptoAlgorithm,
    /// hash primitive for data integrity
    pub hash: HashAlgorithm,
    /// protocol for session key derivation
    pub key_exchange: KeyExchange,
    /// algorithm for identity and message verification
    pub signature: SignatureAlgorithm,
    /// primary symmetric key length in bits
    pub key_size: u16,
    /// duration (seconds) before a session requires re-keying
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

/// container for public and private cryptographic material
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// opaque public key material (encoded)
    pub public_key: Vec<u8>,
    /// opaque private key material (should be encrypted at rest)
    pub private_key: Vec<u8>,
    /// specific algorithm this material is compatible with
    pub algorithm: KeyExchange,
    /// point in time when the material was generated
    pub created_at: DateTime<Utc>,
    /// optional point in time when the material becomes invalid
    pub expires_at: Option<DateTime<Utc>>,
}

impl KeyPair {
    /// Provision a new key pair for a specified cryptographic algorithm.
    ///
    /// # Errors
    /// Returns an error if key generation fails (currently deterministic/placeholder).
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
    #[must_use]
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expiry) => Utc::now() > expiry,
            None => false,
        }
    }

    /// Get key fingerprint
    #[must_use]
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.public_key);
        let result = hasher.finalize();
        hex::encode(result)
    }
}

/// authenticated identity attestation for a discrete payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    /// raw signature material
    pub signature: Vec<u8>,
    /// algorithm used to generate the attestation
    pub algorithm: SignatureAlgorithm,
    /// point in time of attestation generation
    pub timestamp: DateTime<Utc>,
    /// unique fingerprint of the signer's identity key
    pub signer_fingerprint: String,
}

/// container for a confidential payload and its security metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// opaque encrypted payload
    pub ciphertext: Vec<u8>,
    /// entropy/initialization vector used for encryption
    pub nonce: Vec<u8>,
    /// message authentication code (MAC) for integrity verification
    pub tag: Vec<u8>,
    /// primitive used to secure the payload
    pub algorithm: CryptoAlgorithm,
    /// identifier for the originating identity
    pub sender_id: String,
    /// identifier for the target identity
    pub recipient_id: String,
    /// point in time for message ordering and replay protection
    pub timestamp: DateTime<Utc>,
    /// unique identifier for deduplication and tracking
    pub message_id: String,
}

/// established security context between two specific identities
#[derive(Debug, Clone)]
pub struct SecuritySession {
    /// unique identifier for the session context
    pub session_id: String,
    /// identity identifier for the initiating peer
    pub local_id: String,
    /// identity identifier for the remote peer
    pub remote_id: String,
    /// derived shared secret for symmetric protection
    pub shared_secret: Vec<u8>,
    /// point in time of session initialization
    pub created_at: DateTime<Utc>,
    /// point in time of the most recent interaction
    pub last_activity: DateTime<Utc>,
    /// point in time when the session requires re-keying or closure
    pub expires_at: DateTime<Utc>,
    /// cryptographic suite configured for this session
    pub security_level: SecurityLevel,
}

impl SecuritySession {
    /// provision a new security context with a remote peer and common shared secret.
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
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Update last activity time
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// transient credential granting specific network permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// opaque token string (usually a secure random identifier)
    pub token: String,
    /// identifier for the identity who owns the token
    pub entity_id: String,
    /// list of capability strings granted by the token
    pub permissions: Vec<String>,
    /// organizational or functional boundary for the token
    pub scope: String,
    /// point in time of token issuance
    pub created_at: DateTime<Utc>,
    /// point in time of token invalidation
    pub expires_at: DateTime<Utc>,
    /// true if the token has been explicitly invalidated by the issuer
    pub revoked: bool,
}

impl AuthToken {
    /// provision a new transient identity credential with specific capabilities.
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
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.revoked && Utc::now() < self.expires_at
    }

    /// Check if token has specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
}

/// orchestrator for cryptographic lifecycle and identity verification
pub struct SecurityManager {
    /// primary identity identifier for the local node
    entity_id: String,
    /// registry of owned cryptographic materials
    key_pairs: Arc<RwLock<HashMap<String, KeyPair>>>,
    /// active security contexts with remote identities
    sessions: Arc<RwLock<HashMap<String, SecuritySession>>>,
    /// registry of verified cryptographic material from remote peers
    public_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// transient identity credentials managed by this instance
    auth_tokens: Arc<RwLock<HashMap<String, AuthToken>>>,
    /// default security tier for new operations
    security_level: SecurityLevel,
}

impl SecurityManager {
    /// Get session secret for a given session ID
    pub async fn get_session_secret(&self, session_id: &str) -> Option<Vec<u8>> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|s| s.shared_secret.clone())
    }

    /// orchestrates the security lifecycle for the provided identity and default level.
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

    /// Bootstraps the manager and generates initial cryptographic materials.
    ///
    /// # Errors
    /// Returns an error if key generation fails.
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

impl Default for SecurityStats {
    fn default() -> Self {
        Self {
            total_keypairs: 0,
            known_public_keys: 0,
            active_sessions: 0,
            expired_sessions: 0,
            valid_tokens: 0,
            expired_tokens: 0,
            security_level: SecurityLevel::default(),
        }
    }
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
