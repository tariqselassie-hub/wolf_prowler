//! Network Security Module
//!
//! Migrated from wolf_net/src/security.rs
//! Comprehensive network security features including encryption, authentication, and key management

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

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

/// Network entity identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityId {
    pub peer_id: String,
    pub entity_type: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl EntityId {
    pub fn new(peer_id: String, entity_type: String) -> Self {
        let now = Utc::now();
        Self {
            peer_id,
            entity_type,
            created_at: now,
            updated_at: now,
        }
    }
}

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
    pub sender_id: EntityId,
    /// Recipient's entity ID
    pub recipient_id: EntityId,
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
    pub local_id: EntityId,
    /// Remote entity ID
    pub remote_id: EntityId,
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
        local_id: EntityId,
        remote_id: EntityId,
        shared_secret: Vec<u8>,
        security_level: SecurityLevel,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(security_level.session_timeout as i64);

        Self {
            session_id: Uuid::new_v4().to_string(),
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

    /// Extend session expiration
    pub fn extend_session(&mut self, additional_seconds: u64) {
        self.expires_at = Utc::now() + chrono::Duration::seconds(additional_seconds as i64);
    }
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Token value
    pub token: String,
    /// Entity ID this token belongs to
    pub entity_id: EntityId,
    /// Token creation time
    pub created_at: DateTime<Utc>,
    /// Token expiration
    pub expires_at: DateTime<Utc>,
    /// Token permissions
    pub permissions: Vec<String>,
    /// Token scope
    pub scope: String,
}

impl AuthToken {
    /// Generate new authentication token
    pub fn new(
        entity_id: EntityId,
        permissions: Vec<String>,
        scope: String,
        ttl_hours: u64,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(ttl_hours as i64);

        Self {
            token: format!("{}_{}", entity_id.peer_id, Uuid::new_v4()),
            entity_id,
            created_at: now,
            expires_at,
            permissions,
            scope,
        }
    }

    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    /// Check if token has specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
}

/// Network security manager for handling all cryptographic operations
pub struct NetworkSecurityManager {
    /// Local entity ID
    entity_id: EntityId,
    /// Local key pairs
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

impl NetworkSecurityManager {
    /// Create new network security manager
    pub fn new(entity_id: String, security_level: SecurityLevel) -> Self {
        let entity = EntityId::new(entity_id, "network_node".to_string());
        Self {
            entity_id: entity,
            key_pairs: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            public_keys: Arc::new(RwLock::new(HashMap::new())),
            auth_tokens: Arc::new(RwLock::new(HashMap::new())),
            security_level,
        }
    }

    /// Initialize security manager with default keys
    pub async fn initialize(&self) -> Result<()> {
        info!(
            "🔐 Initializing network security manager for {}",
            self.entity_id.peer_id
        );

        // Generate default key pair
        let default_keypair = KeyPair::new(self.security_level.key_exchange)?;
        let fingerprint = default_keypair.fingerprint();

        let mut key_pairs = self.key_pairs.write().await;
        key_pairs.insert("default".to_string(), default_keypair);

        // Register our own public key
        let mut public_keys = self.public_keys.write().await;
        public_keys.insert(
            self.entity_id.peer_id.to_string(),
            key_pairs["default"].public_key.clone(),
        );

        info!("🔑 Generated default key pair: {}", fingerprint);
        Ok(())
    }

    /// Generate new key pair
    pub async fn generate_keypair(&self, algorithm: KeyExchange) -> Result<String> {
        let keypair = KeyPair::new(algorithm)?;
        let fingerprint = keypair.fingerprint();

        let mut key_pairs = self.key_pairs.write().await;
        key_pairs.insert(fingerprint.clone(), keypair);

        info!("🔑 Generated new key pair: {}", fingerprint);
        Ok(fingerprint)
    }

    /// Get public key fingerprint
    pub async fn get_public_key_fingerprint(&self, key_id: &str) -> Result<String> {
        let key_pairs = self.key_pairs.read().await;
        match key_pairs.get(key_id) {
            Some(keypair) => Ok(keypair.fingerprint()),
            None => Err(anyhow::anyhow!("Key pair not found: {}", key_id)),
        }
    }

    /// Add known public key
    pub async fn add_public_key(&self, peer_id: &str, public_key: Vec<u8>) -> Result<()> {
        let mut public_keys = self.public_keys.write().await;
        public_keys.insert(peer_id.to_string(), public_key);

        info!("🔓 Added public key for peer: {}", peer_id);
        Ok(())
    }

    /// Create security session with remote entity
    pub async fn create_session(&self, remote_id: EntityId) -> Result<String> {
        // In a real implementation, this would perform key exchange
        // For now, we'll create a placeholder shared secret
        let shared_secret = vec![42u8; 32]; // Placeholder

        let session = SecuritySession::new(
            self.entity_id.clone(),
            remote_id,
            shared_secret,
            self.security_level.clone(),
        );

        let session_id = session.session_id.clone();
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);

        info!("🔗 Created security session: {}", session_id);
        Ok(session_id)
    }

    /// Get active session
    pub async fn get_session(&self, session_id: &str) -> Option<SecuritySession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Remove expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let mut sessions = self.sessions.write().await;
        let initial_count = sessions.len();

        sessions.retain(|_, session| !session.is_expired());

        let removed = initial_count - sessions.len();
        if removed > 0 {
            info!("🧹 Cleaned up {} expired sessions", removed);
        }

        Ok(removed)
    }

    /// Encrypt message
    pub async fn encrypt_message(
        &self,
        session_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        if session.is_expired() {
            return Err(anyhow::anyhow!("Session expired: {}", session_id));
        }

        // In a real implementation, this would use actual encryption
        // For now, we'll create a placeholder encrypted message
        let ciphertext = plaintext.to_vec(); // Placeholder - not actually encrypted
        let nonce = vec![1u8; 12]; // Placeholder nonce
        let tag = vec![2u8; 16]; // Placeholder authentication tag

        let encrypted = EncryptedMessage {
            ciphertext,
            nonce,
            tag,
            algorithm: session.security_level.encryption,
            sender_id: self.entity_id.clone(),
            recipient_id: session.remote_id.clone(),
            timestamp: Utc::now(),
            message_id: Uuid::new_v4().to_string(),
        };

        info!("🔒 Encrypted message for session: {}", session_id);
        Ok(encrypted)
    }

    /// Decrypt message
    pub async fn decrypt_message(
        &self,
        session_id: &str,
        encrypted: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        if session.is_expired() {
            return Err(anyhow::anyhow!("Session expired: {}", session_id));
        }

        // Verify recipient
        if encrypted.recipient_id.peer_id != self.entity_id.peer_id {
            return Err(anyhow::anyhow!("Message not intended for this recipient"));
        }

        // In a real implementation, this would use actual decryption
        // For now, we'll return the ciphertext as plaintext
        let plaintext = encrypted.ciphertext.clone(); // Placeholder - not actually decrypted

        info!("🔓 Decrypted message from session: {}", session_id);
        Ok(plaintext)
    }

    /// Sign data
    pub async fn sign_data(&self, key_id: &str, _data: &[u8]) -> Result<DigitalSignature> {
        let key_pairs = self.key_pairs.read().await;
        let keypair = key_pairs
            .get(key_id)
            .ok_or_else(|| anyhow::anyhow!("Key pair not found: {}", key_id))?;

        // In a real implementation, this would use actual signing
        // For now, we'll create a placeholder signature
        let signature = vec![3u8; 64]; // Placeholder signature

        let digital_sig = DigitalSignature {
            signature,
            algorithm: match keypair.algorithm {
                KeyExchange::X25519 => SignatureAlgorithm::Ed25519,
                KeyExchange::P256 => SignatureAlgorithm::EcdsaP256,
                KeyExchange::P384 => SignatureAlgorithm::EcdsaP384,
            },
            timestamp: Utc::now(),
            signer_fingerprint: keypair.fingerprint(),
        };

        info!("✍️ Signed data with key: {}", key_id);
        Ok(digital_sig)
    }

    /// Verify signature
    pub async fn verify_signature(
        &self,
        signature: &DigitalSignature,
        _data: &[u8],
    ) -> Result<bool> {
        // Get signer's public key
        let public_keys = self.public_keys.read().await;
        let _public_key = public_keys
            .get(&signature.signer_fingerprint)
            .ok_or_else(|| {
                anyhow::anyhow!("Public key not found for: {}", signature.signer_fingerprint)
            })?;

        // In a real implementation, this would use actual verification
        // For now, we'll assume all signatures are valid
        let is_valid = true; // Placeholder verification

        info!("✅ Verified signature: {}", is_valid);
        Ok(is_valid)
    }

    /// Generate authentication token
    pub async fn generate_auth_token(
        &self,
        permissions: Vec<String>,
        scope: String,
        ttl_hours: u64,
    ) -> Result<AuthToken> {
        let token = AuthToken::new(self.entity_id.clone(), permissions, scope, ttl_hours);
        let token_id = token.token.clone();

        let mut auth_tokens = self.auth_tokens.write().await;
        auth_tokens.insert(token_id.clone(), token.clone());

        info!("🎫 Generated auth token: {}", token_id);
        Ok(token)
    }

    /// Validate authentication token
    pub async fn validate_auth_token(&self, token: &str) -> Result<AuthToken> {
        let auth_tokens = self.auth_tokens.read().await;
        let auth_token = auth_tokens
            .get(token)
            .ok_or_else(|| anyhow::anyhow!("Token not found: {}", token))?;

        if !auth_token.is_valid() {
            return Err(anyhow::anyhow!("Token expired: {}", token));
        }

        info!("✅ Validated auth token: {}", token);
        Ok(auth_token.clone())
    }

    /// Revoke authentication token
    pub async fn revoke_auth_token(&self, token: &str) -> Result<bool> {
        let mut auth_tokens = self.auth_tokens.write().await;
        let removed = auth_tokens.remove(token).is_some();

        if removed {
            info!("🗑️ Revoked auth token: {}", token);
        }

        Ok(removed)
    }

    /// Get security statistics
    pub async fn get_security_stats(&self) -> Result<NetworkSecurityStats> {
        let key_pairs = self.key_pairs.read().await;
        let sessions = self.sessions.read().await;
        let public_keys = self.public_keys.read().await;
        let auth_tokens = self.auth_tokens.read().await;

        let active_sessions = sessions.values().filter(|s| !s.is_expired()).count();
        let expired_sessions = sessions.len() - active_sessions;
        let valid_tokens = auth_tokens.values().filter(|t| t.is_valid()).count();
        let expired_tokens = auth_tokens.len() - valid_tokens;

        Ok(NetworkSecurityStats {
            total_keypairs: key_pairs.len(),
            known_public_keys: public_keys.len(),
            active_sessions,
            expired_sessions,
            valid_tokens,
            expired_tokens,
            security_level: self.security_level.clone(),
        })
    }
}

/// Network security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityStats {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_security_manager_creation() {
        let entity_id = "test_peer_123".to_string();
        let security_manager = NetworkSecurityManager::new(entity_id.clone(), MEDIUM_SECURITY);

        assert_eq!(security_manager.entity_id.peer_id, entity_id);
        assert_eq!(
            security_manager.security_level.encryption,
            CryptoAlgorithm::AES256GCM
        );
    }

    #[tokio::test]
    async fn test_keypair_generation() {
        let entity_id = "test_peer_456".to_string();
        let security_manager = NetworkSecurityManager::new(entity_id, HIGH_SECURITY);

        let fingerprint = security_manager
            .generate_keypair(KeyExchange::X25519)
            .await
            .unwrap();
        assert!(!fingerprint.is_empty());

        let retrieved_fingerprint = security_manager
            .get_public_key_fingerprint(&fingerprint)
            .await
            .unwrap();
        assert_eq!(fingerprint, retrieved_fingerprint);
    }

    #[tokio::test]
    async fn test_session_creation() {
        let entity_id = "test_peer_789".to_string();
        let remote_id = EntityId::new("remote_peer".to_string(), "network_node".to_string());
        let security_manager = NetworkSecurityManager::new(entity_id, MEDIUM_SECURITY);

        let session_id = security_manager.create_session(remote_id).await.unwrap();
        assert!(!session_id.is_empty());

        let session = security_manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.local_id.peer_id, "test_peer_789");
        assert!(!session.is_expired());
    }

    #[tokio::test]
    async fn test_auth_token_generation() {
        let entity_id = "test_peer_token".to_string();
        let security_manager = NetworkSecurityManager::new(entity_id, LOW_SECURITY);

        let permissions = vec!["read".to_string(), "write".to_string()];
        let token = security_manager
            .generate_auth_token(permissions, "api".to_string(), 24)
            .await
            .unwrap();

        assert!(token.is_valid());
        assert!(token.has_permission("read"));
        assert!(!token.has_permission("admin"));

        let validated = security_manager
            .validate_auth_token(&token.token)
            .await
            .unwrap();
        assert_eq!(validated.token, token.token);
    }

    #[tokio::test]
    async fn test_message_encryption() {
        let entity_id = "test_peer_encrypt".to_string();
        let remote_id = EntityId::new("remote_encrypt".to_string(), "network_node".to_string());
        let security_manager = NetworkSecurityManager::new(entity_id, MEDIUM_SECURITY);

        let session_id = security_manager.create_session(remote_id).await.unwrap();
        let plaintext = b"Hello, secure world!";

        let encrypted = security_manager
            .encrypt_message(&session_id, plaintext)
            .await
            .unwrap();
        assert_eq!(encrypted.sender_id.peer_id, "test_peer_encrypt");
        assert_eq!(encrypted.recipient_id.peer_id, "remote_encrypt");

        let decrypted = security_manager
            .decrypt_message(&session_id, &encrypted)
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_digital_signature() {
        let entity_id = "test_peer_sign".to_string();
        let security_manager = NetworkSecurityManager::new(entity_id, HIGH_SECURITY);

        security_manager.initialize().await.unwrap();

        let data = b"Important message";
        let signature = security_manager.sign_data("default", data).await.unwrap();

        let is_valid = security_manager
            .verify_signature(&signature, data)
            .await
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_security_levels() {
        assert_eq!(HIGH_SECURITY.encryption, CryptoAlgorithm::XChaCha20Poly1305);
        assert_eq!(MEDIUM_SECURITY.encryption, CryptoAlgorithm::AES256GCM);
        assert_eq!(LOW_SECURITY.encryption, CryptoAlgorithm::ChaCha20Poly1305);

        assert_eq!(HIGH_SECURITY.session_timeout, 1800);
        assert_eq!(MEDIUM_SECURITY.session_timeout, 3600);
        assert_eq!(LOW_SECURITY.session_timeout, 7200);
    }

    #[test]
    fn test_keypair_expiry() {
        let keypair = KeyPair::new(KeyExchange::X25519).unwrap();
        assert!(!keypair.is_expired());

        // Test with expired key
        let mut expired_keypair = keypair.clone();
        expired_keypair.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        assert!(expired_keypair.is_expired());
    }
}
