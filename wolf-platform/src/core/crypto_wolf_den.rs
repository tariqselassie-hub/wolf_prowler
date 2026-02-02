//! Wolf Den cryptographic integration for Wolf Prowler

use anyhow::Result;
use std::time::{Duration, Instant};
use wolf_den::{
    init, init_with_config, CipherSuite, CryptoEngine, HashFunction, Identity, KeyStore, KeyType,
    MemoryIdentityManager, MemoryKeyStore, MemoryProtectionLevel, RandomnessSource, SecureBytes,
    SecurityLevel,
};

/// Wolf Prowler cryptographic engine using Wolf Den
pub struct CryptoEngine {
    /// Wolf Den crypto engine
    inner: wolf_den::CryptoEngine,
    /// Identity manager
    identity_manager: MemoryIdentityManager,
    /// Key store
    key_store: MemoryKeyStore,
    /// Local peer ID
    peer_id: String,
}

/// Digital signature using Wolf Den
#[derive(Debug, Clone)]
pub struct DigitalSignature {
    /// Signature bytes
    pub signature: Vec<u8>,
    /// Signer's public key
    pub public_key: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Encrypted message using Wolf Den
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// Encrypted data
    pub ciphertext: SecureBytes,
    /// Nonce used
    pub nonce: SecureBytes,
    /// Authentication tag
    pub tag: SecureBytes,
    /// Metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl CryptoEngine {
    /// Create a new cryptographic engine with Wolf Den defaults
    pub fn new() -> Result<Self> {
        let inner = init()?;
        let identity_manager = MemoryIdentityManager::new(Default::default())?;
        let key_store = MemoryKeyStore::new(Default::default())?;

        // Generate initial identity
        let identity = inner.generate_key_pair(KeyType::Ed25519)?;
        let peer_id = Self::derive_peer_id(&identity.public_key().to_bytes());

        // Store identity
        identity_manager.store_identity(&identity)?;
        key_store.store_key(
            &identity.public_key().to_bytes(),
            &identity.private_key().to_bytes(),
        )?;

        Ok(Self {
            inner,
            identity_manager,
            key_store,
            peer_id,
        })
    }

    /// Create from configuration
    pub fn from_config(config: &crate::core::AppSettings) -> Result<Self> {
        let cipher_suite = match config.crypto.cipher_suite.as_str() {
            "chacha20poly1305" => CipherSuite::ChaCha20Poly1305,
            "aes256gcm" => CipherSuite::Aes256Gcm,
            "aes128gcm" => CipherSuite::Aes128Gcm,
            _ => CipherSuite::ChaCha20Poly1305,
        };

        let hash_function = match config.crypto.hash_function.as_str() {
            "blake3" => HashFunction::Blake3,
            "sha256" => HashFunction::Sha256,
            "sha512" => HashFunction::Sha512,
            "sha3_256" => HashFunction::Sha3_256,
            "sha3_512" => HashFunction::Sha3_512,
            _ => HashFunction::Blake3,
        };

        let security_level = match config.crypto.security_level {
            128 => SecurityLevel::Minimum,
            192 => SecurityLevel::Standard,
            256 => SecurityLevel::Maximum,
            _ => SecurityLevel::Maximum,
        };

        let memory_protection = match config.crypto.memory_protection {
            0 => MemoryProtectionLevel::None,
            1 => MemoryProtectionLevel::Basic,
            2 => MemoryProtectionLevel::Strict,
            3 => MemoryProtectionLevel::Maximum,
            _ => MemoryProtectionLevel::Strict,
        };

        let randomness = match config.crypto.randomness_source.as_str() {
            "os" => RandomnessSource::Os,
            "chacha20" => RandomnessSource::ChaCha20,
            "hybrid" => RandomnessSource::Hybrid,
            "hardware" => RandomnessSource::Hardware,
            _ => RandomnessSource::Hybrid,
        };

        let wolf_den_config = wolf_den::Config {
            cipher_suite,
            hash_function,
            security_level,
            memory_protection,
            randomness_source: randomness,
            enable_key_rotation: config.crypto.enable_key_rotation,
            key_rotation_interval: config.crypto.key_rotation_interval,
            enable_perfect_forward_secrecy: config.crypto.enable_perfect_forward_secrecy,
            max_session_duration: config.crypto.max_session_duration,
            enable_audit_logging: config.crypto.enable_audit_logging,
        };

        let inner = wolf_den::CryptoEngine::builder()
            .config(wolf_den_config)
            .build()?;

        let identity_manager = MemoryIdentityManager::new(Default::default())?;
        let key_store = MemoryKeyStore::new(Default::default())?;

        // Generate initial identity
        let identity = inner.generate_key_pair(KeyType::Ed25519)?;
        let peer_id = Self::derive_peer_id(&identity.public_key().to_bytes());

        // Store identity
        identity_manager.store_identity(&identity)?;
        key_store.store_key(
            &identity.public_key().to_bytes(),
            &identity.private_key().to_bytes(),
        )?;

        Ok(Self {
            inner,
            identity_manager,
            key_store,
            peer_id,
        })
    }

    /// Get the local peer ID
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Get the public key for signing
    pub fn signing_public_key(&self) -> Vec<u8> {
        if let Ok(identity) = self.identity_manager.get_default_identity() {
            identity.public_key().to_bytes()
        } else {
            vec![]
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<DigitalSignature> {
        let identity = self.identity_manager.get_default_identity()?;
        let signature = self.inner.sign(message, &identity)?;

        Ok(DigitalSignature {
            signature: signature.to_bytes(),
            public_key: identity.public_key().to_bytes(),
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &DigitalSignature) -> Result<bool> {
        let public_key = self.inner.load_public_key(&signature.public_key)?;
        let signature_bytes = self.inner.load_signature(&signature.signature)?;

        Ok(self.inner.verify(message, &public_key, &signature_bytes)?)
    }

    /// Encrypt data
    pub fn encrypt(&self, data: &[u8], recipient_public_key: &[u8]) -> Result<EncryptedMessage> {
        let recipient_key = self.inner.load_public_key(recipient_public_key)?;
        let identity = self.identity_manager.get_default_identity()?;

        let encrypted = self.inner.encrypt(data, &recipient_key, &identity)?;

        Ok(EncryptedMessage {
            ciphertext: encrypted.ciphertext().clone(),
            nonce: encrypted.nonce().clone(),
            tag: encrypted.tag().clone(),
            metadata: std::collections::HashMap::new(),
        })
    }

    /// Decrypt data
    pub fn decrypt(
        &self,
        encrypted: &EncryptedMessage,
        sender_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let sender_key = self.inner.load_public_key(sender_public_key)?;
        let identity = self.identity_manager.get_default_identity()?;

        let encrypted_message = self.inner.create_encrypted_message(
            encrypted.ciphertext.clone(),
            encrypted.nonce.clone(),
            encrypted.tag.clone(),
        );

        Ok(self
            .inner
            .decrypt(&encrypted_message, &sender_key, &identity)?)
    }

    /// Generate shared secret
    pub fn generate_shared_secret(&self, other_public_key: &[u8]) -> Result<Vec<u8>> {
        let other_key = self.inner.load_public_key(other_public_key)?;
        let identity = self.identity_manager.get_default_identity()?;

        let shared_secret = self.inner.key_exchange(&other_key, &identity)?;
        Ok(shared_secret.to_bytes())
    }

    /// Hash data
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        self.inner.hash(data).to_bytes()
    }

    /// Derive key from password
    pub fn derive_key_from_password(&self, password: &str, salt: &[u8]) -> Result<Vec<u8>> {
        let key = self.inner.derive_key(password.as_bytes(), salt, 32)?;
        Ok(key.to_bytes())
    }

    /// Generate random bytes
    pub fn generate_random(&self, length: usize) -> Vec<u8> {
        self.inner.generate_random(length).to_bytes()
    }

    /// Generate a new key pair
    pub fn generate_key_pair(&self, key_type: KeyType) -> Result<Identity> {
        self.inner.generate_key_pair(key_type)
    }

    /// Store a key
    pub fn store_key(&self, key_id: &[u8], key_data: &[u8]) -> Result<()> {
        let secure_key = SecureBytes::from(key_data.to_vec());
        self.key_store.store_key(key_id, &secure_key)
    }

    /// Retrieve a key
    pub fn retrieve_key(&self, key_id: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(secure_key) = self.key_store.retrieve_key(key_id)? {
            Ok(Some(secure_key.to_bytes()))
        } else {
            Ok(None)
        }
    }

    /// Create protected message with integrity
    pub fn create_protected_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        let hash = self.hash(message);
        let mut protected = Vec::with_capacity(message.len() + hash.len());
        protected.extend_from_slice(message);
        protected.extend_from_slice(&hash);
        Ok(protected)
    }

    /// Extract and verify protected message
    pub fn extract_protected_message(&self, protected: &[u8]) -> Result<Vec<u8>> {
        if protected.len() < 32 {
            return Err(anyhow::anyhow!("Protected message too short"));
        }

        let message = &protected[..protected.len() - 32];
        let expected_hash = &protected[protected.len() - 32..];
        let actual_hash = self.hash(message);

        if expected_hash == actual_hash {
            Ok(message.to_vec())
        } else {
            Err(anyhow::anyhow!("Message integrity check failed"))
        }
    }

    /// Derive peer ID from public key
    fn derive_peer_id(public_key: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(public_key);
        format!("wolf_{}", hex::encode(&hash[..8]))
    }

    /// Rotate keys
    pub fn rotate_keys(&mut self) -> Result<()> {
        let new_identity = self.inner.generate_key_pair(KeyType::Ed25519)?;
        let new_peer_id = Self::derive_peer_id(&new_identity.public_key().to_bytes());

        // Store new identity
        self.identity_manager.store_identity(&new_identity)?;
        self.key_store.store_key(
            &new_identity.public_key().to_bytes(),
            &new_identity.private_key().to_bytes(),
        )?;

        self.peer_id = new_peer_id;

        tracing::info!("🔑 Keys rotated - new peer ID: {}", self.peer_id);
        Ok(())
    }

    /// Get crypto engine statistics
    pub fn get_stats(&self) -> CryptoStats {
        CryptoStats {
            peer_id: self.peer_id.clone(),
            cipher_suite: format!("{:?}", self.inner.config().cipher_suite),
            hash_function: format!("{:?}", self.inner.config().hash_function),
            security_level: self.inner.config().security_level as u32,
            memory_protection: self.inner.config().memory_protection as u32,
            keys_stored: self.key_store.list_keys().unwrap_or_default().len(),
            identities_stored: self
                .identity_manager
                .list_identities()
                .unwrap_or_default()
                .len(),
        }
    }
}

/// Cryptographic statistics
#[derive(Debug, Clone)]
pub struct CryptoStats {
    pub peer_id: String,
    pub cipher_suite: String,
    pub hash_function: String,
    pub security_level: u32,
    pub memory_protection: u32,
    pub keys_stored: usize,
    pub identities_stored: usize,
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create crypto engine")
    }
}

/// Utility functions for cryptographic operations
pub mod utils {
    use super::*;

    /// Generate a secure nonce
    pub fn generate_nonce(length: usize) -> SecureBytes {
        let crypto = CryptoEngine::new().unwrap();
        crypto.inner.generate_random(length)
    }

    /// Generate a secure salt
    pub fn generate_salt(length: usize) -> SecureBytes {
        generate_nonce(length)
    }

    /// Compare two byte arrays in constant time
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        use wolf_den::constant_time_eq;
        constant_time_eq(a, b)
    }

    /// Convert bytes to hex string
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// Convert hex string to bytes
    pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
        hex::decode(hex_str).map_err(|e| anyhow::anyhow!("Invalid hex: {}", e))
    }

    /// Securely wipe sensitive data
    pub fn secure_wipe(data: &mut [u8]) {
        for byte in data.iter_mut() {
            *byte = 0;
        }
    }

    /// Generate a secure random ID
    pub fn generate_secure_id() -> String {
        let crypto = CryptoEngine::new().unwrap();
        let random_bytes = crypto.inner.generate_random(16);
        hex::encode(random_bytes.to_bytes())
    }
}
