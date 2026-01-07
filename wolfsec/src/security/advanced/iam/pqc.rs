//! Post-Quantum Cryptography (PQC) Integration
//!
//! Post-quantum cryptographic algorithms for quantum-resistant security.
//! Uses wolf pack principles for secure quantum-resistant operations.

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::security::advanced::iam::{
    AuthenticationManager, AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig,
    SessionRequest, UserStatus,
};

/// PQC algorithm types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PQCAlgorithm {
    /// Kyber key encapsulation mechanism
    Kyber512,
    /// Kyber768 key encapsulation mechanism
    Kyber768,
    /// Kyber1024 key encapsulation mechanism
    Kyber1024,
    /// Dilithium signature scheme
    Dilithium2,
    /// Dilithium3 signature scheme
    Dilithium3,
    /// Dilithium5 signature scheme
    Dilithium5,
    /// Falcon signature scheme
    Falcon512,
    /// Falcon1024 signature scheme
    Falcon1024,
    /// SPHINCS+ hash-based signatures
    SphincsPlus128,
    /// SPHINCS+ hash-based signatures
    SphincsPlus192,
    /// SPHINCS+ hash-based signatures
    SphincsPlus256,
    /// FrodoKEM key encapsulation
    Frodo640AES,
    /// FrodoKEM key encapsulation
    Frodo976AES,
    /// FrodoKEM key encapsulation
    Frodo1344AES,
}

/// PQC key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCKeyPair {
    /// Key pair ID
    pub id: Uuid,
    /// Algorithm used
    pub algorithm: PQCAlgorithm,
    /// Public key
    pub public_key: Vec<u8>,
    /// Private key
    pub private_key: Vec<u8>,
    /// Created timestamp
    pub created_at: chrono::DateTime<Utc>,
    /// Expires at timestamp
    pub expires_at: Option<chrono::DateTime<Utc>>,
    /// Key usage
    pub key_usage: PQCKeyUsage,
    /// Active status
    pub active: bool,
}

/// PQC key usage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PQCKeyUsage {
    /// For encryption/decryption
    Encryption,
    /// For signing/verification
    Signing,
    /// For key exchange
    KeyExchange,
    /// For both encryption and signing
    DualPurpose,
}

/// PQC encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCData {
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Public key used for encryption
    pub public_key_id: Uuid,
    /// Algorithm used
    pub algorithm: PQCAlgorithm,
    /// Encrypted symmetric key (for hybrid encryption)
    pub encrypted_key: Option<Vec<u8>>,
    /// Initialization vector
    pub iv: Option<Vec<u8>>,
    /// Authentication tag
    pub auth_tag: Option<Vec<u8>>,
    /// Created timestamp
    pub created_at: chrono::DateTime<Utc>,
}

/// PQC signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCSignature {
    /// Signature ID
    pub id: Uuid,
    /// Signed data hash
    pub data_hash: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// Signing key ID
    pub signing_key_id: Uuid,
    /// Algorithm used
    pub algorithm: PQCAlgorithm,
    /// Signed at timestamp
    pub signed_at: chrono::DateTime<Utc>,
    /// Verified status
    pub verified: bool,
}

/// PQC key exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCKeyExchange {
    /// Exchange ID
    pub id: Uuid,
    /// Public key
    pub public_key: Vec<u8>,
    /// Shared secret
    pub shared_secret: Option<Vec<u8>>,
    /// Algorithm used
    pub algorithm: PQCAlgorithm,
    /// Created timestamp
    pub created_at: chrono::DateTime<Utc>,
    /// Expires at timestamp
    pub expires_at: chrono::DateTime<Utc>,
}

/// PQC provider trait
pub trait PQCProvider: Send + Sync {
    /// Generate key pair
    fn generate_key_pair(&self, algorithm: PQCAlgorithm) -> Result<PQCKeyPair>;

    /// Encrypt data
    fn encrypt(&self, data: &[u8], public_key: &[u8], algorithm: PQCAlgorithm) -> Result<PQCData>;

    /// Decrypt data
    fn decrypt(&self, data: &PQCData, private_key: &[u8]) -> Result<Vec<u8>>;

    /// Sign data
    fn sign(
        &self,
        data: &[u8],
        private_key: &[u8],
        algorithm: PQCAlgorithm,
    ) -> Result<PQCSignature>;

    /// Verify signature
    fn verify_signature(
        &self,
        data: &[u8],
        signature: &PQCSignature,
        public_key: &[u8],
    ) -> Result<bool>;

    /// Generate key exchange
    fn generate_key_exchange(&self, algorithm: PQCAlgorithm) -> Result<PQCKeyExchange>;

    /// Derive shared secret
    fn derive_shared_secret(
        &self,
        key_exchange: &PQCKeyExchange,
        private_key: &[u8],
    ) -> Result<Vec<u8>>;
}

/// Kyber PQC provider
pub struct KyberProvider;

impl PQCProvider for KyberProvider {
    fn generate_key_pair(&self, algorithm: PQCAlgorithm) -> Result<PQCKeyPair> {
        // In production, use actual Kyber implementation
        // This is a mock implementation for demonstration

        let key_size = match algorithm {
            PQCAlgorithm::Kyber512 => 1632,
            PQCAlgorithm::Kyber768 => 2400,
            PQCAlgorithm::Kyber1024 => 3168,
            _ => return Err(anyhow!("Invalid Kyber algorithm")),
        };

        let public_key = vec![0u8; key_size];
        let private_key = vec![1u8; key_size];

        Ok(PQCKeyPair {
            id: Uuid::new_v4(),
            algorithm,
            public_key,
            private_key,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(365)),
            key_usage: PQCKeyUsage::KeyExchange,
            active: true,
        })
    }

    fn encrypt(
        &self,
        _data: &[u8],
        _public_key: &[u8],
        _algorithm: PQCAlgorithm,
    ) -> Result<PQCData> {
        // Mock implementation
        Ok(PQCData {
            ciphertext: vec![2u8; 100],
            public_key_id: Uuid::new_v4(),
            algorithm: PQCAlgorithm::Kyber512,
            encrypted_key: Some(vec![3u8; 32]),
            iv: Some(vec![4u8; 16]),
            auth_tag: Some(vec![5u8; 16]),
            created_at: Utc::now(),
        })
    }

    fn decrypt(&self, _data: &PQCData, _private_key: &[u8]) -> Result<Vec<u8>> {
        // Mock implementation
        Ok(vec![6u8; 50])
    }

    fn sign(
        &self,
        _data: &[u8],
        _private_key: &[u8],
        _algorithm: PQCAlgorithm,
    ) -> Result<PQCSignature> {
        Err(anyhow!("Kyber does not support signing"))
    }

    fn verify_signature(
        &self,
        _data: &[u8],
        _signature: &PQCSignature,
        _public_key: &[u8],
    ) -> Result<bool> {
        Err(anyhow!("Kyber does not support signature verification"))
    }

    fn generate_key_exchange(&self, algorithm: PQCAlgorithm) -> Result<PQCKeyExchange> {
        let key_pair = self.generate_key_pair(algorithm.clone())?;

        Ok(PQCKeyExchange {
            id: Uuid::new_v4(),
            public_key: key_pair.public_key,
            shared_secret: None,
            algorithm,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
        })
    }

    fn derive_shared_secret(
        &self,
        _key_exchange: &PQCKeyExchange,
        _private_key: &[u8],
    ) -> Result<Vec<u8>> {
        // Mock implementation
        Ok(vec![7u8; 32])
    }
}

/// Dilithium PQC provider
pub struct DilithiumProvider;

impl PQCProvider for DilithiumProvider {
    fn generate_key_pair(&self, algorithm: PQCAlgorithm) -> Result<PQCKeyPair> {
        // In production, use actual Dilithium implementation
        let key_size = match algorithm {
            PQCAlgorithm::Dilithium2 => 1312,
            PQCAlgorithm::Dilithium3 => 1952,
            PQCAlgorithm::Dilithium5 => 2592,
            _ => return Err(anyhow!("Invalid Dilithium algorithm")),
        };

        let public_key = vec![8u8; key_size];
        let private_key = vec![9u8; key_size];

        Ok(PQCKeyPair {
            id: Uuid::new_v4(),
            algorithm,
            public_key,
            private_key,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(365)),
            key_usage: PQCKeyUsage::Signing,
            active: true,
        })
    }

    fn encrypt(
        &self,
        _data: &[u8],
        _public_key: &[u8],
        _algorithm: PQCAlgorithm,
    ) -> Result<PQCData> {
        Err(anyhow!("Dilithium does not support encryption"))
    }

    fn decrypt(&self, _data: &PQCData, _private_key: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!("Dilithium does not support decryption"))
    }

    fn sign(
        &self,
        _data: &[u8],
        _private_key: &[u8],
        algorithm: PQCAlgorithm,
    ) -> Result<PQCSignature> {
        let key_pair = self.generate_key_pair(algorithm.clone())?;

        Ok(PQCSignature {
            id: Uuid::new_v4(),
            data_hash: vec![10u8; 32],
            signature: vec![11u8; 2420],
            signing_key_id: key_pair.id,
            algorithm,
            signed_at: Utc::now(),
            verified: true,
        })
    }

    fn verify_signature(
        &self,
        _data: &[u8],
        _signature: &PQCSignature,
        _public_key: &[u8],
    ) -> Result<bool> {
        // Mock implementation
        Ok(true)
    }

    fn generate_key_exchange(&self, _algorithm: PQCAlgorithm) -> Result<PQCKeyExchange> {
        Err(anyhow!("Dilithium does not support key exchange"))
    }

    fn derive_shared_secret(
        &self,
        _key_exchange: &PQCKeyExchange,
        _private_key: &[u8],
    ) -> Result<Vec<u8>> {
        Err(anyhow!(
            "Dilithium does not support shared secret derivation"
        ))
    }
}

/// SPHINCS+ PQC provider
pub struct SphincsPlusProvider;

impl PQCProvider for SphincsPlusProvider {
    fn generate_key_pair(&self, algorithm: PQCAlgorithm) -> Result<PQCKeyPair> {
        let key_size = match algorithm {
            PQCAlgorithm::SphincsPlus128 => 64,
            PQCAlgorithm::SphincsPlus192 => 96,
            PQCAlgorithm::SphincsPlus256 => 128,
            _ => return Err(anyhow!("Invalid SPHINCS+ algorithm")),
        };

        let public_key = vec![12u8; key_size];
        let private_key = vec![13u8; key_size];

        Ok(PQCKeyPair {
            id: Uuid::new_v4(),
            algorithm,
            public_key,
            private_key,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(365)),
            key_usage: PQCKeyUsage::Signing,
            active: true,
        })
    }

    fn encrypt(
        &self,
        _data: &[u8],
        _public_key: &[u8],
        _algorithm: PQCAlgorithm,
    ) -> Result<PQCData> {
        Err(anyhow!("SPHINCS+ does not support encryption"))
    }

    fn decrypt(&self, _data: &PQCData, _private_key: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!("SPHINCS+ does not support decryption"))
    }

    fn sign(
        &self,
        _data: &[u8],
        _private_key: &[u8],
        algorithm: PQCAlgorithm,
    ) -> Result<PQCSignature> {
        let key_pair = self.generate_key_pair(algorithm.clone())?;

        Ok(PQCSignature {
            id: Uuid::new_v4(),
            data_hash: vec![14u8; 32],
            signature: vec![15u8; 8000],
            signing_key_id: key_pair.id,
            algorithm,
            signed_at: Utc::now(),
            verified: true,
        })
    }

    fn verify_signature(
        &self,
        _data: &[u8],
        _signature: &PQCSignature,
        _public_key: &[u8],
    ) -> Result<bool> {
        // Mock implementation
        Ok(true)
    }

    fn generate_key_exchange(&self, _algorithm: PQCAlgorithm) -> Result<PQCKeyExchange> {
        Err(anyhow!("SPHINCS+ does not support key exchange"))
    }

    fn derive_shared_secret(
        &self,
        _key_exchange: &PQCKeyExchange,
        _private_key: &[u8],
    ) -> Result<Vec<u8>> {
        Err(anyhow!(
            "SPHINCS+ does not support shared secret derivation"
        ))
    }
}

/// PQC manager
pub struct PQCManager {
    /// PQC providers
    providers: Arc<Mutex<HashMap<PQCAlgorithm, Box<dyn PQCProvider>>>>,
    /// Key pairs
    key_pairs: Arc<Mutex<HashMap<Uuid, PQCKeyPair>>>,
    /// Signatures
    signatures: Arc<Mutex<HashMap<Uuid, PQCSignature>>>,
    /// Key exchanges
    key_exchanges: Arc<Mutex<HashMap<Uuid, PQCKeyExchange>>>,
    /// Configuration
    config: IAMConfig,
}

impl PQCManager {
    /// Create new PQC manager
    pub async fn new(config: IAMConfig) -> Result<Self> {
        info!("🔐 Initializing PQC Manager");

        let mut providers: HashMap<PQCAlgorithm, Box<dyn PQCProvider>> = HashMap::new();

        // Add Kyber providers
        providers.insert(PQCAlgorithm::Kyber512, Box::new(KyberProvider));
        providers.insert(PQCAlgorithm::Kyber768, Box::new(KyberProvider));
        providers.insert(PQCAlgorithm::Kyber1024, Box::new(KyberProvider));

        // Add Dilithium providers
        providers.insert(PQCAlgorithm::Dilithium2, Box::new(DilithiumProvider));
        providers.insert(PQCAlgorithm::Dilithium3, Box::new(DilithiumProvider));
        providers.insert(PQCAlgorithm::Dilithium5, Box::new(DilithiumProvider));

        // Add SPHINCS+ providers
        providers.insert(PQCAlgorithm::SphincsPlus128, Box::new(SphincsPlusProvider));
        providers.insert(PQCAlgorithm::SphincsPlus192, Box::new(SphincsPlusProvider));
        providers.insert(PQCAlgorithm::SphincsPlus256, Box::new(SphincsPlusProvider));

        let manager = Self {
            providers: Arc::new(Mutex::new(providers)),
            key_pairs: Arc::new(Mutex::new(HashMap::new())),
            signatures: Arc::new(Mutex::new(HashMap::new())),
            key_exchanges: Arc::new(Mutex::new(HashMap::new())),
            config,
        };

        info!("✅ PQC Manager initialized successfully");
        Ok(manager)
    }

    /// Generate PQC key pair
    pub async fn generate_key_pair(&self, algorithm: PQCAlgorithm) -> Result<PQCKeyPair> {
        debug!("🔐 Generating PQC key pair for algorithm: {:?}", algorithm);

        let providers = self.providers.lock().await;
        let provider = providers
            .get(&algorithm)
            .ok_or_else(|| anyhow!("PQC provider not found for algorithm: {:?}", algorithm))?;

        let key_pair = provider.generate_key_pair(algorithm)?;

        // Store key pair
        let mut key_pairs = self.key_pairs.lock().await;
        key_pairs.insert(key_pair.id, key_pair.clone());

        info!("✅ PQC key pair generated: {}", key_pair.id);
        Ok(key_pair)
    }

    /// Encrypt data with PQC
    pub async fn encrypt(
        &self,
        data: &[u8],
        public_key_id: Uuid,
        algorithm: PQCAlgorithm,
    ) -> Result<PQCData> {
        debug!("🔐 Encrypting data with PQC algorithm: {:?}", algorithm);

        let key_pairs = self.key_pairs.lock().await;
        let key_pair = key_pairs
            .get(&public_key_id)
            .ok_or_else(|| anyhow!("Key pair not found: {}", public_key_id))?;

        let providers = self.providers.lock().await;
        let provider = providers
            .get(&algorithm)
            .ok_or_else(|| anyhow!("PQC provider not found for algorithm: {:?}", algorithm))?;

        let encrypted_data = provider.encrypt(data, &key_pair.public_key, algorithm.clone())?;

        // Store encrypted data
        let mut signatures = self.signatures.lock().await;
        let signature = PQCSignature {
            id: Uuid::new_v4(),
            data_hash: vec![], // Would be calculated from data
            signature: vec![], // Would be calculated
            signing_key_id: public_key_id,
            algorithm,
            signed_at: Utc::now(),
            verified: false,
        };
        signatures.insert(signature.id, signature);

        info!("✅ Data encrypted with PQC");
        Ok(encrypted_data)
    }

    /// Decrypt data with PQC
    pub async fn decrypt(&self, data: &PQCData, private_key_id: Uuid) -> Result<Vec<u8>> {
        debug!("🔐 Decrypting data with PQC");

        let key_pairs = self.key_pairs.lock().await;
        let key_pair = key_pairs
            .get(&private_key_id)
            .ok_or_else(|| anyhow!("Key pair not found: {}", private_key_id))?;

        let providers = self.providers.lock().await;
        let provider = providers
            .get(&data.algorithm)
            .ok_or_else(|| anyhow!("PQC provider not found for algorithm: {:?}", data.algorithm))?;

        let decrypted_data = provider.decrypt(data, &key_pair.private_key)?;

        info!("✅ Data decrypted with PQC");
        Ok(decrypted_data)
    }

    /// Sign data with PQC
    pub async fn sign(
        &self,
        data: &[u8],
        private_key_id: Uuid,
        algorithm: PQCAlgorithm,
    ) -> Result<PQCSignature> {
        debug!("🔐 Signing data with PQC algorithm: {:?}", algorithm);

        let key_pairs = self.key_pairs.lock().await;
        let key_pair = key_pairs
            .get(&private_key_id)
            .ok_or_else(|| anyhow!("Key pair not found: {}", private_key_id))?;

        let providers = self.providers.lock().await;
        let provider = providers
            .get(&algorithm)
            .ok_or_else(|| anyhow!("PQC provider not found for algorithm: {:?}", algorithm))?;

        let signature = provider.sign(data, &key_pair.private_key, algorithm)?;

        // Store signature
        let mut signatures = self.signatures.lock().await;
        signatures.insert(signature.id, signature.clone());

        info!("✅ Data signed with PQC");
        Ok(signature)
    }

    /// Verify PQC signature
    pub async fn verify_signature(
        &self,
        data: &[u8],
        signature_id: Uuid,
    ) -> Result<PQCVerificationResult> {
        debug!("🔐 Verifying PQC signature: {}", signature_id);

        let signatures = self.signatures.lock().await;
        let signature = signatures
            .get(&signature_id)
            .ok_or_else(|| anyhow!("Signature not found: {}", signature_id))?;

        let key_pairs = self.key_pairs.lock().await;
        let key_pair = key_pairs
            .get(&signature.signing_key_id)
            .ok_or_else(|| anyhow!("Key pair not found: {}", signature.signing_key_id))?;

        let providers = self.providers.lock().await;
        let provider = providers.get(&signature.algorithm).ok_or_else(|| {
            anyhow!(
                "PQC provider not found for algorithm: {:?}",
                signature.algorithm
            )
        })?;

        let is_valid = provider.verify_signature(data, signature, &key_pair.public_key)?;

        let verification_result = PQCVerificationResult {
            signature_id,
            valid: is_valid,
            algorithm: signature.algorithm.clone(),
            verified_at: Utc::now(),
            error_message: if is_valid {
                None
            } else {
                Some("Signature verification failed".to_string())
            },
        };

        info!("✅ PQC signature verification completed: {}", is_valid);
        Ok(verification_result)
    }

    /// Generate PQC key exchange
    pub async fn generate_key_exchange(&self, algorithm: PQCAlgorithm) -> Result<PQCKeyExchange> {
        debug!(
            "🔐 Generating PQC key exchange for algorithm: {:?}",
            algorithm
        );

        let providers = self.providers.lock().await;
        let provider = providers
            .get(&algorithm)
            .ok_or_else(|| anyhow!("PQC provider not found for algorithm: {:?}", algorithm))?;

        let key_exchange = provider.generate_key_exchange(algorithm)?;

        // Store key exchange
        let mut key_exchanges = self.key_exchanges.lock().await;
        key_exchanges.insert(key_exchange.id, key_exchange.clone());

        info!("✅ PQC key exchange generated: {}", key_exchange.id);
        Ok(key_exchange)
    }

    /// Derive shared secret
    pub async fn derive_shared_secret(
        &self,
        key_exchange_id: Uuid,
        private_key_id: Uuid,
    ) -> Result<Vec<u8>> {
        debug!(
            "🔐 Deriving shared secret for key exchange: {}",
            key_exchange_id
        );

        let key_exchanges = self.key_exchanges.lock().await;
        let key_exchange = key_exchanges
            .get(&key_exchange_id)
            .ok_or_else(|| anyhow!("Key exchange not found: {}", key_exchange_id))?;

        let key_pairs = self.key_pairs.lock().await;
        let key_pair = key_pairs
            .get(&private_key_id)
            .ok_or_else(|| anyhow!("Key pair not found: {}", private_key_id))?;

        let providers = self.providers.lock().await;
        let provider = providers.get(&key_exchange.algorithm).ok_or_else(|| {
            anyhow!(
                "PQC provider not found for algorithm: {:?}",
                key_exchange.algorithm
            )
        })?;

        let shared_secret = provider.derive_shared_secret(key_exchange, &key_pair.private_key)?;

        info!(
            "✅ Shared secret derived for key exchange: {}",
            key_exchange_id
        );
        Ok(shared_secret)
    }

    /// Get PQC statistics
    pub async fn get_stats(&self) -> PQCStats {
        let key_pairs = self.key_pairs.lock().await;
        let signatures = self.signatures.lock().await;
        let key_exchanges = self.key_exchanges.lock().await;

        PQCStats {
            total_key_pairs: key_pairs.len(),
            total_signatures: signatures.len(),
            total_key_exchanges: key_exchanges.len(),
            last_update: Utc::now(),
        }
    }

    /// Clean up expired keys and exchanges
    pub async fn cleanup_expired_items(&self) -> Result<()> {
        let now = Utc::now();
        let mut key_pairs = self.key_pairs.lock().await;
        let mut key_exchanges = self.key_exchanges.lock().await;

        // Clean up expired key pairs
        key_pairs.retain(|_, key_pair| {
            key_pair.expires_at.map_or(true, |exp| exp > now) && key_pair.active
        });

        // Clean up expired key exchanges
        key_exchanges.retain(|_, key_exchange| now < key_exchange.expires_at);

        info!("✅ Cleaned up expired PQC items");
        Ok(())
    }

    /// Get key pair by ID
    pub async fn get_key_pair(&self, key_id: Uuid) -> Option<PQCKeyPair> {
        let key_pairs = self.key_pairs.lock().await;
        key_pairs.get(&key_id).cloned()
    }

    /// Get signature by ID
    pub async fn get_signature(&self, signature_id: Uuid) -> Option<PQCSignature> {
        let signatures = self.signatures.lock().await;
        signatures.get(&signature_id).cloned()
    }
}

/// PQC verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCVerificationResult {
    /// Signature ID
    pub signature_id: Uuid,
    /// Verification success
    pub valid: bool,
    /// Algorithm used
    pub algorithm: PQCAlgorithm,
    /// Verified at timestamp
    pub verified_at: chrono::DateTime<Utc>,
    /// Error message
    pub error_message: Option<String>,
}

/// PQC statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCStats {
    /// Total key pairs
    pub total_key_pairs: usize,
    /// Total signatures
    pub total_signatures: usize,
    /// Total key exchanges
    pub total_key_exchanges: usize,
    /// Last update timestamp
    pub last_update: chrono::DateTime<Utc>,
}

impl From<PQCVerificationResult> for AuthenticationResult {
    fn from(pqc_result: PQCVerificationResult) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(), // Would be extracted from signature context
            method: AuthenticationMethod::Certificate,
            success: pqc_result.valid,
            timestamp: pqc_result.verified_at,
            ip_address: "unknown".to_string(), // Would be extracted from request
            user_agent: "unknown".to_string(), // Would be extracted from request
            mfa_required: false,
            mfa_completed: true,
            session_id: None,
            error_message: pqc_result.error_message,
        }
    }
}
