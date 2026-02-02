use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Database-backed vault with persistent storage
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Vault {
    /// List of encrypted entries.
    pub entries: Vec<VaultEntry>,
}

/// Metadata for vault entries stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Unique identifier for the entry.
    pub id: String,
    /// Type of the secret (e.g., "SSH", "BitLocker").
    pub secret_type: String,
    /// Human-readable description.
    pub description: String,
    /// Timestamp when the entry was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Types of secrets that can be stored in the vault
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    /// BitLocker recovery key.
    BitLocker,
    /// SSH private key.
    SSH,
    /// PGP private key.
    PGP,
    /// Cryptocurrency wallet seed.
    CryptoSeed,
    /// API key or token.
    APIKey,
    /// Generic secret data.
    Generic,
}

/// A single encrypted secret entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique identifier for this entry.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Type of the secret.
    pub secret_type: SecretType,
    /// Encrypted secret data.
    #[serde(with = "hex_serde")]
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    #[serde(with = "hex_serde")]
    pub nonce: Vec<u8>,
}

impl Vault {
    /// Creates a new, empty vault.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a secret to the vault, encrypting it with the provided Master Key.
    pub fn add_secret(
        &mut self,
        master_key: &[u8; 32],
        id: &str,
        secret_type: SecretType,
        plaintext: &[u8],
    ) -> Result<()> {
        let key = Key::<Aes256Gcm>::from_slice(master_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failure: {}", e))?;

        self.entries.push(VaultEntry {
            id: id.to_string(),
            description: format!("{:?} Secret: {}", secret_type, id),
            secret_type,
            ciphertext,
            nonce: nonce.to_vec(),
        });

        Ok(())
    }

    /// Decrypts a secret from the vault using the provided Master Key.
    pub fn get_secret(&self, master_key: &[u8; 32], id: &str) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .context("Secret not found")?;

        let key = Key::<Aes256Gcm>::from_slice(master_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&entry.nonce);

        let plaintext = cipher
            .decrypt(nonce, entry.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failure (Wrong Master Key?): {}", e))?;

        Ok(plaintext)
    }

    /// Lists public metadata of all entries.
    pub fn list_entries(&self) -> Vec<(String, SecretType)> {
        self.entries
            .iter()
            .map(|e| (e.id.clone(), e.secret_type.clone()))
            .collect()
    }

    /// Serializes the vault to JSON for database storage.
    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))
    }

    /// Deserializes vault from JSON.
    pub fn deserialize(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))
    }

    /// Saves vault entries to WolfDb.
    pub async fn save_to_db(&self, store: &mut super::storage::WolfStore) -> Result<()> {
        println!("[Vault] Saving {} entries to database", self.entries.len());

        for entry in &self.entries {
            store
                .save_vault_entry(
                    &entry.id,
                    &format!("{:?}", entry.secret_type),
                    &entry.description,
                    &hex::encode(&entry.ciphertext),
                    &hex::encode(&entry.nonce),
                )
                .await?;
            println!("[Vault] Saved entry: {}", entry.id);
        }

        println!("[Vault] All entries saved successfully");
        Ok(())
    }

    /// Loads vault entries from WolfDb.
    pub async fn load_from_db(store: &mut super::storage::WolfStore) -> Result<Self> {
        println!("[Vault] Loading entries from database");

        let entry_ids = store.list_vault_entries().await?;

        let mut vault = Self::new();

        for entry_id in entry_ids {
            if let Some(metadata) = store.find_vault_entry(&entry_id).await? {
                let ciphertext_hex = metadata
                    .get("ciphertext_hex")
                    .context("Missing ciphertext")?;
                let nonce_hex = metadata.get("nonce_hex").context("Missing nonce")?;
                let secret_type_str = metadata.get("secret_type").context("Missing secret_type")?;

                let secret_type = match secret_type_str.as_str() {
                    "BitLocker" => SecretType::BitLocker,
                    "SSH" => SecretType::SSH,
                    "PGP" => SecretType::PGP,
                    "CryptoSeed" => SecretType::CryptoSeed,
                    "APIKey" => SecretType::APIKey,
                    _ => SecretType::Generic,
                };

                let entry = VaultEntry {
                    id: entry_id.clone(),
                    description: metadata
                        .get("description")
                        .unwrap_or(&"Unknown".to_string())
                        .clone(),
                    secret_type,
                    ciphertext: hex::decode(ciphertext_hex)
                        .map_err(|e| anyhow::anyhow!("Invalid hex: {}", e))?,
                    nonce: hex::decode(nonce_hex)
                        .map_err(|e| anyhow::anyhow!("Invalid hex: {}", e))?,
                };

                vault.entries.push(entry);
                println!("[Vault] Loaded entry: {}", entry_id);
            }
        }

        println!(
            "[Vault] Loaded {} entries from database",
            vault.entries.len()
        );
        Ok(vault)
    }

    /// Exports vault metadata (without secrets) for listing.
    pub fn export_metadata(&self) -> Vec<VaultMetadata> {
        self.entries
            .iter()
            .map(|e| VaultMetadata {
                id: e.id.clone(),
                secret_type: format!("{:?}", e.secret_type),
                description: e.description.clone(),
                created_at: chrono::Utc::now(),
            })
            .collect()
    }
}

// Helper module for hex serialization of byte vectors
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_encryption_cycle() {
        let mut vault = Vault::new();
        let master_key = [0x42u8; 32]; // Fixed key for test

        // Add secrets
        vault
            .add_secret(&master_key, "ssh_prod", SecretType::SSH, b"ssh-rsa AAAA...")
            .unwrap();
        vault
            .add_secret(
                &master_key,
                "wallet_seed",
                SecretType::CryptoSeed,
                b"abandon abandon...",
            )
            .unwrap();

        // Verify listing
        let list = vault.list_entries();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "ssh_prod");

        // Decrypt success
        let recovered_ssh = vault.get_secret(&master_key, "ssh_prod").unwrap();
        assert_eq!(recovered_ssh, b"ssh-rsa AAAA...");

        // Decrypt failure (wrong key)
        let wrong_key = [0x00u8; 32];
        let res = vault.get_secret(&wrong_key, "ssh_prod");
        assert!(res.is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut vault = Vault::new();
        let master_key = [0x42u8; 32];

        vault
            .add_secret(&master_key, "test", SecretType::SSH, b"secret data")
            .unwrap();

        let json = vault.serialize().unwrap();
        let restored = Vault::deserialize(&json).unwrap();

        assert_eq!(vault.entries.len(), restored.entries.len());
        assert_eq!(vault.entries[0].id, restored.entries[0].id);
    }
}
