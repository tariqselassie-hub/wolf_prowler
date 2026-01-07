pub mod engine;
pub mod model;
pub mod pqc_pool;
pub mod partition;

use crate::crypto::{CryptoManager, EncryptedData};
use crate::vector::VectorIndex;
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use rayon::prelude::*;
use zeroize::Zeroizing;
use std::collections::HashMap;

pub use partition::Partition;

pub struct WolfDbStorage {
    path: String,
    // Multiple storage engines, one per partition
    engines: HashMap<Partition, engine::StorageEngine>,
    // Multiple vector indices, one per partition that supports vectors
    vector_indices: HashMap<Partition, VectorIndex>,
    crypto: CryptoManager,
    pqc_pool: Option<pqc_pool::PqcWorkerPool>,
    kem_sk: Option<Zeroizing<Vec<u8>>>,
    kem_pk: Option<Vec<u8>>,
    dsa_sk: Option<Zeroizing<Vec<u8>>>,
    dsa_pk: Option<Vec<u8>>,
    dsa_keypair: Option<crate::crypto::signature::Keypair>,
}

impl WolfDbStorage {
    pub fn open(path: &str) -> Result<Self> {
        let mut engines = HashMap::new();
        let mut vector_indices = HashMap::new();
        
        // Create directory structure for partitions
        std::fs::create_dir_all(path)?;
        std::fs::create_dir_all(&format!("{}/relational", path))?;
        std::fs::create_dir_all(&format!("{}/vector", path))?;
        std::fs::create_dir_all(&format!("{}/indices", path))?;
        
        // Open storage engine for each partition
        for partition in [Partition::Relational, Partition::Vector, Partition::Hybrid] {
            let db_path = partition.get_db_path(path);
            let engine = engine::StorageEngine::open(&db_path)?;
            engines.insert(partition, engine);
            
            // Initialize vector index for partitions that support vectors
            if partition.supports_vectors() {
                let vector_path = partition.get_index_path(path, "hnsw_index");
                let index = if std::path::Path::new(&vector_path).exists() {
                    match VectorIndex::load(&vector_path) {
                        Ok(index) => index,
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load {} partition vector index: {}. Starting fresh.",
                                partition.name(),
                                e
                            );
                            VectorIndex::new(crate::vector::VectorConfig::default())
                        }
                    }
                } else {
                    VectorIndex::new(crate::vector::VectorConfig::default())
                };
                vector_indices.insert(partition, index);
            }
        }

        let crypto = CryptoManager::new();

        Ok(Self {
            path: path.to_string(),
            engines,
            vector_indices,
            crypto,
            pqc_pool: None,
            kem_sk: None,
            kem_pk: None,
            dsa_sk: None,
            dsa_pk: None,
            dsa_keypair: None,
        })
    }

    pub fn is_initialized(&self) -> bool {
        std::path::Path::new(&format!("{}/keystore.json", self.path)).exists()
    }

    pub fn initialize_keystore(&mut self, password: &str, hsm_pin: Option<&str>) -> Result<()> {
        let (kem_sk, kem_pk) = crate::crypto::kem::generate_keypair()?;
        let (dsa_sk, dsa_pk) = crate::crypto::signature::generate_keypair()?;

        let mut keystore = crate::crypto::keystore::Keystore::create_encrypted(
            &kem_sk, &kem_pk, &dsa_sk, &dsa_pk, password,
        )?;

        if let Some(pin) = hsm_pin {
            keystore.hsm_enabled = true;
            let wrapped = crate::crypto::hsm::MockHsm::wrap(pin, password.as_bytes());
            keystore.hsm_wrapped_key = Some(general_purpose::STANDARD.encode(wrapped));
        }

        crate::crypto::keystore::Keystore::save(
            &keystore,
            &format!("{}/keystore.json", self.path),
        )?;

        self.kem_sk = Some(Zeroizing::new(kem_sk));
        self.kem_pk = Some(kem_pk);
        self.dsa_sk = Some(Zeroizing::new(dsa_sk));
        self.dsa_pk = Some(dsa_pk);

        Ok(())
    }

    pub fn unlock(&mut self, password: &str, hsm_pin: Option<&str>) -> Result<()> {
        let keystore =
            crate::crypto::keystore::Keystore::load(&format!("{}/keystore.json", self.path))?;

        if keystore.hsm_enabled {
            let pin = hsm_pin.context("HSM PIN required for this database")?;
            let wrapped_b64 = keystore
                .hsm_wrapped_key
                .as_ref()
                .context("No wrapped key")?;
            let wrapped = general_purpose::STANDARD.decode(wrapped_b64)?;
            crate::crypto::hsm::MockHsm::unwrap(pin, &wrapped)?;
        }

        let (kem_sk, maybe_dsa_sk) = crate::crypto::keystore::Keystore::unlock_keys(&keystore, password)?;
        self.kem_sk = Some(kem_sk);
        self.kem_pk = Some(keystore.pk.clone());

        if let Some(dsa_sk) = maybe_dsa_sk {
            self.dsa_sk = Some(dsa_sk.clone());
            // Safe unwrap because if encrypted_dsa_sk existed (returned dsa_sk), dsa_pk should exist too
            // or we fall back to empty if really corrupted, but we should probably error or handle it.
            // For now, let's assume if dsa_sk is present, dsa_pk is too.
            let pk = keystore.dsa_pk.clone().ok_or_else(|| anyhow::anyhow!("DSA PK missing but SK present"))?;
            self.dsa_pk = Some(pk.clone());
            self.dsa_keypair = Some(crate::crypto::signature::reconstruct_keypair(&dsa_sk)?);
        } else {
            tracing::info!("Migrating keystore: Generating missing DSA keys...");
            let (new_dsa_sk, new_dsa_pk) = crate::crypto::signature::generate_keypair()?;
            
            // Re-encrypt everything to save the new DSA keys
            let kem_sk_bytes = self.kem_sk.as_ref().unwrap().as_slice();
            let kem_pk_bytes = self.kem_pk.as_ref().unwrap();

            let mut new_keystore = crate::crypto::keystore::Keystore::create_encrypted(
                kem_sk_bytes,
                kem_pk_bytes,
                &new_dsa_sk,
                &new_dsa_pk,
                password
            )?;
            // Preserve HSM settings from old keystore
            new_keystore.hsm_enabled = keystore.hsm_enabled;
            new_keystore.hsm_wrapped_key = keystore.hsm_wrapped_key.clone();

            crate::crypto::keystore::Keystore::save(
                &new_keystore,
                &format!("{}/keystore.json", self.path),
            )?;

            self.dsa_sk = Some(Zeroizing::new(new_dsa_sk));
            self.dsa_pk = Some(new_dsa_pk);
            // We need to fetch the keypair structure properly
            let dsa_sk_zeroized = self.dsa_sk.as_ref().unwrap();
             self.dsa_keypair = Some(crate::crypto::signature::reconstruct_keypair(dsa_sk_zeroized)?);
        }

        Ok(())
    }

    /// Get the storage engine for a given partition
    fn get_engine(&self, partition: Partition) -> Result<&engine::StorageEngine> {
        self.engines.get(&partition)
            .ok_or_else(|| anyhow::anyhow!("Partition {:?} not initialized", partition))
    }
    
    /// Get the vector index for a given partition
    fn get_vector_index(&self, partition: Partition) -> Result<&VectorIndex> {
        self.vector_indices.get(&partition)
            .ok_or_else(|| anyhow::anyhow!("Vector index for partition {:?} not available", partition))
    }
    
    /// Get mutable vector index for a given partition
    fn get_vector_index_mut(&mut self, partition: Partition) -> Result<&mut VectorIndex> {
        self.vector_indices.get_mut(&partition)
            .ok_or_else(|| anyhow::anyhow!("Vector index for partition {:?} not available", partition))
    }

    pub fn save(&self) -> Result<()> {
        // Save all vector indices
        for (partition, index) in &self.vector_indices {
            let vector_path = partition.get_index_path(&self.path, "hnsw_index");
            index.save(&vector_path)?;
        }
        Ok(())
    }

    pub fn get_active_pk(&self) -> Option<&[u8]> {
        self.kem_pk.as_deref()
    }

    pub fn get_active_sk(&self) -> Option<&[u8]> {
        self.kem_sk.as_ref().map(|s| s.as_slice())
    }

    pub fn insert_record(
        &mut self,
        table: &str,
        record: &model::Record,
        kem_pk: &[u8],
    ) -> Result<()> {
        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(table);
        
        // Validate vector usage
        if !partition.supports_vectors() && record.vector.is_some() {
            tracing::warn!("Vector data provided for relational partition '{}', ignoring vector", table);
        }
        
        let serialized = bincode::serialize(record)?;
        let encrypted =
            self.crypto
                .encrypt_at_rest(&serialized, kem_pk, self.dsa_keypair.as_ref())?;
        let bin = bincode::serialize(&encrypted)?;
        
        // Insert into appropriate partition's engine
        let engine = self.get_engine(partition)?;
        engine.insert(&clean_table, record.id.as_bytes(), bin)?;

        // Update secondary index for metadata filtering
        self.index_metadata(table, record)?;

        // Insert vector if supported and present
        if partition.supports_vectors() {
            if let Some(vec) = &record.vector {
                let vector_index = self.get_vector_index_mut(partition)?;
                vector_index.insert(&record.id, vec.clone())?;
            }
        }
        Ok(())
    }

    pub fn use_async_pqc(&mut self, workers: usize) {
        self.pqc_pool = Some(pqc_pool::PqcWorkerPool::new(workers));
    }

    pub async fn insert_record_async(
        &mut self,
        table: String,
        record: model::Record,
        kem_pk: Vec<u8>,
    ) -> Result<()> {
        let pool = self
            .pqc_pool
            .as_ref()
            .context("PQC Pool not initialized. Call use_async_pqc() first.")?;

        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(&table);
        
        // Pass a clone of dsa_keypair if available
        let dsa_keypair = self.dsa_keypair.clone();

        let rx = pool.submit(record, kem_pk, dsa_keypair).await?;
        let (record, bin) = rx.await??;

        let engine = self.get_engine(partition)?;
        engine.insert(&clean_table, record.id.as_bytes(), bin)?;
        self.index_metadata(&table, &record)?;

        if partition.supports_vectors() {
            if let Some(vec) = record.vector {
                let vector_index = self.get_vector_index_mut(partition)?;
                vector_index.insert(&record.id, vec)?;
            }
        }

        Ok(())
    }

    pub fn insert_batch_records(
        &mut self,
        table: &str,
        records: Vec<model::Record>,
        kem_pk: &[u8],
    ) -> Result<()> {
        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(table);
        
        let dsa_keypair = self.dsa_keypair.as_ref();

        // 1. Parallel Encryption and Signing
        let processed_records: Result<Vec<_>> = records
            .into_par_iter()
            .map(|record| {
                let serialized = bincode::serialize(&record)?;
                let encrypted = self
                    .crypto
                    .encrypt_at_rest(&serialized, kem_pk, dsa_keypair)?;
                let bin = bincode::serialize(&encrypted)?;
                Ok((record, bin))
            })
            .collect();

        let processed = processed_records?;

        // 2. Sequential Storage Engine Insertion and Vector Preparation
        let engine = self.get_engine(partition)?;
        let mut vector_batch = Vec::with_capacity(processed.len());
        for (record, bin) in processed {
            engine.insert(&clean_table, record.id.as_bytes(), bin)?;
            self.index_metadata(table, &record)?;
            if partition.supports_vectors() {
                if let Some(vec) = record.vector {
                    vector_batch.push((record.id, vec));
                }
            }
        }

        // 3. Batch Vector Insertion
        if !vector_batch.is_empty() && partition.supports_vectors() {
            let vector_index = self.get_vector_index_mut(partition)?;
            vector_index.insert_batch(vector_batch)?;
        }

        Ok(())
    }

    fn index_metadata(&self, table: &str, record: &model::Record) -> Result<()> {
        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(table);
        
        let index_table = format!("idx_{}", clean_table);
        let engine = self.get_engine(partition)?;
        
        for (field, value) in &record.data {
            let key = format!("{}:{}:{}", field, value, record.id);
            engine.insert(&index_table, key.as_bytes(), vec![])?;
        }
        Ok(())
    }

    pub fn find_by_metadata(
        &self,
        table: &str,
        field: &str,
        value: &str,
        kem_sk: &[u8],
    ) -> Result<Vec<model::Record>> {
        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(table);
        
        let index_table = format!("idx_{}", clean_table);
        let prefix = format!("{}:{}:", field, value);
        let prefix_bytes = prefix.as_bytes();

        let engine = self.get_engine(partition)?;
        let matching_record_ids: Vec<String> = engine
            .scan_prefix(&index_table, prefix_bytes)?
            .into_iter()
            .filter_map(|(key, _)| {
                let key_str = String::from_utf8_lossy(&key);
                key_str.strip_prefix(&prefix).map(|s| s.to_string())
            })
            .collect();

        let final_results: Result<Vec<_>> = matching_record_ids
            .into_par_iter()
            .map(|record_id| {
                self.get_record(table, &record_id, kem_sk)
            })
            .collect();
            
        Ok(final_results?.into_iter().flatten().collect())
    }

    pub fn list_keys(&self, table: &str) -> Result<Vec<String>> {
        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(table);
        
        let engine = self.get_engine(partition)?;
        let keys = engine.scan_keys(&clean_table)?;
        let mut string_keys = Vec::new();
        for k in keys {
            if let Ok(s) = String::from_utf8(k) {
                string_keys.push(s);
            }
        }
        Ok(string_keys)
    }

    pub fn search_hybrid(
        &self,
        table: &str,
        query_vector: &[f32],
        k: usize,
        filter_field: &str,
        filter_value: &str,
        kem_sk: &[u8],
    ) -> Result<Vec<(model::Record, f32)>> {
        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(table);
        if !partition.supports_vectors() {
            return Err(anyhow::anyhow!("Partition does not support vector operations"));
        }
        
        let index_table = format!("idx_{}", clean_table);
        let prefix = format!("{}:{}:", filter_field, filter_value);
        let prefix_bytes = prefix.as_bytes();

        // 1. Scan secondary index for matching record IDs
        let engine = self.get_engine(partition)?;
        let matching_record_ids: Vec<String> = engine
            .scan_prefix(&index_table, prefix_bytes)?
            .into_iter()
            .filter_map(|(key, _)| {
                let key_str = String::from_utf8_lossy(&key);
                key_str.strip_prefix(&prefix).map(|s| s.to_string())
            })
            .collect();

        if matching_record_ids.is_empty() {
            return Ok(vec![]);
        }

        let vector_index = self.get_vector_index(partition)?;

        // 2. Map record IDs to internal IDs for vector filtering
        let allowed_internal_ids = vector_index.get_internal_ids(&matching_record_ids);

        // 3. Perform internal filtered vector search
        let results =
            vector_index
                .search_with_filter(query_vector, k, Some(&allowed_internal_ids));

        // 4. Retrieve and decrypt records
        let final_results: Result<Vec<_>> = results
            .into_par_iter()
            .map(|(record_id, distance)| {
                let rec = self.get_record(table, &record_id, kem_sk)?;
                Ok(rec.map(|r| (r, distance)))
            })
            .collect();

        Ok(final_results?.into_iter().flatten().collect())
    }

    pub fn get_record(
        &self,
        table: &str,
        id: &str,
        kem_sk: &[u8],
    ) -> Result<Option<model::Record>> {
        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(table);
        
        let engine = self.get_engine(partition)?;
        let bin = engine.get(&clean_table, id.as_bytes())?;
        if let Some(encrypted_bin) = bin {
            let encrypted: EncryptedData = bincode::deserialize(&encrypted_bin)?;
            let dsa_pk_ref = self.dsa_pk.as_deref();
            let decrypted = self
                .crypto
                .decrypt_at_rest(&encrypted, kem_sk, dsa_pk_ref)?;
            let record: model::Record = bincode::deserialize(&decrypted)?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    pub fn delete_record(&mut self, table: &str, id: &str) -> Result<bool> {
        // Determine partition from table name
        let (partition, clean_table) = Partition::from_table(table);
        
        let engine = self.get_engine(partition)?;
        let removed = engine.delete(&clean_table, id.as_bytes())?;
        if removed && partition.supports_vectors() {
            let vector_index = self.get_vector_index_mut(partition)?;
            vector_index.delete(id);
        }
        Ok(removed)
    }

    pub fn search_similar_records(
        &self,
        table: &str,
        query_vector: &[f32],
        k: usize,
        kem_sk: &[u8],
    ) -> Result<Vec<(model::Record, f32)>> {
        // Determine partition for vector operations
        let (partition, _) = Partition::from_table(table);
        if !partition.supports_vectors() {
            return Err(anyhow::anyhow!("Partition does not support vector operations"));
        }
        
        let vector_index = self.get_vector_index(partition)?;
        let results = vector_index.search(query_vector, k);

        // Parallelize the retrieval and decryption of search results
        let final_results: Result<Vec<_>> = results
            .into_par_iter()
            .map(|(record_id, distance)| {
                let rec = self.get_record(table, &record_id, kem_sk)?;
                Ok(rec.map(|r| (r, distance)))
            })
            .collect();

        Ok(final_results?.into_iter().flatten().collect())
    }

    pub fn generate_recovery_backup(&self, recovery_password: &str) -> Result<String> {
        let kem_sk = self.kem_sk.as_ref().context("No active KEM SK")?;
        let dsa_sk = self.dsa_sk.as_ref().context("No active DSA SK")?;
        use argon2::PasswordHasher;
        use argon2::password_hash::SaltString;

        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = argon2::Argon2::default();
        let password_hash = argon2
            .hash_password(recovery_password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Recovery hashing failed: {}", e))?;

        let hash_output = password_hash.hash.context("No hash output")?;
        let hash_bytes = hash_output.as_bytes();
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&hash_bytes[..32]);

        // Wrap both keys in a JSON for backup
        let keys_to_backup = serde_json::json!({
            "kem_sk": general_purpose::STANDARD.encode(kem_sk.as_slice()),
            "dsa_sk": general_purpose::STANDARD.encode(dsa_sk.as_slice())
        });
        let keys_bin = keys_to_backup.to_string();
        let (encrypted_keys, nonce) =
            crate::crypto::aes::encrypt(keys_bin.as_bytes(), &master_key)?;

        let kem_pk = self.kem_pk.as_ref().context("No KEM PK")?;
        let dsa_pk = self.dsa_pk.as_ref().context("No DSA PK")?;

        let backup = serde_json::json!({
            "encrypted_keys": general_purpose::STANDARD.encode(encrypted_keys),
            "salt": salt.as_str(),
            "nonce": general_purpose::STANDARD.encode(nonce),
            "kem_pk": general_purpose::STANDARD.encode(kem_pk),
            "dsa_pk": general_purpose::STANDARD.encode(dsa_pk)
        });

        Ok(general_purpose::STANDARD.encode(backup.to_string()))
    }

    pub fn recover_from_backup(
        &mut self,
        blob_b64: &str,
        recovery_password: &str,
        new_master_password: &str,
    ) -> Result<()> {
        use argon2::PasswordHasher;
        let decoded_json_str = String::from_utf8(general_purpose::STANDARD.decode(blob_b64)?)?;
        let json: serde_json::Value = serde_json::from_str(&decoded_json_str)?;

        let encrypted_keys = general_purpose::STANDARD.decode(
            json["encrypted_keys"]
                .as_str()
                .context("No encrypted_keys")?,
        )?;
        let salt_str = json["salt"].as_str().context("No salt")?;
        let nonce_vec =
            general_purpose::STANDARD.decode(json["nonce"].as_str().context("No nonce")?)?;
        let kem_pk =
            general_purpose::STANDARD.decode(json["kem_pk"].as_str().context("No kem_pk")?)?;
        let dsa_pk =
            general_purpose::STANDARD.decode(json["dsa_pk"].as_str().context("No dsa_pk")?)?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_vec);

        let salt = argon2::password_hash::SaltString::from_b64(salt_str)
            .map_err(|e| anyhow::anyhow!("Invalid salt: {}", e))?;
        let argon2 = argon2::Argon2::default();
        let password_hash = argon2
            .hash_password(recovery_password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Recovery hashing failed: {}", e))?;

        let hash_output = password_hash.hash.context("No hash output")?;
        let hash_bytes = hash_output.as_bytes();
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&hash_bytes[..32]);

        let decrypted_keys_bin = crate::crypto::aes::decrypt(&encrypted_keys, &master_key, &nonce)?;
        let keys_json: serde_json::Value = serde_json::from_slice(&decrypted_keys_bin)?;

        let kem_sk = general_purpose::STANDARD.decode(
            keys_json["kem_sk"]
                .as_str()
                .context("No kem_sk in backup")?,
        )?;
        let dsa_sk = general_purpose::STANDARD.decode(
            keys_json["dsa_sk"]
                .as_str()
                .context("No dsa_sk in backup")?,
        )?;

        let new_keystore = crate::crypto::keystore::Keystore::create_encrypted(
            &kem_sk,
            &kem_pk,
            &dsa_sk,
            &dsa_pk,
            new_master_password,
        )?;
        crate::crypto::keystore::Keystore::save(
            &new_keystore,
            &format!("{}/keystore.json", self.path),
        )?;

        self.kem_sk = Some(Zeroizing::new(kem_sk));
        self.kem_pk = Some(kem_pk);
        self.dsa_sk = Some(Zeroizing::new(dsa_sk));
        self.dsa_pk = Some(dsa_pk);

        Ok(())
    }

    pub fn get_info(&self) -> Result<serde_json::Value> {
        // Aggregate stats from all vector indices
        let mut total_v_count = 0;
        let mut total_v_index_size = 0;
        let mut total_v_deleted = 0;
        
        for (_partition, index) in &self.vector_indices {
            let (v_count, v_index_size, v_deleted) = index.get_stats();
            total_v_count += v_count;
            total_v_index_size += v_index_size;
            total_v_deleted += v_deleted;
        }
        
        Ok(serde_json::json!({
            "vector_records": total_v_count,
            "vector_index_size": total_v_index_size,
            "vector_deleted": total_v_deleted,
            "pqc_integrity": "ACTIVE (Dilithium)",
            "pqc_encryption": "ACTIVE (Kyber768)",
            "zeroize": "ENABLED",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::model::Record;
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[test]
    fn test_storage_lifecycle() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().to_str().unwrap();
        let password = "WolfPassword123";
        {
            let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
            storage
                .initialize_keystore(password, None)
                .expect("Initialize failed");
            assert!(storage.is_initialized());
        }

        // Re-open and unlock
        let mut storage2 = WolfDbStorage::open(path).expect("Failed to re-open storage");
        storage2.unlock(password, None).expect("Unlock failed");

        let mut data = HashMap::new();
        data.insert("test".to_string(), "data".to_string());
        let record = Record {
            id: "rec1".to_string(),
            data,
            vector: Some(vec![1.0, 0.0, 0.0]),
        };

        let pk = storage2.get_active_pk().unwrap().to_vec();
        storage2
            .insert_record("data", &record, &pk)
            .expect("Insert record failed");

        let sk = storage2.get_active_sk().unwrap().to_vec();
        let retrieved = storage2
            .get_record("data", "rec1", &sk)
            .expect("Get record failed");

        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, record.id);
        assert_eq!(retrieved.data, record.data);
        assert_eq!(retrieved.vector, record.vector);
    }

    #[test]
    fn test_storage_recovery() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().to_str().unwrap();
        let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");

        let password = "WolfPassword123";
        let recovery_password = "RecoverySecret";
        storage
            .initialize_keystore(password, None)
            .expect("Initialize failed");

        let backup_blob = storage
            .generate_recovery_backup(recovery_password)
            .expect("Backup failed");

        // Recover in a new directory
        let dir2 = tempdir().expect("Failed to create second temp dir");
        let path2 = dir2.path().to_str().unwrap();
        let mut storage_recovered =
            WolfDbStorage::open(path2).expect("Failed to open second storage");

        storage_recovered
            .recover_from_backup(&backup_blob, recovery_password, "NewPassword")
            .expect("Recovery failed");
        assert!(storage_recovered.is_initialized());

        // Verify we can unlock with new password
        storage_recovered
            .unlock("NewPassword", None)
            .expect("Unlock with new password failed");
    }
}
