/// Low-level storage engine implementation
pub mod engine;
/// Data models for storage
pub mod model;
/// Storage partitioning logic
pub mod partition;
/// Post-Quantum Cryptography worker pool
pub mod pqc_pool;

use crate::crypto::{CryptoManager, EncryptedData};
use crate::error::{Result, WolfDbError};
use crate::vector::VectorIndex;
use base64::{engine::general_purpose, Engine as _};
use rayon::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

pub use partition::Partition;
use serde::{Deserialize, Serialize};

/// Policy for determining which metadata fields are indexed for searching
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum IndexingPolicy {
    /// Index all fields available in the record metadata
    #[default]
    All,
    /// Index only the specifically listed fields
    Selected(Vec<String>),
    /// Do not index any metadata (only primary ID and Vector)
    None,
}

/// High-level encrypted storage manager for `WolfDb`
pub struct WolfDbStorage {
    /// Base directory for the database
    path: String,
    /// Storage engines for each partition
    engines: HashMap<Partition, engine::StorageEngine>,
    /// Vector similarity indices for each partition
    vector_indices: HashMap<Partition, Arc<VectorIndex>>,
    /// Manager for cryptographic operations
    crypto: CryptoManager,
    /// Worker pool for PQC encryption
    _pqc_pool: Option<pqc_pool::PqcWorkerPool>,
    /// Decrypted KEM secret key (zeroized on drop)
    kem_secret_key: Option<Zeroizing<Vec<u8>>>,
    /// Raw KEM public key
    kem_public_key: Option<Vec<u8>>,
    /// Decrypted DSA secret key (zeroized on drop)
    dsa_secret_key: Option<Zeroizing<Vec<u8>>>,
    /// Raw DSA public key
    dsa_public_key: Option<Vec<u8>>,
    /// Reconstructed DSA keypair for signing
    dsa_keypair: Option<Arc<crate::crypto::signature::Keypair>>,
    /// Table-level indexing configuration
    indexing_policies: Arc<std::sync::RwLock<HashMap<String, IndexingPolicy>>>,
}

impl WolfDbStorage {
    /// Opens a `WolfDb` database at the specified path, initializing engines and indices
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or storage engine initialization fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal indexing policy lock is poisoned.
    pub fn open(path: &str) -> Result<Self> {
        let mut engines = HashMap::new();
        let mut vector_indices = HashMap::new();
        let indexing_policies = Arc::new(std::sync::RwLock::new(HashMap::new()));

        // Create directory structure for partitions
        std::fs::create_dir_all(path)?;
        std::fs::create_dir_all(format!("{path}/relational"))?;
        std::fs::create_dir_all(format!("{path}/vector"))?;
        std::fs::create_dir_all(format!("{path}/indices"))?;

        // Open storage engine for each partition
        for partition in [Partition::Relational, Partition::Vector, Partition::Hybrid] {
            let db_path = partition.get_db_path(path);
            let engine = engine::StorageEngine::open(&db_path).map_err(WolfDbError::from)?;

            // Load indexing policies from _meta table if in Relational partition (central place)
            if partition == Partition::Relational {
                if let Ok(meta_tree) = engine.get_table("_meta") {
                    for (k, v) in meta_tree.iter().flatten() {
                        let key_str = String::from_utf8_lossy(&k);
                        if let Some(table_name) = key_str.strip_prefix("policy:") {
                            if let Ok(policy) = serde_json::from_slice::<IndexingPolicy>(&v) {
                                #[allow(clippy::expect_used)]
                                indexing_policies
                                    .write()
                                    .expect("Lock poisoned")
                                    .insert(table_name.to_string(), policy);
                            }
                        }
                    }
                }
            }

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
                vector_indices.insert(partition, Arc::new(index));
            }
        }

        let crypto = CryptoManager::new();

        Ok(Self {
            path: path.to_string(),
            engines,
            vector_indices,
            crypto,
            _pqc_pool: None,
            kem_secret_key: None,
            kem_public_key: None,
            dsa_secret_key: None,
            dsa_public_key: None,
            dsa_keypair: None,
            indexing_policies,
        })
    }

    /// Returns true if the database has been initialized with a keystore
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        std::path::Path::new(&format!("{}/keystore.json", self.path)).exists()
    }

    /// Generates and secures a new set of PQC keys for the database
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or keystore saving fails.
    pub fn initialize_keystore(&mut self, password: &str, hsm_pin: Option<&str>) -> Result<()> {
        let (kem_secret, kem_public) = crate::crypto::kem::generate_keypair()
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;
        let (dsa_secret, dsa_public) = crate::crypto::signature::generate_keypair()
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

        let mut keystore = crate::crypto::keystore::Keystore::create_encrypted(
            &kem_secret,
            &kem_public,
            &dsa_secret,
            &dsa_public,
            password,
        )
        .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

        if let Some(pin) = hsm_pin {
            keystore.hsm_enabled = true;
            let wrapped = crate::crypto::hsm::MockHsm::wrap(pin, password.as_bytes());
            keystore.hsm_wrapped_key = Some(general_purpose::STANDARD.encode(wrapped));
        }

        crate::crypto::keystore::Keystore::save(&keystore, &format!("{}/keystore.json", self.path))
            .map_err(|e| {
                WolfDbError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

        self.kem_secret_key = Some(Zeroizing::new(kem_secret));
        self.kem_public_key = Some(kem_public);
        self.dsa_secret_key = Some(Zeroizing::new(dsa_secret));
        self.dsa_public_key = Some(dsa_public);

        Ok(())
    }

    /// Unlocks the database using the provided password and optional HSM PIN
    ///
    /// # Errors
    ///
    /// Returns an error if the password is incorrect, HSM unwrap fails, or the keystore is missing.
    ///
    /// # Panics
    ///
    /// Panics if the internal keys are missing during migration or initialization.
    pub fn unlock(&mut self, password: &str, hsm_pin: Option<&str>) -> Result<()> {
        let keystore =
            crate::crypto::keystore::Keystore::load(&format!("{}/keystore.json", self.path))
                .map_err(|e| {
                    WolfDbError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ))
                })?;

        if keystore.hsm_enabled {
            let pin = hsm_pin.ok_or_else(|| WolfDbError::Crypto("HSM PIN required".to_string()))?;
            let wrapped_b64 = keystore
                .hsm_wrapped_key
                .as_ref()
                .ok_or_else(|| WolfDbError::Crypto("No wrapped key".to_string()))?;
            let wrapped = general_purpose::STANDARD
                .decode(wrapped_b64)
                .map_err(|e| WolfDbError::Crypto(e.to_string()))?;
            crate::crypto::hsm::MockHsm::unwrap(pin, &wrapped)
                .map_err(|e| WolfDbError::Crypto(e.to_string()))?;
        }

        let (kem_sk_unlocked, maybe_dsa_sk_unlocked) =
            crate::crypto::keystore::Keystore::unlock_keys(&keystore, password)
                .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

        self.kem_secret_key = Some(kem_sk_unlocked);
        self.kem_public_key = Some(keystore.pk.clone());

        if let Some(dsa_sk_unlocked) = maybe_dsa_sk_unlocked {
            self.dsa_secret_key = Some(dsa_sk_unlocked.clone());
            let public_key = keystore
                .dsa_pk
                .as_ref()
                .ok_or_else(|| WolfDbError::Crypto("DSA PK missing but SK present".to_string()))?;
            self.dsa_public_key = Some(public_key.clone());

            let keypair = crate::crypto::signature::reconstruct_keypair(
                dsa_sk_unlocked.as_slice(),
                public_key,
            )
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;
            self.dsa_keypair = Some(Arc::new(keypair));
        } else {
            tracing::info!("Migrating keystore: Generating missing DSA keys...");
            let (migrated_dsa_secret, migrated_dsa_public) =
                crate::crypto::signature::generate_keypair()
                    .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

            #[allow(clippy::expect_used)]
            let kem_secret_bytes = self
                .kem_secret_key
                .as_ref()
                .expect("KEM SK missing during migration")
                .as_slice();
            #[allow(clippy::expect_used)]
            let kem_public_bytes = self
                .kem_public_key
                .as_ref()
                .expect("KEM PK missing during migration");

            let mut new_keystore = crate::crypto::keystore::Keystore::create_encrypted(
                kem_secret_bytes,
                kem_public_bytes,
                &migrated_dsa_secret,
                &migrated_dsa_public,
                password,
            )
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

            new_keystore.hsm_enabled = keystore.hsm_enabled;
            new_keystore
                .hsm_wrapped_key
                .clone_from(&keystore.hsm_wrapped_key);

            crate::crypto::keystore::Keystore::save(
                &new_keystore,
                &format!("{}/keystore.json", self.path),
            )
            .map_err(|e| {
                WolfDbError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

            self.dsa_secret_key = Some(Zeroizing::new(migrated_dsa_secret));
            self.dsa_public_key = Some(migrated_dsa_public);
            #[allow(clippy::expect_used)]
            let dsa_sk_zeroized = self
                .dsa_secret_key
                .as_ref()
                .expect("DSA SK missing after migration");
            #[allow(clippy::expect_used)]
            let dsa_pk_ref = self
                .dsa_public_key
                .as_ref()
                .expect("DSA PK missing after migration");
            let keypair = crate::crypto::signature::reconstruct_keypair(
                dsa_sk_zeroized.as_slice(),
                dsa_pk_ref,
            )
            .map_err(|e: anyhow::Error| WolfDbError::Crypto(e.to_string()))?;
            self.dsa_keypair = Some(Arc::new(keypair));
        }

        Ok(())
    }

    fn get_engine(&self, partition: Partition) -> Result<&engine::StorageEngine> {
        self.engines
            .get(&partition)
            .ok_or_else(|| WolfDbError::InvalidPartition(format!("{partition:?}")))
    }

    fn get_vector_index(&self, partition: Partition) -> Result<Arc<VectorIndex>> {
        self.vector_indices
            .get(&partition)
            .cloned()
            .ok_or_else(|| WolfDbError::InvalidPartition(format!("{partition:?}")))
    }

    /// Persists all vector indices to disk
    ///
    /// # Errors
    ///
    /// Returns an error if index saving fails for any partition.
    pub fn save(&self) -> Result<()> {
        for (partition, index) in &self.vector_indices {
            let vector_path = partition.get_index_path(&self.path, "hnsw_index");
            index
                .save(&vector_path)
                .map_err(|e| WolfDbError::Vector(e.to_string()))?;
        }
        Ok(())
    }

    /// Returns the currently active KEM public key
    #[must_use]
    pub fn get_active_pk(&self) -> Option<&[u8]> {
        self.kem_public_key.as_deref()
    }

    /// Returns the currently active KEM secret key
    #[must_use]
    pub fn get_active_sk(&self) -> Option<&[u8]> {
        self.kem_secret_key.as_ref().map(|s| s.as_slice())
    }

    // ==================================================================================
    // ASYNC API
    // ==================================================================================

    /// Encrypts and inserts a single record into the specified table
    ///
    /// # Errors
    ///
    /// Returns an error if encryption, storage, or vector indexing fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal indexing policy lock is poisoned.
    pub async fn insert_record(
        &self,
        table: String,
        record: model::Record,
        kem_pk: Vec<u8>,
    ) -> Result<()> {
        let (partition, clean_table) = Partition::from_table(&table);

        if !partition.supports_vectors() && record.vector.is_some() {
            tracing::warn!(
                "Vector data provided for relational partition '{}', ignoring vector",
                table
            );
        }

        let engine = self.get_engine(partition)?.clone();
        let vector_index = if partition.supports_vectors() {
            Some(self.get_vector_index(partition)?)
        } else {
            None
        };

        let dsa_keypair = self.dsa_keypair.clone();
        #[allow(clippy::expect_used)]
        let policy = self
            .indexing_policies
            .read()
            .expect("Lock poisoned")
            .get(&table)
            .cloned()
            .unwrap_or_default();

        let crypto_manager = self.crypto;

        // Move everything to blocking task
        tokio::task::spawn_blocking(move || -> Result<()> {
            let dsa_keypair_ref = dsa_keypair.as_deref();

            let serialized = bincode::serialize(&record)?;
            let encrypted = crypto_manager
                .encrypt_at_rest(&serialized, &kem_pk, dsa_keypair_ref)
                .map_err(|e: anyhow::Error| WolfDbError::Crypto(e.to_string()))?;
            let bin = bincode::serialize(&encrypted)?;

            engine
                .insert(&clean_table, record.id.as_bytes(), bin)
                .map_err(|e: anyhow::Error| WolfDbError::Storage(e.to_string()))?;

            // Index metadata based on policy
            let index_table = format!("idx_{clean_table}");
            match &policy {
                IndexingPolicy::All => {
                    for (field, value) in &record.data {
                        let key = format!("{field}:{value}:{}", record.id);
                        engine
                            .insert(&index_table, key.as_bytes(), vec![])
                            .map_err(|e| WolfDbError::Storage(e.to_string()))?;
                    }
                }
                IndexingPolicy::Selected(fields) => {
                    for field in fields {
                        if let Some(value) = record.data.get(field) {
                            let key = format!("{field}:{value}:{}", record.id);
                            engine
                                .insert(&index_table, key.as_bytes(), vec![])
                                .map_err(|e| WolfDbError::Storage(e.to_string()))?;
                        }
                    }
                }
                IndexingPolicy::None => {}
            }

            if let Some(index) = vector_index {
                if let Some(vec) = record.vector {
                    index
                        .insert(&record.id, &vec)
                        .map_err(|e| WolfDbError::Vector(e.to_string()))?;
                }
            }
            Ok(())
        })
        .await?
    }

    /// Encrypts and inserts a batch of records into the specified table efficiently
    ///
    /// # Errors
    ///
    /// Returns an error if encryption, storage, or vector indexing fails for any record in the batch.
    ///
    /// # Panics
    ///
    /// Panics if the internal indexing policy lock is poisoned.
    pub async fn insert_batch_records(
        &self,
        table: String,
        records: Vec<model::Record>,
        kem_pk: Vec<u8>,
    ) -> Result<()> {
        let (partition, clean_table) = Partition::from_table(&table);

        let engine = self.get_engine(partition)?.clone();
        let vector_index = if partition.supports_vectors() {
            Some(self.get_vector_index(partition)?)
        } else {
            None
        };

        let dsa_keypair = self.dsa_keypair.clone();
        #[allow(clippy::expect_used)]
        let policy = self
            .indexing_policies
            .read()
            .expect("Lock poisoned")
            .get(&table)
            .cloned()
            .unwrap_or_default();

        let crypto_manager = self.crypto;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let dsa_keypair_ref = dsa_keypair.as_deref();

            // 1. Encryption (Parallel with Rayon inside blocking task is fine)
            let processed_records: Vec<_> = records
                .into_par_iter()
                .map(|record| {
                    let serialized = bincode::serialize(&record)?;
                    let encrypted = crypto_manager
                        .encrypt_at_rest(&serialized, &kem_pk, dsa_keypair_ref)
                        .map_err(|e: anyhow::Error| WolfDbError::Crypto(e.to_string()))?;
                    let bin = bincode::serialize(&encrypted)?;
                    Ok((record, bin))
                })
                .collect::<Result<Vec<_>>>()?;

            // 2. Storage
            let mut vector_batch = Vec::with_capacity(processed_records.len());
            for (record, bin) in processed_records {
                engine
                    .insert(&clean_table, record.id.as_bytes(), bin)
                    .map_err(|e| WolfDbError::Storage(e.to_string()))?;

                let index_table = format!("idx_{clean_table}");
                match &policy {
                    IndexingPolicy::All => {
                        for (field, value) in &record.data {
                            let key = format!("{field}:{value}:{}", record.id);
                            engine
                                .insert(&index_table, key.as_bytes(), vec![])
                                .map_err(|e| WolfDbError::Storage(e.to_string()))?;
                        }
                    }
                    IndexingPolicy::Selected(fields) => {
                        for field in fields {
                            if let Some(value) = record.data.get(field) {
                                let key = format!("{field}:{value}:{}", record.id);
                                engine
                                    .insert(&index_table, key.as_bytes(), vec![])
                                    .map_err(|e| WolfDbError::Storage(e.to_string()))?;
                            }
                        }
                    }
                    IndexingPolicy::None => {}
                }

                if let Some(vec) = record.vector {
                    vector_batch.push((record.id, vec));
                }
            }

            // 3. Vector Batch
            if !vector_batch.is_empty() {
                if let Some(index) = vector_index {
                    index
                        .insert_batch(vector_batch)
                        .map_err(|e| WolfDbError::Vector(e.to_string()))?;
                }
            }
            Ok(())
        })
        .await?
    }

    /// Retrieves and decrypts a record by ID from the specified table
    ///
    /// # Errors
    ///
    /// Returns an error if record retrieval or decryption fails.
    pub async fn get_record(
        &self,
        table: String,
        id: String,
        kem_sk: Vec<u8>,
    ) -> Result<Option<model::Record>> {
        let (partition, clean_table) = Partition::from_table(&table);
        let storage_engine = self.get_engine(partition)?.clone();
        let crypto_manager = self.crypto;
        let dsa_public_key = self.dsa_public_key.clone();

        tokio::task::spawn_blocking(move || -> Result<Option<model::Record>> {
            let bin = storage_engine
                .get(&clean_table, id.as_bytes())
                .map_err(|e| WolfDbError::Storage(e.to_string()))?;
            if let Some(encrypted_bin) = bin {
                let encrypted: EncryptedData = bincode::deserialize(&encrypted_bin)?;
                let dsa_pk_ref = dsa_public_key.as_deref(); // as_deref works on Option<Vec<u8>>
                let decrypted = crypto_manager
                    .decrypt_at_rest(&encrypted, &kem_sk, dsa_pk_ref)
                    .map_err(|e| WolfDbError::Crypto(e.to_string()))?;
                let record: model::Record = bincode::deserialize(&decrypted)?;
                Ok(Some(record))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    /// Deletes a record from the specified table and its vector index
    ///
    /// # Errors
    ///
    /// Returns an error if the database is locked or deletion fails.
    pub async fn delete_record(&self, table: String, id: String) -> Result<bool> {
        let (partition, clean_table) = Partition::from_table(&table);
        let storage_engine = self.get_engine(partition)?.clone();
        let vector_index = if partition.supports_vectors() {
            Some(self.get_vector_index(partition)?)
        } else {
            None
        };

        tokio::task::spawn_blocking(move || -> Result<bool> {
            let removed = storage_engine
                .delete(&clean_table, id.as_bytes())
                .map_err(|e| WolfDbError::Storage(e.to_string()))?;
            if removed {
                if let Some(index) = vector_index {
                    index.delete(&id);
                }
            }
            Ok(removed)
        })
        .await?
    }

    /// Returns a list of all primary IDs in the specified table
    ///
    /// # Errors
    ///
    /// Returns an error if key scanning fails.
    pub async fn list_keys(&self, table: String) -> Result<Vec<String>> {
        let (partition, clean_table) = Partition::from_table(&table);
        let storage_engine = self.get_engine(partition)?.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let keys = storage_engine
                .scan_keys(&clean_table)
                .map_err(|e| WolfDbError::Storage(e.to_string()))?;
            let mut string_keys = Vec::new();
            for k in keys {
                if let Ok(s) = String::from_utf8(k) {
                    string_keys.push(s);
                }
            }
            Ok(string_keys)
        })
        .await?
    }

    /// Performs a filtered search for records matching a specific metadata field and value
    ///
    /// # Errors
    ///
    /// Returns an error if index scanning or record retrieval fails.
    pub async fn find_by_metadata(
        &self,
        table: String,
        field: String,
        value: String,
        kem_sk: Vec<u8>,
    ) -> Result<Vec<model::Record>> {
        let (partition, clean_table) = Partition::from_table(&table);
        let storage_engine = self.get_engine(partition)?.clone();

        let _sk_clone = kem_sk.clone();

        // First pass: scan index to get IDs (sync/blocking operation)
        // We do this in a blocking task
        let ids = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let index_table = format!("idx_{clean_table}");
            let prefix = format!("{field}:{value}:");
            let prefix_bytes = prefix.as_bytes();

            let matching = storage_engine
                .scan_prefix(&index_table, prefix_bytes)
                .map_err(|e| WolfDbError::Storage(e.to_string()))?
                .into_iter()
                .filter_map(|(key, _)| {
                    let key_str = String::from_utf8_lossy(&key);
                    key_str.strip_prefix(&prefix).map(ToString::to_string)
                })
                .collect();
            Ok(matching)
        })
        .await??;

        // Second pass: fetch actual records (concurrently ideally, but let's reuse get_record)
        // We can spawn futures for each fetch
        let mut tasks = Vec::with_capacity(ids.len());
        for id in ids {
            // Need to pass shared ref or clone? get_record takes &self.
            // But we are in an async method on self.
            // Ideally we run these in parallel.
            let table = table.clone();
            let sk = kem_sk.clone();
            // We can't easily spawn parallel accesses to &self without Arc<Self>.
            // Since we don't have Arc<Self> here (we are inside &self), we have to await them sequentially
            // OR we rely on the fact that `engine` and `crypto` are cloneable and we can spawn tasks that don't need `&self`
            // but just the components.
            // Let's implement a helper that takes components to avoid `self` dependency in inner loop if we want parallelism.
            // For now, sequential await is safer for this refactor without changing architecture too much.
            // Actually, we can just call `self.get_record` sequentially.
            tasks.push(self.get_record(table, id, sk));
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Some(record) = task.await? {
                results.push(record);
            }
        }
        Ok(results)
    }

    /// Performs a hybrid search combining metadata filtering and vector similarity
    ///
    /// # Errors
    ///
    /// Returns an error if the partition doesn't support vectors or if the search fails.
    pub async fn search_hybrid(
        &self,
        table: String,
        query_vector: Vec<f32>,
        k: usize,
        filter_field: String,
        filter_value: String,
        kem_sk: Vec<u8>,
    ) -> Result<Vec<(model::Record, f32)>> {
        let (partition, clean_table) = Partition::from_table(&table);
        if !partition.supports_vectors() {
            return Err(WolfDbError::InvalidPartition(
                "No vector support".to_string(),
            ));
        }

        let engine = self.get_engine(partition)?.clone();
        let vector_index = self.get_vector_index(partition)?;

        // 1. Get Matching IDs (Blocking)
        let matching_ids = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let index_table = format!("idx_{clean_table}");
            let prefix = format!("{filter_field}:{filter_value}:");
            let prefix_bytes = prefix.as_bytes();

            let ids = engine
                .scan_prefix(&index_table, prefix_bytes)
                .map_err(|e| WolfDbError::Storage(e.to_string()))?
                .into_iter()
                .filter_map(|(key, _)| {
                    let key_str = String::from_utf8_lossy(&key);
                    key_str.strip_prefix(&prefix).map(ToString::to_string)
                })
                .collect();
            Ok(ids)
        })
        .await??;

        if matching_ids.is_empty() {
            return Ok(vec![]);
        }

        // 2. Vector Search (Blocking)
        // VectorIndex is Arc, so we can clone it into task
        let index_clone = vector_index.clone();
        let results = tokio::task::spawn_blocking(move || {
            let allowed_internal_ids = index_clone.get_internal_ids(&matching_ids);
            index_clone.search_with_filter(&query_vector, k, Some(&allowed_internal_ids))
        })
        .await?;

        // 3. Fetch Records (Sequential async for now)
        let mut final_results = Vec::new();
        for (id, score) in results {
            if let Some(record) = self.get_record(table.clone(), id, kem_sk.clone()).await? {
                final_results.push((record, score));
            }
        }
        Ok(final_results)
    }

    /// Performs a vector similarity search in the specified table
    ///
    /// # Errors
    ///
    /// Returns an error if the partition doesn't support vectors or if the search fails.
    pub async fn search_similar_records(
        &self,
        table: String,
        query_vector: Vec<f32>,
        k: usize,
        kem_sk: Vec<u8>,
    ) -> Result<Vec<(model::Record, f32)>> {
        let (partition, _) = Partition::from_table(&table);
        if !partition.supports_vectors() {
            return Err(WolfDbError::InvalidPartition(
                "No vector support".to_string(),
            ));
        }

        let vector_index = self.get_vector_index(partition)?;

        let results =
            tokio::task::spawn_blocking(move || vector_index.search(&query_vector, k)).await?;

        let mut final_results = Vec::new();
        for (id, score) in results {
            if let Some(record) = self.get_record(table.clone(), id, kem_sk.clone()).await? {
                final_results.push((record, score));
            }
        }
        Ok(final_results)
    }

    /// Configures the indexing policy for a specific table
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata update fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal indexing policy lock is poisoned.
    pub async fn set_indexing_policy(&self, table: String, policy: IndexingPolicy) -> Result<()> {
        let (_partition, _) = Partition::from_table(&table);
        // We actially store policies centrally in the Relational partition's _meta table
        // regardless of where data lives, to keep it simple.
        let meta_engine = self
            .engines
            .get(&Partition::Relational)
            .ok_or_else(|| {
                WolfDbError::Storage("Relational engine missing for meta storage".to_string())
            })?
            .clone();

        {
            #[allow(clippy::expect_used)]
            let mut cache = self.indexing_policies.write().expect("Lock poisoned");
            cache.insert(table.clone(), policy.clone());
        }

        tokio::task::spawn_blocking(move || -> Result<()> {
            // Persist to disk
            let meta_tree = meta_engine
                .get_table("_meta")
                .map_err(|e| WolfDbError::Storage(e.to_string()))?;

            let key = format!("policy:{table}");
            let val = serde_json::to_vec(&policy).map_err(|e| {
                WolfDbError::Serialization(bincode::Error::from(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                )))
            })?;

            meta_tree
                .insert(key.as_bytes(), val)
                .map_err(|e| WolfDbError::Storage(e.to_string()))?;
            Ok(())
        })
        .await?
    }

    // Sync methods for recovery/init (rarely called, ok to block or lightweight)
    /// Generates a base64 encoded recovery blob for the database keys
    ///
    /// # Panics
    ///
    /// Panics if the KEM or DSA public keys are missing from the storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the database is locked or if backup generation fails.
    pub fn generate_recovery_backup(&self, recovery_password: &str) -> Result<String> {
        use argon2::PasswordHasher;
        let kem_secret_key = self
            .kem_secret_key
            .as_ref()
            .ok_or(WolfDbError::Crypto("No KEM SK".to_string()))?;
        let dsa_secret_key = self
            .dsa_secret_key
            .as_ref()
            .ok_or(WolfDbError::Crypto("No DSA SK".to_string()))?;

        // This password hashing is slow, should technically be async/blocking too but it's rare operation
        let salt = argon2::password_hash::SaltString::generate(&mut rand::thread_rng());
        let argon2 = argon2::Argon2::default();
        let password_hash = argon2
            .hash_password(recovery_password.as_bytes(), &salt)
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

        let hash_output = password_hash
            .hash
            .ok_or(WolfDbError::Crypto("Hash failed".to_string()))?;
        let hash_bytes = hash_output.as_bytes();
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&hash_bytes[..32]);

        let keys_to_backup = serde_json::json!({
            "kem_sk": general_purpose::STANDARD.encode(kem_secret_key.as_slice()),
            "dsa_sk": general_purpose::STANDARD.encode(dsa_secret_key.as_slice())
        });
        let keys_bin = keys_to_backup.to_string();
        let (encrypted_keys, nonce) = crate::crypto::aes::encrypt(keys_bin.as_bytes(), &master_key)
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

        #[allow(clippy::expect_used)]
        let kem_public_key_raw = self
            .kem_public_key
            .as_ref()
            .expect("KEM PK missing during backup");
        #[allow(clippy::expect_used)]
        let dsa_public_key_raw = self
            .dsa_public_key
            .as_ref()
            .expect("DSA PK missing during backup");

        let backup = serde_json::json!({
            "encrypted_keys": general_purpose::STANDARD.encode(encrypted_keys),
            "salt": salt.as_str(),
            "nonce": general_purpose::STANDARD.encode(nonce),
            "kem_pk": general_purpose::STANDARD.encode(kem_public_key_raw),
            "dsa_pk": general_purpose::STANDARD.encode(dsa_public_key_raw)
        });

        Ok(general_purpose::STANDARD.encode(backup.to_string()))
    }

    /// Restores database keys from a recovery blob
    ///
    /// # Errors
    ///
    /// Returns an error if the recovery blob is invalid or if decryption fails.
    pub fn recover_from_backup(
        &mut self,
        blob_b64: &str,
        recovery_password: &str,
        new_master_password: &str,
    ) -> Result<()> {
        use argon2::PasswordHasher;
        let decoded_json_str =
            String::from_utf8(general_purpose::STANDARD.decode(blob_b64).map_err(|e| {
                WolfDbError::Serialization(bincode::Error::from(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                )))
            })?)
            .map_err(WolfDbError::from)?;
        let json: serde_json::Value = serde_json::from_str(&decoded_json_str).map_err(|e| {
            WolfDbError::Serialization(bincode::Error::from(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e,
            )))
        })?;

        let encrypted_keys_str = json["encrypted_keys"]
            .as_str()
            .ok_or(WolfDbError::Import("Missing encrypted_keys".to_string()))?;
        let encrypted_keys = general_purpose::STANDARD
            .decode(encrypted_keys_str)
            .map_err(|e| WolfDbError::Import(e.to_string()))?;

        let salt_str = json["salt"]
            .as_str()
            .ok_or(WolfDbError::Import("Missing salt".to_string()))?;
        let nonce_str = json["nonce"]
            .as_str()
            .ok_or(WolfDbError::Import("Missing nonce".to_string()))?;
        let nonce_vec = general_purpose::STANDARD
            .decode(nonce_str)
            .map_err(|e| WolfDbError::Import(e.to_string()))?;

        let kem_public_key_b64 = json["kem_pk"]
            .as_str()
            .ok_or(WolfDbError::Import("Missing kem_pk".to_string()))?;
        let kem_public_key_raw = general_purpose::STANDARD
            .decode(kem_public_key_b64)
            .map_err(|e| WolfDbError::Import(e.to_string()))?;

        let dsa_public_key_b64 = json["dsa_pk"]
            .as_str()
            .ok_or(WolfDbError::Import("Missing dsa_pk".to_string()))?;
        let dsa_public_key_raw = general_purpose::STANDARD
            .decode(dsa_public_key_b64)
            .map_err(|e| WolfDbError::Import(e.to_string()))?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_vec);

        let salt = argon2::password_hash::SaltString::from_b64(salt_str)
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;
        let argon2 = argon2::Argon2::default();
        let password_hash = argon2
            .hash_password(recovery_password.as_bytes(), &salt)
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

        let hash_output = password_hash
            .hash
            .ok_or(WolfDbError::Crypto("Hash failed".to_string()))?;
        let hash_bytes = hash_output.as_bytes();
        let mut master_key = Zeroizing::new([0u8; 32]);
        master_key.copy_from_slice(&hash_bytes[..32]);

        let decrypted_keys_bin = crate::crypto::aes::decrypt(&encrypted_keys, &master_key, &nonce)
            .map_err(|e| WolfDbError::Crypto(e.to_string()))?;
        let keys_json: serde_json::Value =
            serde_json::from_slice(&decrypted_keys_bin).map_err(|e| {
                WolfDbError::Serialization(bincode::Error::from(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                )))
            })?;

        let kem_secret_key_b64 = keys_json["kem_sk"]
            .as_str()
            .ok_or(WolfDbError::Import("Missing kem_sk".to_string()))?;
        let kem_secret_key_raw = general_purpose::STANDARD
            .decode(kem_secret_key_b64)
            .map_err(|e| WolfDbError::Import(e.to_string()))?;

        let dsa_secret_key_b64 = keys_json["dsa_sk"]
            .as_str()
            .ok_or(WolfDbError::Import("Missing dsa_sk".to_string()))?;
        let dsa_secret_key_raw = general_purpose::STANDARD
            .decode(dsa_secret_key_b64)
            .map_err(|e| WolfDbError::Import(e.to_string()))?;

        let new_keystore = crate::crypto::keystore::Keystore::create_encrypted(
            &kem_secret_key_raw,
            &kem_public_key_raw,
            &dsa_secret_key_raw,
            &dsa_public_key_raw,
            new_master_password,
        )
        .map_err(|e| WolfDbError::Crypto(e.to_string()))?;

        crate::crypto::keystore::Keystore::save(
            &new_keystore,
            &format!("{}/keystore.json", self.path),
        )
        .map_err(|e| {
            WolfDbError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        self.kem_secret_key = Some(Zeroizing::new(kem_secret_key_raw));
        self.kem_public_key = Some(kem_public_key_raw);
        self.dsa_secret_key = Some(Zeroizing::new(dsa_secret_key_raw));
        self.dsa_public_key = Some(dsa_public_key_raw);

        Ok(())
    }

    /// Returns high-level statistics and security status for the database
    ///
    /// # Errors
    ///
    /// Returns an error if indexing statistics cannot be retrieved.
    pub fn get_info(&self) -> Result<serde_json::Value> {
        let mut total_v_count = 0;
        let mut total_v_index_size = 0;
        let mut total_v_deleted = 0;

        for index in self.vector_indices.values() {
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
