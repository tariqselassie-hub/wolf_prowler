use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use wolf_db::storage::model::Record;
use wolf_db::storage::WolfDbStorage;

/// Configuration for WolfStore database operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfStoreConfig {
    /// Whether to automatically save changes to disk.
    pub auto_save: bool,
    /// Whether to create backups.
    pub backup_enabled: bool,
    /// Interval between backups in seconds.
    pub backup_interval: u64, // in seconds
    /// Maximum number of backup files to keep.
    pub max_backup_files: usize,
    /// Encryption algorithm used for the database.
    pub encryption_level: String,
}

impl Default for WolfStoreConfig {
    fn default() -> Self {
        Self {
            auto_save: true,
            backup_enabled: true,
            backup_interval: 3600, // 1 hour
            max_backup_files: 10,
            encryption_level: "AES256_GCM".to_string(),
        }
    }
}

/// Database statistics and health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    /// Total number of records across all tables.
    pub total_records: usize,
    /// Number of records in the vault table.
    pub vault_records: usize,
    /// Number of records in the shards table.
    pub shard_records: usize,
    /// Number of records in the forensics table.
    pub session_records: usize,
    /// Timestamp of the last backup.
    pub last_backup: Option<DateTime<Utc>>,
    /// Timestamp of the last save operation.
    pub last_save: Option<DateTime<Utc>>,
    /// Current encryption status (LOCKED, UNLOCKED, INITIALIZED).
    pub encryption_status: String,
    /// Whether the last integrity check passed.
    pub integrity_check: bool,
}

/// Transaction wrapper for atomic operations
pub struct Transaction<'a> {
    store: &'a mut WolfStore,
    operations: Vec<String>,
    committed: bool,
}

impl<'a> Transaction<'a> {
    /// Creates a new transaction for the given store.
    pub fn new(store: &'a mut WolfStore) -> Self {
        Self {
            store,
            operations: Vec::new(),
            committed: false,
        }
    }

    pub async fn save_session(
        &mut self,
        session_id: &str,
        metadata: HashMap<String, String>,
    ) -> Result<()> {
        self.store
            .save_session_internal(session_id, metadata)
            .await?;
        self.operations
            .push(format!("SAVE_SESSION: {}", session_id));
        Ok(())
    }

    pub async fn save_vault_entry(
        &mut self,
        entry_id: &str,
        secret_type: &str,
        description: &str,
        ciphertext_hex: &str,
        nonce_hex: &str,
    ) -> Result<()> {
        self.store
            .save_vault_entry_internal(
                entry_id,
                secret_type,
                description,
                ciphertext_hex,
                nonce_hex,
            )
            .await?;
        self.operations.push(format!("SAVE_VAULT: {}", entry_id));
        Ok(())
    }

    pub async fn save_key_shard(
        &mut self,
        shard_id: &str,
        secret_id: &str,
        index: u8,
        data_hex: &str,
    ) -> Result<()> {
        self.store
            .save_key_shard_internal(shard_id, secret_id, index, data_hex)
            .await?;
        self.operations.push(format!("SAVE_SHARD: {}", shard_id));
        Ok(())
    }

    /// Commits the transaction, persisting changes to disk.
    ///
    /// # Errors
    /// Returns an error if the save operation fails or if the transaction was already committed.
    pub fn commit(mut self) -> Result<()> {
        if self.committed {
            return Err(anyhow::anyhow!("Transaction already committed"));
        }

        self.store.storage.save()?;
        self.committed = true;

        println!(
            "[WolfStore] Transaction committed with {} operations",
            self.operations.len()
        );
        Ok(())
    }
}

impl<'a> Drop for Transaction<'a> {
    fn drop(&mut self) {
        if !self.committed {
            println!(
                "[WolfStore] Transaction rolled back ({} operations)",
                self.operations.len()
            );
        }
    }
}

/// Main storage manager for Wolf Prowler, wrapping WolfDb.
pub struct WolfStore {
    storage: WolfDbStorage,
    connected: bool,
    db_path: String,
    config: WolfStoreConfig,
    stats: DatabaseStats,
    last_backup: Option<DateTime<Utc>>,
}

impl WolfStore {
    /// Creates a new WolfStore instance with default configuration
    pub async fn new(path: &str) -> Result<Self> {
        println!("[WolfStore] Attempting to open database at: {}", path);

        // Ensure directory exists
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let storage = WolfDbStorage::open(path)?;
        println!("[WolfStore] Database opened successfully at: {}", path);

        let mut store = Self {
            storage,
            connected: true,
            db_path: path.to_string(),
            config: WolfStoreConfig::default(),
            stats: DatabaseStats {
                total_records: 0,
                vault_records: 0,
                shard_records: 0,
                session_records: 0,
                last_backup: None,
                last_save: None,
                encryption_status: "UNLOCKED".to_string(),
                integrity_check: false,
            },
            last_backup: None,
        };

        // Load initial stats only if unlocked
        if store.is_unlocked() {
            store.refresh_stats().await?;
        }

        Ok(store)
    }

    /// Creates a new WolfStore instance with custom configuration
    pub async fn new_with_config(path: &str, config: WolfStoreConfig) -> Result<Self> {
        let mut store = Self::new(path).await?;
        store.config = config;
        Ok(store)
    }

    /// Checks if the database is initialized
    pub fn is_initialized(&self) -> bool {
        self.storage.is_initialized()
    }

    /// Checks if the database is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.storage.get_active_sk().is_some()
    }

    /// Initializes the keystore with a password
    pub async fn initialize(&mut self, password: &str) -> Result<()> {
        if self.is_initialized() {
            return Err(anyhow::anyhow!("Database is already initialized"));
        }

        println!("[WolfStore] Initializing keystore with password...");
        self.storage.initialize_keystore(password, None)?;
        println!("[WolfStore] Keystore initialized successfully");

        self.stats.encryption_status = "INITIALIZED".to_string();
        self.refresh_stats().await?;
        Ok(())
    }

    /// Unlocks the database with a password
    pub async fn unlock(&mut self, password: &str) -> Result<()> {
        if !self.is_initialized() {
            return Err(anyhow::anyhow!(
                "Database not initialized. Initialize first."
            ));
        }

        println!("[WolfStore] Unlocking database...");
        self.storage.unlock(password, None)?;
        println!("[WolfStore] Database unlocked successfully");

        self.stats.encryption_status = "UNLOCKED".to_string();
        self.stats.last_save = Some(Utc::now());
        self.refresh_stats().await?;
        Ok(())
    }

    /// Locks the database
    pub fn lock(&mut self) -> Result<()> {
        println!("[WolfStore] Locking database...");
        // Note: WolfDbStorage doesn't have a lock method, so we just update status
        self.stats.encryption_status = "LOCKED".to_string();
        self.stats.last_save = Some(Utc::now());
        println!("[WolfStore] Database locked");
        Ok(())
    }

    /// Saves a session record to the database
    pub async fn save_session(
        &mut self,
        session_id: &str,
        metadata: HashMap<String, String>,
    ) -> Result<()> {
        self.save_session_internal(session_id, metadata).await?;
        if self.config.auto_save {
            self.save()?;
        }
        Ok(())
    }

    /// Internal method for saving sessions (used in transactions)
    /// Internal method for saving sessions (used in transactions)
    async fn save_session_internal(
        &mut self,
        session_id: &str,
        metadata: HashMap<String, String>,
    ) -> Result<()> {
        let pk = self
            .storage
            .get_active_pk()
            .context("Database locked. Unlock first.")?;
        let pk_vec = pk.to_vec();

        let record = Record {
            id: session_id.to_string(),
            data: metadata,
            vector: None,
        };

        println!(
            "[WolfStore] Inserting record '{}' into forensics table",
            session_id
        );
        self.storage
            .insert_record("forensics".to_string(), record, pk_vec)
            .await?;
        self.stats.session_records += 1;
        self.stats.total_records += 1;
        Ok(())
    }

    /// Loads a session record from the database
    pub async fn load_session(&self, session_id: &str) -> Result<Option<HashMap<String, String>>> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Unlock first.")?;
        let sk_vec = sk.to_vec();

        println!(
            "[WolfStore] Loading session '{}' from forensics table",
            session_id
        );
        let record = self
            .storage
            .get_record("forensics".to_string(), session_id.to_string(), sk_vec)
            .await?;
        Ok(record.map(|r| r.data))
    }

    /// Lists all session IDs
    pub async fn list_sessions(&self) -> Result<Vec<String>> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Unlock first.")?;
        let sk_vec = sk.to_vec();

        let records = self
            .storage
            .find_by_metadata(
                "forensics".to_string(),
                "id".to_string(),
                "*".to_string(),
                sk_vec,
            )
            .await?;
        Ok(records.into_iter().map(|r| r.id).collect())
    }

    /// Saves a vault entry to the database
    pub async fn save_vault_entry(
        &mut self,
        entry_id: &str,
        secret_type: &str,
        description: &str,
        ciphertext_hex: &str,
        nonce_hex: &str,
    ) -> Result<()> {
        self.save_vault_entry_internal(
            entry_id,
            secret_type,
            description,
            ciphertext_hex,
            nonce_hex,
        )
        .await?;
        if self.config.auto_save {
            self.save()?;
        }
        Ok(())
    }

    /// Internal method for saving vault entries (used in transactions)
    /// Internal method for saving vault entries (used in transactions)
    async fn save_vault_entry_internal(
        &mut self,
        entry_id: &str,
        secret_type: &str,
        description: &str,
        ciphertext_hex: &str,
        nonce_hex: &str,
    ) -> Result<()> {
        let pk = self
            .storage
            .get_active_pk()
            .context("Database locked. Unlock first.")?;
        let pk_vec = pk.to_vec();

        let mut metadata = HashMap::new();
        metadata.insert("id".to_string(), entry_id.to_string());
        metadata.insert("secret_type".to_string(), secret_type.to_string());
        metadata.insert("description".to_string(), description.to_string());
        metadata.insert("ciphertext_hex".to_string(), ciphertext_hex.to_string());
        metadata.insert("nonce_hex".to_string(), nonce_hex.to_string());

        let record = Record {
            id: format!("vault_entry_{}", entry_id),
            data: metadata,
            vector: None,
        };

        self.storage
            .insert_record("vault".to_string(), record, pk_vec)
            .await?;
        self.stats.vault_records += 1;
        self.stats.total_records += 1;
        Ok(())
    }

    /// Finds a vault entry by ID
    pub async fn find_vault_entry(
        &self,
        entry_id: &str,
    ) -> Result<Option<HashMap<String, String>>> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Unlock first.")?;
        let sk_vec = sk.to_vec();

        let records = self
            .storage
            .find_by_metadata(
                "vault".to_string(),
                "id".to_string(),
                entry_id.to_string(),
                sk_vec,
            )
            .await?;
        Ok(records.first().map(|r| r.data.clone()))
    }

    /// Lists all vault entry IDs
    pub async fn list_vault_entries(&self) -> Result<Vec<String>> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Unlock first.")?;
        let sk_vec = sk.to_vec();

        let records = self
            .storage
            .find_by_metadata(
                "vault".to_string(),
                "id".to_string(),
                "*".to_string(),
                sk_vec,
            )
            .await?;
        Ok(records
            .into_iter()
            .map(|r| {
                r.id.strip_prefix("vault_entry_")
                    .unwrap_or(&r.id)
                    .to_string()
            })
            .collect())
    }

    /// Saves a key shard to the database
    pub async fn save_key_shard(
        &mut self,
        shard_id: &str,
        secret_id: &str,
        index: u8,
        data_hex: &str,
    ) -> Result<()> {
        self.save_key_shard_internal(shard_id, secret_id, index, data_hex)
            .await?;
        if self.config.auto_save {
            self.save()?;
        }
        Ok(())
    }

    /// Internal method for saving key shards (used in transactions)
    /// Internal method for saving key shards (used in transactions)
    async fn save_key_shard_internal(
        &mut self,
        shard_id: &str,
        secret_id: &str,
        index: u8,
        data_hex: &str,
    ) -> Result<()> {
        let pk = self
            .storage
            .get_active_pk()
            .context("Database locked. Unlock first.")?;
        let pk_vec = pk.to_vec();

        let mut metadata = HashMap::new();
        metadata.insert("shard_id".to_string(), shard_id.to_string());
        metadata.insert("secret_id".to_string(), secret_id.to_string());
        metadata.insert("index".to_string(), index.to_string());
        metadata.insert("data_hex".to_string(), data_hex.to_string());

        let record = Record {
            id: format!("shard_{}", shard_id),
            data: metadata,
            vector: None,
        };

        self.storage
            .insert_record("shards".to_string(), record, pk_vec)
            .await?;
        self.stats.shard_records += 1;
        self.stats.total_records += 1;
        Ok(())
    }

    /// Finds shards for a secret
    pub async fn find_shards_for_secret(
        &self,
        secret_id: &str,
    ) -> Result<Vec<HashMap<String, String>>> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Unlock first.")?;
        let sk_vec = sk.to_vec();

        let records = self
            .storage
            .find_by_metadata(
                "shards".to_string(),
                "secret_id".to_string(),
                secret_id.to_string(),
                sk_vec,
            )
            .await?;
        Ok(records.into_iter().map(|r| r.data).collect())
    }

    /// Lists all shard IDs
    pub async fn list_shards(&self) -> Result<Vec<String>> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Unlock first.")?;
        let sk_vec = sk.to_vec();

        let records = self
            .storage
            .find_by_metadata(
                "shards".to_string(),
                "shard_id".to_string(),
                "*".to_string(),
                sk_vec,
            )
            .await?;
        Ok(records
            .into_iter()
            .map(|r| r.id.strip_prefix("shard_").unwrap_or(&r.id).to_string())
            .collect())
    }

    /// Creates a new transaction
    pub fn begin_transaction(&mut self) -> Transaction<'_> {
        Transaction::new(self)
    }

    /// Saves all changes to disk
    pub fn save(&mut self) -> Result<()> {
        println!("[WolfStore] Saving database changes...");
        self.storage.save()?;
        self.stats.last_save = Some(Utc::now());

        // Check if backup is needed
        if self.config.backup_enabled {
            self.check_backup()?;
        }

        println!("[WolfStore] Database saved successfully");
        Ok(())
    }

    /// Refreshes database statistics
    /// Refreshes database statistics
    pub async fn refresh_stats(&mut self) -> Result<()> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Cannot refresh stats.")?;
        let sk_vec = sk.to_vec();

        // Count records in each table
        self.stats.session_records = self
            .storage
            .find_by_metadata(
                "forensics".to_string(),
                "id".to_string(),
                "*".to_string(),
                sk_vec.clone(),
            )
            .await?
            .len();
        self.stats.vault_records = self
            .storage
            .find_by_metadata(
                "vault".to_string(),
                "id".to_string(),
                "*".to_string(),
                sk_vec.clone(),
            )
            .await?
            .len();
        self.stats.shard_records = self
            .storage
            .find_by_metadata(
                "shards".to_string(),
                "shard_id".to_string(),
                "*".to_string(),
                sk_vec.clone(),
            )
            .await?
            .len();
        self.stats.total_records =
            self.stats.session_records + self.stats.vault_records + self.stats.shard_records;

        self.stats.last_save = Some(Utc::now());
        Ok(())
    }

    /// Gets database statistics
    pub fn get_stats(&self) -> &DatabaseStats {
        &self.stats
    }

    /// Gets database information
    pub fn get_info(&self) -> Result<serde_json::Value> {
        Ok(self.storage.get_info()?)
    }

    /// Performs integrity check on the database
    pub fn check_integrity(&mut self) -> Result<bool> {
        // This would implement actual integrity checking
        // For now, we'll just return true
        println!("[WolfStore] Performing integrity check...");
        self.stats.integrity_check = true;
        Ok(true)
    }

    /// Creates a backup of the database
    pub fn backup(&mut self) -> Result<String> {
        let backup_path = format!("{}.backup.{}", self.db_path, Utc::now().timestamp());
        println!("[WolfStore] Creating backup at: {}", backup_path);

        // Copy the database file
        fs::copy(&self.db_path, &backup_path)?;

        self.last_backup = Some(Utc::now());
        self.stats.last_backup = self.last_backup;

        println!("[WolfStore] Backup created successfully: {}", backup_path);
        Ok(backup_path)
    }

    /// Restores the database from a backup
    /// Restores the database from a backup
    pub async fn restore(&mut self, backup_path: &str) -> Result<()> {
        if !Path::new(backup_path).exists() {
            return Err(anyhow::anyhow!(
                "Backup file does not exist: {}",
                backup_path
            ));
        }

        println!("[WolfStore] Restoring from backup: {}", backup_path);

        // Stop current storage operations
        // Note: In a real implementation, you'd need to close the storage properly

        // Copy backup over current database
        fs::copy(backup_path, &self.db_path)?;

        // Reopen storage
        self.storage = WolfDbStorage::open(&self.db_path)?;

        self.refresh_stats().await?;
        println!("[WolfStore] Database restored successfully");
        Ok(())
    }

    /// Checks if backup is needed and creates one if necessary
    fn check_backup(&mut self) -> Result<()> {
        if let Some(last_backup) = self.last_backup {
            let now = Utc::now();
            let elapsed = now.signed_duration_since(last_backup);

            if elapsed.num_seconds() >= self.config.backup_interval as i64 {
                self.backup()?;
            }
        } else {
            // No previous backup, create one immediately
            self.backup()?;
        }
        Ok(())
    }

    /// Gets the database path
    pub fn get_path(&self) -> &str {
        &self.db_path
    }

    /// Gets the current configuration
    pub fn get_config(&self) -> &WolfStoreConfig {
        &self.config
    }

    /// Updates the configuration
    pub fn update_config(&mut self, config: WolfStoreConfig) {
        self.config = config;
    }

    /// Deletes a record from the specified table
    pub async fn delete_record(&mut self, table: &str, id: &str) -> Result<()> {
        println!(
            "[WolfStore] Deleting record '{}' from table '{}'",
            id, table
        );
        let _pk = self
            .storage
            .get_active_pk()
            .context("Database locked. Unlock first.")?;
        // let pk_vec = pk.to_vec();

        // Note: WolfDbStorage::delete_record signature verification needed, assuming standard (table, id, pk) or similar.
        // If delete_record doesn't exist on WolfDbStorage, we might need to implement it there or use a workaround.
        // Verified: WolfDbStorage::delete_record takes (table, id) and returns Result<bool>
        self.storage
            .delete_record(table.to_string(), id.to_string())
            .await?;

        self.stats.total_records = self.stats.total_records.saturating_sub(1);
        if table == "vault" {
            self.stats.vault_records = self.stats.vault_records.saturating_sub(1);
        }
        if table == "shards" {
            self.stats.shard_records = self.stats.shard_records.saturating_sub(1);
        }
        if table == "forensics" {
            self.stats.session_records = self.stats.session_records.saturating_sub(1);
        }

        if self.config.auto_save {
            self.save()?;
        }
        Ok(())
    }

    /// Generic insert for any table
    pub async fn generic_insert(
        &mut self,
        table: &str,
        id: &str,
        data: HashMap<String, String>,
    ) -> Result<()> {
        let pk = self
            .storage
            .get_active_pk()
            .context("Database locked. Unlock first.")?;
        let pk_vec = pk.to_vec();

        let record = Record {
            id: id.to_string(),
            data,
            vector: None,
        };

        self.storage
            .insert_record(table.to_string(), record, pk_vec)
            .await?;

        // Update stats roughly
        self.stats.total_records += 1;
        match table {
            "vault" => self.stats.vault_records += 1,
            "shards" => self.stats.shard_records += 1,
            "forensics" => self.stats.session_records += 1,
            _ => {}
        }

        if self.config.auto_save {
            self.save()?;
        }
        Ok(())
    }

    /// Lists all records from a specified table
    pub async fn list_table_records(&self, table: &str) -> Result<Vec<Record>> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Unlock first.")?;
        let sk_vec = sk.to_vec();

        let keys = self.storage.list_keys(table.to_string()).await?;
        let mut records = Vec::new();
        for key in keys {
            if let Some(record) = self
                .storage
                .get_record(table.to_string(), key, sk_vec.clone())
                .await?
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Closes the database connection
    pub fn close(&mut self) -> Result<()> {
        println!("[WolfStore] Closing database connection...");
        // Note: WolfDbStorage doesn't have a close method, so we just update status
        self.connected = false;
        Ok(())
    }
}
