use anyhow::Result;
use sled::{Db, Tree};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Low-level storage engine based on Sled
#[derive(Clone)]
pub struct StorageEngine {
    /// The underlying Sled database
    db: Db,
    /// Cache of open trees (tables)
    tree_cache: Arc<RwLock<HashMap<String, Tree>>>,
}

impl StorageEngine {
    /// Opens a Sled database at the specified path
    ///
    /// # Errors
    ///
    /// Returns an error if the Sled database cannot be opened.
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self {
            db,
            tree_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Returns a Sled Tree (table) by name, using a cache to avoid repeated opens
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lock is poisoned or if opening the tree fails.
    pub fn get_table(&self, name: &str) -> Result<Tree> {
        // Optimistic read: Check if the tree is already cached
        {
            let cache = self
                .tree_cache
                .read()
                .map_err(|_| anyhow::anyhow!("Cache lock poisoned"))?;
            if let Some(tree) = cache.get(name) {
                return Ok(tree.clone());
            }
        }

        // Write path: Acquire write lock and double-check
        let mut cache = self
            .tree_cache
            .write()
            .map_err(|_| anyhow::anyhow!("Cache lock poisoned"))?;
        if let Some(tree) = cache.get(name) {
            return Ok(tree.clone());
        }

        let tree = self.db.open_tree(name)?;
        cache.insert(name.to_string(), tree.clone());
        drop(cache);
        Ok(tree)
    }

    /// Inserts a raw key-value pair into a table
    ///
    /// # Errors
    ///
    /// Returns an error if the table cannot be opened or if the insertion fails.
    pub fn insert(&self, table: &str, key: &[u8], value: Vec<u8>) -> Result<()> {
        let tree = self.get_table(table)?;
        tree.insert(key, value)?;
        Ok(())
    }

    /// Retrieves a raw value from a table by key
    ///
    /// # Errors
    ///
    /// Returns an error if the table cannot be opened or if the retrieval fails.
    pub fn get(&self, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tree = self.get_table(table)?;
        let res = tree.get(key)?.map(|v| v.to_vec());
        Ok(res)
    }

    /// Deletes a record from a table by key
    ///
    /// # Errors
    ///
    /// Returns an error if the table cannot be opened or if the deletion fails.
    pub fn delete(&self, table: &str, key: &[u8]) -> Result<bool> {
        let tree = self.get_table(table)?;
        let res = tree.remove(key)?;
        Ok(res.is_some())
    }

    /// Returns all records whose keys start with the given prefix
    ///
    /// # Errors
    ///
    /// Returns an error if the table cannot be opened or if the scan fails.
    pub fn scan_prefix(&self, table: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tree = self.get_table(table)?;
        let mut results = Vec::new();
        for item in tree.scan_prefix(prefix) {
            let (k, v) = item?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }

    /// Returns all keys present in a table
    ///
    /// # Errors
    ///
    /// Returns an error if the table cannot be opened or if the iteration fails.
    pub fn scan_keys(&self, table: &str) -> Result<Vec<Vec<u8>>> {
        let tree = self.get_table(table)?;
        let mut keys = Vec::new();
        for item in tree.iter().keys() {
            let k = item?;
            keys.push(k.to_vec());
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn test_engine_basic_ops() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().to_str().unwrap();
        let engine = StorageEngine::open(path).expect("Failed to open engine");

        let table = "test_table";
        let key = b"key1";
        let value = b"value1".to_vec();

        engine
            .insert(table, key, value.clone())
            .expect("Insert failed");
        let retrieved = engine.get(table, key).expect("Get failed");
        assert_eq!(retrieved, Some(value));
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn test_engine_caching() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path().to_str().unwrap();
        let engine = StorageEngine::open(path).expect("Failed to open engine");

        let table = "cached_table";
        let tree1 = engine.get_table(table).expect("First open failed");
        let tree2 = engine.get_table(table).expect("Second open failed");

        // sled::Tree doesn't implement Eq, but we can check if they point to the same name
        // and if they are both functional.
        assert_eq!(tree1.name(), tree2.name());

        // Ensure cache actually populated
        assert!(engine.tree_cache.read().unwrap().contains_key(table));
    }
}
