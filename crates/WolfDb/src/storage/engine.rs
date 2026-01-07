use anyhow::Result;
use sled::{Db, Tree};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct StorageEngine {
    db: Db,
    tree_cache: Arc<Mutex<HashMap<String, Tree>>>,
}

impl StorageEngine {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self {
            db,
            tree_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn get_table(&self, name: &str) -> Result<Tree> {
        let mut cache = self
            .tree_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Cache lock poisoned"))?;
        if let Some(tree) = cache.get(name) {
            return Ok(tree.clone());
        }
        let tree = self.db.open_tree(name)?;
        cache.insert(name.to_string(), tree.clone());
        Ok(tree)
    }

    pub fn insert(&self, table: &str, key: &[u8], value: Vec<u8>) -> Result<()> {
        let tree = self.get_table(table)?;
        tree.insert(key, value)?;
        Ok(())
    }

    pub fn get(&self, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tree = self.get_table(table)?;
        let res = tree.get(key)?.map(|v| v.to_vec());
        Ok(res)
    }

    pub fn delete(&self, table: &str, key: &[u8]) -> Result<bool> {
        let tree = self.get_table(table)?;
        let res = tree.remove(key)?;
        Ok(res.is_some())
    }

    pub fn scan_prefix(&self, table: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tree = self.get_table(table)?;
        let mut results = Vec::new();
        for item in tree.scan_prefix(prefix) {
            let (k, v) = item?;
            results.push((k.to_vec(), v.to_vec()));
        }
        Ok(results)
    }

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
        let cache = engine.tree_cache.lock().unwrap();
        assert!(cache.contains_key(table));
    }
}
