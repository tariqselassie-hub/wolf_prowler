//! Persistent Storage for Raft using Sled
//!
//! Implements the Raft Storage trait using Sled embedded database.

use anyhow::Result;
use prost::Message;
use raft::{
    eraftpb::{ConfState, Entry, HardState, Snapshot},
    RaftState, Storage, StorageError,
};
use sled::Db;
use std::sync::{Arc, RwLock as StdRwLock};

const KEY_HARD_STATE: &[u8] = b"hard_state";
const KEY_CONF_STATE: &[u8] = b"conf_state";
const KEY_SNAPSHOT: &[u8] = b"snapshot";
const KEY_COMMIT_INDEX: &[u8] = b"commit_index";
const PREFIX_ENTRY: &[u8] = b"entry_";

/// Sled-based storage for Raft
#[derive(Clone)]
pub struct SledStorage {
    db: Db,
    hard_state: Arc<StdRwLock<HardState>>,
    conf_state: Arc<StdRwLock<ConfState>>,
    snapshot: Arc<StdRwLock<Snapshot>>,
}

#[allow(clippy::expect_used)]
impl SledStorage {
    /// Create new Sled storage
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or initialized.
    pub fn new(path: &str) -> Result<Self> {
        let db = sled::open(path)?;

        // Load or initialize hard state
        let hard_state = if let Some(data) = db.get(KEY_HARD_STATE)? {
            <HardState as Message>::decode(&data[..])?
        } else {
            HardState::default()
        };

        // Load or initialize conf state
        let conf_state = if let Some(data) = db.get(KEY_CONF_STATE)? {
            <ConfState as Message>::decode(&data[..])?
        } else {
            ConfState::default()
        };

        // Load or initialize snapshot
        let snapshot = if let Some(data) = db.get(KEY_SNAPSHOT)? {
            <Snapshot as Message>::decode(&data[..])?
        } else {
            Snapshot::default()
        };

        Ok(Self {
            db,
            hard_state: Arc::new(StdRwLock::new(hard_state)),
            conf_state: Arc::new(StdRwLock::new(conf_state)),
            snapshot: Arc::new(StdRwLock::new(snapshot)),
        })
    }

    /// Set commit index
    ///
    /// # Errors
    /// Returns an error if the database write fails.
    pub fn set_commit_index(&self, index: u64) -> Result<()> {
        self.db.insert(KEY_COMMIT_INDEX, &index.to_le_bytes())?;
        Ok(())
    }

    /// Get entry key
    fn entry_key(index: u64) -> Vec<u8> {
        let mut key = PREFIX_ENTRY.to_vec();
        key.extend_from_slice(&index.to_le_bytes());
        key
    }

    /// Append entries
    ///
    /// # Errors
    /// Returns an error if encoding or database write fails.
    pub fn append(&self, entries: &[Entry]) -> Result<()> {
        for entry in entries {
            let key = Self::entry_key(entry.index);
            let mut data = Vec::new();
            <Entry as Message>::encode(entry, &mut data)?;
            self.db.insert(key, data)?;
        }
        self.db.flush()?;
        Ok(())
    }

    /// Set hard state
    ///
    /// # Errors
    /// Returns an error if encoding or database write fails.
    ///
    /// # Panics
    /// Panics if the `hard_state` write lock is poisoned.
    pub fn set_hard_state(&self, hs: &HardState) -> Result<()> {
        let mut data = Vec::new();
        <HardState as Message>::encode(hs, &mut data)?;
        self.db.insert(KEY_HARD_STATE, data)?;
        *self.hard_state.write().expect("hard_state lock poisoned") = hs.clone();
        self.db.flush()?;
        Ok(())
    }

    /// Set conf state
    ///
    /// # Errors
    /// Returns an error if encoding fails or database write fails.
    ///
    /// # Panics
    /// Panics if the `conf_state` write lock is poisoned.
    pub fn set_conf_state(&self, cs: &ConfState) -> Result<()> {
        let mut data = Vec::new();
        <ConfState as Message>::encode(cs, &mut data)?;
        self.db.insert(KEY_CONF_STATE, data)?;
        *self.conf_state.write().expect("conf_state lock poisoned") = cs.clone();
        self.db.flush()?;
        Ok(())
    }

    /// Apply a snapshot to the storage
    ///
    /// # Errors
    /// Returns a `raft::Error::Store` if encoding or writing to the database fails.
    ///
    /// # Panics
    /// Panics if the internal `RwLock`s are poisoned.
    pub fn apply_snapshot(&self, snapshot: &Snapshot) -> Result<(), raft::Error> {
        let mut hs = self.hard_state.write().expect("hard_state lock poisoned");
        let mut cs = self.conf_state.write().expect("conf_state lock poisoned");
        let mut snap = self.snapshot.write().expect("snapshot lock poisoned");

        let metadata = snapshot.get_metadata();
        *hs = HardState {
            term: metadata.term,
            commit: metadata.index,
            ..Default::default()
        };
        *cs = metadata.get_conf_state().clone();
        *snap = snapshot.clone();

        // Persist states
        let mut data = Vec::new();
        hs.encode(&mut data)
            .map_err(|e| raft::Error::Store(StorageError::Other(Box::new(e))))?;
        drop(hs);
        self.db
            .insert(KEY_HARD_STATE, data.clone())
            .map_err(|e| raft::Error::Store(StorageError::Other(Box::new(e))))?;

        data.clear();
        cs.encode(&mut data)
            .map_err(|e| raft::Error::Store(StorageError::Other(Box::new(e))))?;
        drop(cs);
        self.db
            .insert(KEY_CONF_STATE, data.clone())
            .map_err(|e| raft::Error::Store(StorageError::Other(Box::new(e))))?;

        data.clear();
        snap.encode(&mut data)
            .map_err(|e| raft::Error::Store(StorageError::Other(Box::new(e))))?;
        drop(snap);
        self.db
            .insert(KEY_SNAPSHOT, data)
            .map_err(|e| raft::Error::Store(StorageError::Other(Box::new(e))))?;

        Ok(())
    }
}

#[allow(clippy::expect_used)]
impl Storage for SledStorage {
    fn initial_state(&self) -> raft::Result<RaftState> {
        Ok(RaftState {
            hard_state: self
                .hard_state
                .read()
                .expect("hard_state lock poisoned")
                .clone(),
            conf_state: self
                .conf_state
                .read()
                .expect("conf_state lock poisoned")
                .clone(),
        })
    }

    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        _context: raft::GetEntriesContext,
    ) -> raft::Result<Vec<Entry>> {
        let max_size = max_size.into();
        let mut entries = Vec::new();
        let mut total_size = 0u64;

        for index in low..high {
            let key = Self::entry_key(index);

            if let Some(data) = self
                .db
                .get(&key)
                .map_err(|e| StorageError::Other(Box::new(e)))?
            {
                let entry: Entry = <Entry as Message>::decode(&data[..])
                    .map_err(|e| StorageError::Other(Box::new(e)))?;

                let entry_size = entry.data.len() as u64;

                if let Some(max) = max_size {
                    if total_size.saturating_add(entry_size) > max && !entries.is_empty() {
                        break;
                    }
                }

                total_size = total_size.saturating_add(entry_size);
                entries.push(entry);
            } else {
                return Err(raft::Error::Store(StorageError::Unavailable));
            }
        }

        Ok(entries)
    }

    fn term(&self, idx: u64) -> raft::Result<u64> {
        let snapshot = self.snapshot.read().expect("snapshot lock poisoned");
        if idx == snapshot.get_metadata().index {
            return Ok(snapshot.get_metadata().term);
        }
        drop(snapshot);

        let key = Self::entry_key(idx);

        if let Some(data) = self
            .db
            .get(&key)
            .map_err(|e| raft::Error::Store(StorageError::Other(Box::new(e))))?
        {
            let entry: Entry = <Entry as Message>::decode(&data[..])
                .map_err(|e| raft::Error::Store(StorageError::Other(Box::new(e))))?;
            Ok(entry.term)
        } else {
            Err(raft::Error::Store(StorageError::Unavailable))
        }
    }

    fn first_index(&self) -> raft::Result<u64> {
        let snapshot = self.snapshot.read().expect("snapshot lock poisoned");
        Ok(snapshot.get_metadata().index.saturating_add(1))
    }

    fn last_index(&self) -> raft::Result<u64> {
        // Scan for last entry
        let mut last_idx = self.first_index()?.saturating_sub(1);

        for (key, _) in self.db.scan_prefix(PREFIX_ENTRY).flatten() {
            let start = PREFIX_ENTRY.len();
            let end = start.saturating_add(8);
            if let Some(idx_bytes_slice) = key.get(start..end) {
                let idx_bytes: [u8; 8] = idx_bytes_slice.try_into().expect("Slice length correct");
                let idx = u64::from_le_bytes(idx_bytes);
                if idx > last_idx {
                    last_idx = idx;
                }
            }
        }

        Ok(last_idx)
    }

    fn snapshot(&self, _request_index: u64, _to: u64) -> raft::Result<Snapshot> {
        Ok(self
            .snapshot
            .read()
            .expect("snapshot lock poisoned")
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_sled_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SledStorage::new(temp_dir.path().to_str().unwrap()).unwrap();

        let state = storage.initial_state().unwrap();
        assert_eq!(state.hard_state.term, 0);
    }

    #[test]
    fn test_append_and_retrieve_entries() {
        let temp_dir = TempDir::new().unwrap();
        let storage = SledStorage::new(temp_dir.path().to_str().unwrap()).unwrap();

        let entries = vec![Entry {
            entry_type: raft::eraftpb::EntryType::EntryNormal.into(),
            term: 1,
            index: 1,
            data: b"test data".to_vec(),
            ..Default::default()
        }];

        storage.append(&entries).unwrap();

        let retrieved = storage
            .entries(1, 2, None, raft::GetEntriesContext::empty(false))
            .unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].data, b"test data"[..]);
    }
}
