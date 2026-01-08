/// Module for vector quantization algorithms
pub mod quantization;
use hnsw_rs::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::RwLock;

/// Configuration for the HNSW vector index
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VectorConfig {
    /// Maximum number of connections per node
    pub max_nb_connection: usize,
    /// Size of the dynamic candidate list during construction
    pub ef_construction: usize,
    /// Maximum connections for nodes at the base layer
    pub level_0_max_nb_connection: usize,
    /// Number of layers in the skip list
    pub nb_layer: usize,
    /// Dimensionality of the vectors
    pub dimension: usize,
    /// Whether to use SQ8 quantization for 75% memory compression
    pub quantized: bool, // SQ8 quantization for 75% compression
}

impl Default for VectorConfig {
    fn default() -> Self {
        Self {
            max_nb_connection: 32,
            ef_construction: 400,
            level_0_max_nb_connection: 64,
            nb_layer: 16,
            dimension: 0,
            quantized: false,
        }
    }
}

enum HnswInstance {
    F32(Hnsw<'static, f32, DistCosine>),
    U8(Hnsw<'static, u8, DistL1>),
}

/// A high-performance vector similarity index based on HNSW
pub struct VectorIndex {
    hnsw: HnswInstance,
    state: RwLock<IndexState>,
    config: VectorConfig,
}

#[derive(Serialize, Deserialize)]
struct IndexState {
    id_map: HashMap<usize, String>,         // internal_id -> record_id
    reverse_id_map: HashMap<String, usize>, // record_id -> internal_id
    deleted_ids: HashSet<usize>,
    next_id: usize,
}

struct HybridFilter<'a> {
    allowed_ids: Option<&'a HashSet<usize>>,
    deleted_ids: &'a HashSet<usize>,
}

impl FilterT for HybridFilter<'_> {
    fn hnsw_filter(&self, id: &usize) -> bool {
        if self.deleted_ids.contains(id) {
            return false;
        }
        if let Some(allowed) = self.allowed_ids {
            return allowed.contains(id);
        }
        true
    }
}

impl VectorIndex {
    /// Initializes a new `VectorIndex` with the given configuration
    #[must_use]
    pub fn new(config: VectorConfig) -> Self {
        let hnsw = if config.quantized {
            HnswInstance::U8(Hnsw::new(
                config.max_nb_connection,
                config.ef_construction,
                config.nb_layer,
                config.level_0_max_nb_connection,
                DistL1,
            ))
        } else {
            HnswInstance::F32(Hnsw::new(
                config.max_nb_connection,
                config.ef_construction,
                config.nb_layer,
                config.level_0_max_nb_connection,
                DistCosine,
            ))
        };
        Self {
            hnsw,
            state: RwLock::new(IndexState {
                id_map: HashMap::new(),
                reverse_id_map: HashMap::new(),
                deleted_ids: HashSet::new(),
                next_id: 0,
            }),
            config,
        }
    }

    /// Inserts a single vector into the index
    ///
    /// # Errors
    ///
    /// Returns an error if the vector dimension is invalid or if the lock is poisoned.
    pub fn insert(&self, record_id: &str, vector: &[f32]) -> Result<(), anyhow::Error> {
        self.validate_dimension(vector.len())?;

        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;

        if let Some(&old_internal_id) = state.reverse_id_map.get(record_id) {
            state.deleted_ids.insert(old_internal_id);
        }

        let internal_id = state.next_id;
        match &self.hnsw {
            HnswInstance::F32(h) => h.insert((vector, internal_id)),
            HnswInstance::U8(h) => {
                let quantized = quantization::ScalarQuantizer::quantize(vector);
                h.insert((&quantized, internal_id));
            }
        }

        state.id_map.insert(internal_id, record_id.to_string());
        state
            .reverse_id_map
            .insert(record_id.to_string(), internal_id);
        state.next_id += 1;
        drop(state);

        Ok(())
    }

    /// Inserts a batch of vectors into the index efficiently
    ///
    /// # Errors
    ///
    /// Returns an error if any vector dimension is invalid or if the lock is poisoned.
    pub fn insert_batch(&self, records: Vec<(String, Vec<f32>)>) -> Result<(), anyhow::Error> {
        for (_, vector) in &records {
            self.validate_dimension(vector.len())?;
        }

        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;

        let mut hnsw_data_f32 = Vec::with_capacity(records.len());
        let mut hnsw_data_u8 = Vec::with_capacity(records.len());

        for (record_id, vector) in records {
            if let Some(&old_internal_id) = state.reverse_id_map.get(&record_id) {
                state.deleted_ids.insert(old_internal_id);
            }

            let internal_id = state.next_id;
            match &self.hnsw {
                HnswInstance::F32(_) => hnsw_data_f32.push((vector, internal_id)),
                HnswInstance::U8(_) => {
                    let quantized = quantization::ScalarQuantizer::quantize(&vector);
                    hnsw_data_u8.push((quantized, internal_id));
                }
            }

            state.id_map.insert(internal_id, record_id.clone());
            state.reverse_id_map.insert(record_id, internal_id);
            state.next_id += 1;
        }

        match &self.hnsw {
            HnswInstance::F32(h) => {
                let refs: Vec<(&Vec<f32>, usize)> =
                    hnsw_data_f32.iter().map(|(v, id)| (v, *id)).collect();
                h.parallel_insert(&refs);
            }
            HnswInstance::U8(h) => {
                let refs: Vec<(&Vec<u8>, usize)> =
                    hnsw_data_u8.iter().map(|(v, id)| (v, *id)).collect();
                h.parallel_insert(&refs);
            }
        }
        drop(state);

        Ok(())
    }

    /// Marks a record as deleted in the index (soft delete)
    pub fn delete(&self, record_id: &str) -> bool {
        if let Ok(mut state) = self.state.write() {
            if let Some(&internal_id) = state.reverse_id_map.get(record_id) {
                return state.deleted_ids.insert(internal_id);
            }
        }
        false
    }

    /// Searches for the top-k most similar records to the query vector
    #[must_use]
    pub fn search(&self, vector: &[f32], k: usize) -> Vec<(String, f32)> {
        self.search_with_filter(vector, k, None)
    }

    /// Performs a similarity search with an optional whitelist of permitted internal IDs
    ///
    /// # Panics
    ///
    /// Panics if the internal index state lock is poisoned.
    #[must_use]
    pub fn search_with_filter(
        &self,
        vector: &[f32],
        k: usize,
        allowed_ids: Option<&HashSet<usize>>,
    ) -> Vec<(String, f32)> {
        #[allow(clippy::expect_used)]
        let state = self.state.read().expect("Lock poisoned");

        let filter = HybridFilter {
            allowed_ids,
            deleted_ids: &state.deleted_ids,
        };

        let results = match &self.hnsw {
            HnswInstance::F32(h) => h.search_possible_filter(vector, k, 64, Some(&filter)),
            HnswInstance::U8(h) => {
                let quantized = quantization::ScalarQuantizer::quantize(vector);
                h.search_possible_filter(&quantized, k, 64, Some(&filter))
            }
        };

        let mapped_results = results
            .into_iter()
            .filter_map(|neighbour| {
                state
                    .id_map
                    .get(&neighbour.d_id)
                    .map(|rid| (rid.clone(), neighbour.distance))
            })
            .collect();
        drop(state);
        mapped_results
    }

    /// Maps a list of record IDs to their internal numerical IDs used by HNSW
    ///
    /// # Panics
    ///
    /// Panics if the internal index state lock is poisoned.
    #[must_use]
    pub fn get_internal_ids(&self, record_ids: &[String]) -> HashSet<usize> {
        #[allow(clippy::expect_used)]
        let state = self.state.read().expect("Lock poisoned");
        let ids = record_ids
            .iter()
            .filter_map(|rid| state.reverse_id_map.get(rid).copied())
            .collect();
        drop(state);
        ids
    }

    /// # Errors
    ///
    /// Returns an error if the vector dimension doesn't match the index configuration.
    fn validate_dimension(&self, dim: usize) -> Result<(), anyhow::Error> {
        if self.config.dimension == 0 {
            return Ok(());
        }
        if dim != self.config.dimension {
            return Err(anyhow::anyhow!(
                "Dimension mismatch: expected {expected}, got {dim}",
                expected = self.config.dimension,
                dim = dim
            ));
        }
        Ok(())
    }

    /// Serializes the index and its metadata to a directory
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation, file writing, or HNSW dumping fails.
    pub fn save(&self, directory: &str) -> Result<(), anyhow::Error> {
        let dir_path = Path::new(directory);
        if !dir_path.exists() {
            std::fs::create_dir_all(dir_path)?;
        }

        let state = self
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;

        if state.next_id > 0 {
            use hnsw_rs::prelude::AnnT;
            let hnsw_basename = "hnsw_index";
            match &self.hnsw {
                HnswInstance::F32(h) => {
                    let _ = h
                        .file_dump(dir_path, hnsw_basename)
                        .map_err(|e| anyhow::anyhow!("HNSW dump failed: {e}"))?;
                }
                HnswInstance::U8(h) => {
                    let _ = h
                        .file_dump(dir_path, hnsw_basename)
                        .map_err(|e| anyhow::anyhow!("HNSW dump failed: {e}"))?;
                }
            }
        }

        let meta_path = dir_path.join("vector_meta.bin");
        let file = File::create(meta_path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, &(&*state, &self.config))?;
        drop(state);

        Ok(())
    }

    /// Loads a `VectorIndex` and its HNSW state from a directory
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata file is missing or corrupted, or if HNSW loading fails.
    pub fn load(directory: &str) -> Result<Self, anyhow::Error> {
        let dir_path = Path::new(directory);
        let hnsw_basename = "hnsw_index";

        let meta_path = dir_path.join("vector_meta.bin");
        let (state, config): (IndexState, VectorConfig) = if meta_path.exists() {
            let file = File::open(meta_path)?;
            let reader = BufReader::new(file);
            bincode::deserialize_from(reader)?
        } else {
            return Err(anyhow::anyhow!("Metadata not found in {directory}"));
        };

        let hnsw_io = Box::new(HnswIo::new(dir_path, hnsw_basename));
        let hnsw_io_leak = Box::leak(hnsw_io);

        let hnsw = if config.quantized {
            let h = hnsw_io_leak
                .load_hnsw_with_dist(DistL1)
                .map_err(|e| anyhow::anyhow!("HNSW load failed: {e}"))?;
            HnswInstance::U8(h)
        } else {
            let h = hnsw_io_leak
                .load_hnsw_with_dist(DistCosine)
                .map_err(|e| anyhow::anyhow!("HNSW load failed: {e}"))?;
            HnswInstance::F32(h)
        };

        Ok(Self {
            hnsw,
            state: RwLock::new(state),
            config,
        })
    }

    /// Returns statistics about the index (total nodes, active nodes, deleted nodes)
    ///
    /// # Panics
    ///
    /// Panics if the internal index state lock is poisoned.
    #[must_use]
    pub fn get_stats(&self) -> (usize, usize, usize) {
        #[allow(clippy::expect_used)]
        let state = self.state.read().expect("Lock poisoned");
        let current_stats = (state.next_id, state.id_map.len(), state.deleted_ids.len());
        drop(state);
        current_stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_vector_search() {
        let index = VectorIndex::new(VectorConfig::default());
        index.insert("a", &[1.0, 0.0, 0.0]).unwrap();
        index.insert("b", &[0.0, 1.0, 0.0]).unwrap();

        let results = index.search(&[1.0, 0.1, 0.0], 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "a");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_quantized_search() {
        let config = VectorConfig {
            quantized: true,
            dimension: 3,
            ..Default::default()
        };
        let index = VectorIndex::new(config);
        index.insert("p1", &[1.0, 0.0, 0.0]).unwrap();
        index.insert("p2", &[0.0, 1.0, 0.0]).unwrap();

        let results = index.search(&[0.9, 0.1, 0.0], 1);
        assert_eq!(results[0].0, "p1");
    }
}
