# Implementation Plan - Vector Index Optimization

The goal is to optimize the `VectorIndex` for better performance, functionality, and robustness.

## Proposed Changes

### [vector](file:///home/t4riq/Project1/WolfDb/src/vector/mod.rs)

#### [MODIFY] [mod.rs](file:///home/t4riq/Project1/WolfDb/src/vector/mod.rs)

- **Logical Deletion**: Add a `deleted_ids: HashSet<usize>` to `VectorIndex`.
    - Implement `delete(record_id: &str)` which finds the internal ID and adds it to `deleted_ids`.
    - Update `search` to filter out results that are in `deleted_ids`.
- **Batch Insertion**: Add `insert_batch(records: Vec<(String, Vec<f32>)>)` to allow adding multiple vectors efficiently.
- **Thread Safety**: Wrap `id_map`, `deleted_ids`, and `next_id` in a `std::sync::RwLock` or similar to allow concurrent reads during searches while protecting writes. Note: `hnsw_rs::Hnsw` is already designed for concurrent access for searching, but insertion might need synchronization if not using its parallel APIs.
- **Metadata Optimization**: 
    - Switch from `serde_json` to `bincode` for saving `id_map`, `next_id`, and `deleted_ids`.
    - Rename `vector_meta.json` to `vector_meta.bin`.
- **Configurability**: Introduce a `VectorConfig` struct to allow customizing HNSW parameters (`max_nb_connection`, `ef_construction`, etc.) instead of hardcoding them.
- **Dimension Validation**: Store the expected dimension of vectors and validate all inserts and searches against it.
- **Refactor `load`**: Attempt to improve the `Box::leak` usage if `hnsw_rs` versions allow, or at least document why it's there.

## Verification Plan

### Automated Tests
- Run existing tests in `mod.rs`: `cargo test vector::tests`
- Add new unit tests for:
    - `test_delete`: Verify that deleted records are not returned in search results.
    - `test_batch_insert`: Verify that multiple records can be inserted and searched.
    - `test_dimension_mismatch`: Verify that inserting a vector with the wrong dimension fails.
    - `test_persistence_bincode`: Verify that saving and loading works with the new binary format.

### Manual Verification
- N/A for this low-level component, automated tests should be sufficient.
