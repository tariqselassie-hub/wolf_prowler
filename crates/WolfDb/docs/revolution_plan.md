# Implementation Plan: wolf_db Neural Revolution

This plan outlines the "Revolutionary" upgrades to transform wolf_db into a world-class hybrid database, merging high-speed PQC security with enterprise-grade search features.

## 1. Hybrid Filtered Search (The "Wolf Sight" Engine)
**Goal**: Allow filtering by metadata *during* the vector search traversal, avoiding the "over-fetching" problem.

### Proposed Changes
- **Secondary Indexing**: Use `sled` to maintain secondary indices for `Record::data` fields.
- **Internal Filtering**: Implement `hnsw_rs::FilterT` to pass a bitset or ID-check function into the HNSW search.
- **Unified Query API**: Add `search_hybrid(table, vector, k, filter_metadata)` to `WolfDbStorage`.

## 2. Neural Squeeze (SQ8 Quantization)
**Goal**: Reduce RAM and Disk footprint of the vector index by 75%.

### Proposed Changes
- **Quantization Layer**: Implement a module to map `f32` (-1.0 to 1.0) to `u8` (0 to 255).
- **Quantized HNSW**: Option to store internal HNSW vectors as `u8` while keeping the original `f32` for final distance refinement.
- **Performance**: Dramatically improves cache locality and reduces I/O pressure during scale-out.

## 3. Asynchronous PQC Pipeline
**Goal**: Hide Dilithium and Kyber latency by parallelizing them with storage I/O.

### Proposed Changes
- **Worker Pool**: Use a bounded channel and a pool of background threads for PQC operations.
- **Non-Blocking Ingestion**: `insert_record` will return a `Future` or accept a callback, allowing the application to continue while PQC signing happens in the background.

## 4. PQC-Locked Metadata
**Goal**: Zero-leaks on metadata patterns.

### Proposed Changes
- **Encrypted Secondary Index**: Values in the secondary index will be HMAC-protected or encrypted using the PQC keypair.

## Verification Plan
1. **Hybrid Test**: Search with 50,000 records where only 5% match a metadata filter. Verify 100% precision.
2. **Memory Benchmark**: Compare `vector_meta.bin` size before and after SQ8 quantization.
3. **Async Throughput**: Measure IOPS under heavy PQC load using the async pipeline.
