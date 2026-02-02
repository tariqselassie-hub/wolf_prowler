# Implementation Plan - Large-Scale Stress Test

I will implement a specialized stress test to evaluate the system's performance with larger data volumes and persistent storage.

## Objectives
- Verify scalability with 50,000+ records.
- Stress test the new `insert_batch` optimization.
- Evaluate search performance as the index grows.
- Ensure persistence and logical deletion work correctly at scale.

## Proposed Changes

### [NEW] [large_scale_vector.rs](file:///home/t4riq/Project1/WolfDb/tests/large_scale_vector.rs)
- **Data Generation**: Create 50,000 records with 128-dimensional vectors.
- **Batch Ingestion**: Use `insert_batch` in chunks (e.g., 5,000 records per batch) to maximize throughput.
- **Concurrency**: Perform 100 concurrent search queries while background insertions are happening.
- **Logical Deletion Stress**: Delete 10% of records and verify they are correctly excluded from search results.
- **Persistence Check**: Save the index, re-open the database, and verify that the 50,000 records are still searchable and deletions are preserved.

## Verification Plan
1. **Execution**: Run the test using `cargo test --test large_scale_vector -- --nocapture`.
2. **Metrics**: 
   - Measure total ingestion time.
   - Measure average search latency at 10k, 25k, and 50k records.
   - Verify index file sizes on disk.
