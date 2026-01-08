//! Large-scale performance and stress tests for `WolfDb`.

use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;

/// Tests large-scale vector operations including batch ingestion and concurrent search.
///
/// # Panics
///
/// Panics if database operations fail.
#[tokio::test]
async fn test_large_scale_vector_ops() -> anyhow::Result<()> {
    let dir = tempdir().map_err(|e| anyhow::anyhow!("Failed to create temp dir: {e}"))?;
    let path_buf = dir.path().to_owned();
    let path = path_buf.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    let password = "LargeScalePassword";

    let mut storage = WolfDbStorage::open(path).map_err(|e| anyhow::anyhow!("Failed to open storage: {e}"))?;
    storage
        .initialize_keystore(password, None)
        .map_err(|e| anyhow::anyhow!("Init failed: {e}"))?;

    let pk = storage.get_active_pk().ok_or_else(|| anyhow::anyhow!("No PK"))?.to_vec();
    let sk = storage.get_active_sk().ok_or_else(|| anyhow::anyhow!("No SK"))?.to_vec();

    // No RwLock needed 
    let storage = Arc::new(storage);

    let total_records = 50_000;
    let batch_size = 5_000;
    let vector_dim = 128;

    println!("Starting Large-Scale Stress Test: {total_records} records");

    let start_total = Instant::now();

    // 1. Ingest 50,000 records in batches
    for i in (0..total_records).step_by(batch_size) {
        let mut records = Vec::with_capacity(batch_size);
        for j in 0..batch_size {
            let id = i + j;
            let mut data = HashMap::new();
            data.insert("meta".to_string(), format!("data_{id}"));
            records.push(Record {
                id: format!("doc_{id}"),
                data,
                vector: Some(vec![rand::random::<f32>(); vector_dim]),
            });
        }

        let batch_start = Instant::now();
        storage.insert_batch_records("large_scale".to_string(), records, pk.clone()).await?;
        println!(
            "  Ingested batch {i}-{} in {:?}",
            i + batch_size,
            batch_start.elapsed()
        );
    }

    println!("Total Ingestion Time: {:?}", start_total.elapsed());

    // 2. Stress search queries while index is large
    let search_queries = 100;
    let mut search_handles = Vec::new();

    println!("Starting {search_queries} concurrent searches...");
    let search_start = Instant::now();
    for _ in 0..search_queries {
        let storage_clone = Arc::clone(&storage);
        let sk_clone = sk.clone();
        let query_vec = vec![rand::random::<f32>(); vector_dim];

        let handle = tokio::spawn(async move {
            // storage_clone is Arc<WolfDbStorage>
            #[allow(clippy::expect_used)]
            let results = storage_clone
                .search_similar_records("large_scale".to_string(), query_vec, 10, sk_clone)
                .await
                .expect("Search failed");
            assert!(!results.is_empty());
        });
        search_handles.push(handle);
    }

    for handle in search_handles {
        handle.await.map_err(|e| anyhow::anyhow!("Handle join failed: {e}"))?;
    }
    println!("Concurrent Search Time: {:?}", search_start.elapsed());

    // 3. Test logical deletion at scale
    println!("Deleting 1,000 records...");
    {
        for i in 0..1000 {
            let id = format!("doc_{i}");
            storage.delete_record("large_scale".to_string(), id).await?;
        }
    }

    // 4. Persistence Test
    println!("Saving and re-loading database...");
    {
        // save is sync, but we are in async. It's fast enough.
        storage.save()?;
    }

    // Explicitly drop Arc and RwLock references to release sled locks
    drop(storage);

    let storage_loaded = WolfDbStorage::open(path).map_err(|e| anyhow::anyhow!("Failed to re-open storage: {e}"))?;
    let stats = storage_loaded.get_info().map_err(|e| anyhow::anyhow!("Failed to get info: {e}"))?;
    println!("Final Persistence Stats: {stats}");

    // Total should still be 50,000 internal IDs, but 1,000 are deleted
    assert_eq!(
        stats["vector_records"].as_u64().ok_or_else(|| anyhow::anyhow!("Missing vector_records"))?,
        total_records as u64
    );
    assert_eq!(stats["vector_deleted"].as_u64().ok_or_else(|| anyhow::anyhow!("Missing vector_deleted"))?, 1000);

    println!("Large-Scale Stress Test Completed Successfully!");
    Ok(())
}
