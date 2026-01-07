use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_large_scale_vector_ops() {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().to_str().unwrap();
    let password = "LargeScalePassword";

    let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
    storage
        .initialize_keystore(password, None)
        .expect("Init failed");

    let pk = storage.get_active_pk().unwrap().to_vec();
    let sk = storage.get_active_sk().unwrap().to_vec();

    let storage = Arc::new(RwLock::new(storage));

    let total_records = 50000;
    let batch_size = 5000;
    let vector_dim = 128;

    println!(
        "Starting Large-Scale Stress Test: {} records",
        total_records
    );

    let start_total = Instant::now();

    // 1. Ingest 50,000 records in batches
    for i in (0..total_records).step_by(batch_size) {
        let mut records = Vec::with_capacity(batch_size);
        for j in 0..batch_size {
            let id = i + j;
            let mut data = HashMap::new();
            data.insert("meta".to_string(), format!("data_{}", id));
            records.push(Record {
                id: format!("doc_{}", id),
                data,
                vector: Some(vec![rand::random::<f32>(); vector_dim]),
            });
        }

        let mut s = storage.write().await;
        let batch_start = Instant::now();
        s.insert_batch_records("large_scale", records, &pk).unwrap();
        println!(
            "  Ingested batch {}-{} in {:?}",
            i,
            i + batch_size,
            batch_start.elapsed()
        );
    }

    println!("Total Ingestion Time: {:?}", start_total.elapsed());

    // 2. Stress search queries while index is large
    let search_queries = 100;
    let mut search_handles = Vec::new();

    println!("Starting {} concurrent searches...", search_queries);
    let search_start = Instant::now();
    for _ in 0..search_queries {
        let storage_clone = Arc::clone(&storage);
        let sk_clone = sk.clone();
        let query_vec = vec![rand::random::<f32>(); vector_dim];

        let handle = tokio::spawn(async move {
            let s = storage_clone.read().await;
            let results = s
                .search_similar_records("large_scale", &query_vec, 10, &sk_clone)
                .unwrap();
            assert!(!results.is_empty());
        });
        search_handles.push(handle);
    }

    for handle in search_handles {
        handle.await.unwrap();
    }
    println!("Concurrent Search Time: {:?}", search_start.elapsed());

    // 3. Test logical deletion at scale
    println!("Deleting 1,000 records...");
    {
        let mut s = storage.write().await;
        for i in 0..1000 {
            let id = format!("doc_{}", i);
            s.delete_record("large_scale", &id).unwrap();
        }
    }

    // 4. Persistence Test
    println!("Saving and re-loading database...");
    {
        let s = storage.read().await;
        s.save().unwrap();
    }

    // Explicitly drop Arc and RwLock references to release sled locks
    drop(storage);

    let storage_loaded = WolfDbStorage::open(path).expect("Failed to re-open storage");
    let stats = storage_loaded.get_info().unwrap();
    println!("Final Persistence Stats: {}", stats);

    // Total should still be 50,000 internal IDs, but 1,000 are deleted
    assert_eq!(
        stats["vector_records"].as_u64().unwrap(),
        total_records as u64
    );
    assert_eq!(stats["vector_deleted"].as_u64().unwrap(), 1000);

    println!("Large-Scale Stress Test Completed Successfully!");
}
