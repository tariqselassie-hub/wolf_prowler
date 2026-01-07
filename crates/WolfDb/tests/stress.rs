use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_high_concurrency_stress() {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().to_str().unwrap();
    let password = "StressPassword";

    let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
    storage
        .initialize_keystore(password, None)
        .expect("Init failed");

    let pk = storage.get_active_pk().unwrap().to_vec();
    let _sk = storage.get_active_sk().unwrap().to_vec();

    let storage = Arc::new(Mutex::new(storage));
    let mut handles = Vec::new();

    println!("Starting stress test: 1,000 concurrent insertions...");
    for i in 0..1000 {
        let storage_clone = Arc::clone(&storage);
        let pk_clone = pk.clone();
        let handle = tokio::spawn(async move {
            let mut data = HashMap::new();
            data.insert("key".to_string(), format!("val_{}", i));
            let record = Record {
                id: format!("doc_{}", i),
                data,
                vector: Some(vec![i as f32; 128]),
            };
            let mut s = storage_clone.lock().await;
            s.insert_record("stress", &record, &pk_clone).unwrap();
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    println!("Stress test: verifying results...");
    let s = storage.lock().await;
    let counts = s.get_info().unwrap();
    println!("Final stats: {}", counts);

    assert!(counts["vector_records"].as_u64().unwrap() >= 1000);
}
