use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_hybrid_search_accuracy() {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().to_str().unwrap();
    let password = "HybridPassword";

    let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
    storage
        .initialize_keystore(password, None)
        .expect("Init failed");

    let pk = storage.get_active_pk().unwrap().to_vec();
    let sk = storage.get_active_sk().unwrap().to_vec();

    println!("Inserting mixed metadata records...");

    // Half Alpha, half Beta
    for i in 0..100 {
        let mut data = HashMap::new();
        let category = if i % 2 == 0 { "alpha" } else { "beta" };
        data.insert("category".to_string(), category.to_string());

        let record = Record {
            id: format!("doc_{}", i),
            data,
            vector: Some(vec![1.0; 128]), // All same vector for simplicity
        };
        storage.insert_record("hybrid", &record, &pk).unwrap();
    }

    // Search for "alpha" category
    println!("Performing hybrid search for 'category:alpha'...");
    let query_vector = vec![1.0; 128];
    let results = storage
        .search_hybrid("hybrid", &query_vector, 10, "category", "alpha", &sk)
        .unwrap();

    assert_eq!(results.len(), 10);
    for (rec, _) in results {
        assert_eq!(rec.data.get("category").unwrap(), "alpha");
        println!("  Found matching record: {}", rec.id);
    }

    // Search for "beta" category
    println!("Performing hybrid search for 'category:beta'...");
    let results_beta = storage
        .search_hybrid("hybrid", &query_vector, 5, "category", "beta", &sk)
        .unwrap();
    assert_eq!(results_beta.len(), 5);
    for (rec, _) in results_beta {
        assert_eq!(rec.data.get("category").unwrap(), "beta");
    }

    println!("Hybrid Search Test Completed Successfully!");
}
