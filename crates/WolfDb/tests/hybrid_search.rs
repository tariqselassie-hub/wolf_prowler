//! Hybrid search accuracy tests for `WolfDb`.

use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;
use std::collections::HashMap;
use tempfile::tempdir;

/// Tests the accuracy of hybrid search combining vector similarity and metadata filtering.
#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn test_hybrid_search_accuracy() -> anyhow::Result<()> {
    let dir = tempdir().map_err(|e| anyhow::anyhow!("Failed to create temp dir: {e}"))?;
    let path_buf = dir.path().to_owned();
    let path = path_buf.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    let password = "HybridPassword";

    let mut storage = WolfDbStorage::open(path).map_err(|e| anyhow::anyhow!("Failed to open storage: {e}"))?;
    storage
        .initialize_keystore(password, None)
        .map_err(|e| anyhow::anyhow!("Init failed: {e}"))?;

    let pk = storage.get_active_pk().ok_or_else(|| anyhow::anyhow!("No PK"))?.to_vec();
    let sk = storage.get_active_sk().ok_or_else(|| anyhow::anyhow!("No SK"))?.to_vec();

    println!("Inserting mixed metadata records...");

    // Half Alpha, half Beta
    for i in 0..100 {
        let mut data = HashMap::new();
        let category = if i % 2 == 0 { "alpha" } else { "beta" };
        data.insert("category".to_string(), category.to_string());

        let record = Record {
            id: format!("doc_{i}"),
            data,
            vector: Some(vec![1.0; 128]), // All same vector for simplicity
        };
        storage.insert_record("hybrid".to_string(), record, pk.clone()).await?;
    }

    // Search for "alpha" category
    println!("Performing hybrid search for 'category:alpha'...");
    let query_vector = vec![1.0; 128];
    let results = storage
        .search_hybrid("hybrid".to_string(), query_vector.clone(), 10, "category".to_string(), "alpha".to_string(), sk.clone())
        .await?;

    assert_eq!(results.len(), 10);
    for (rec, _) in results {
        #[allow(clippy::unwrap_used)]
        {
            assert_eq!(rec.data.get("category").unwrap(), "alpha");
        }
        println!("  Found matching record: {}", rec.id);
    }

    // Search for "beta" category
    println!("Performing hybrid search for 'category:beta'...");
    let results_beta = storage
        .search_hybrid("hybrid".to_string(), query_vector, 5, "category".to_string(), "beta".to_string(), sk)
        .await?;
    assert_eq!(results_beta.len(), 5);
    for (rec, _) in results_beta {
        #[allow(clippy::unwrap_used)]
        {
            assert_eq!(rec.data.get("category").unwrap(), "beta");
        }
    }

    println!("Hybrid Search Test Completed Successfully!");
    Ok(())
}
