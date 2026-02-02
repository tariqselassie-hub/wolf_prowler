//! High-concurrency stress tests for `WolfDb`.

use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;
use wolf_db::storage::model::Record;
use wolf_db::storage::WolfDbStorage;

/// Tests high-concurrency record insertions.
#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::cast_precision_loss)]
async fn test_high_concurrency_stress() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path_buf = dir.path().to_owned();
    let path = path_buf
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    let password = "StressPassword";

    let mut storage = WolfDbStorage::open(path)?;
    storage.initialize_keystore(password, None)?;

    let pk = storage
        .get_active_pk()
        .ok_or_else(|| anyhow::anyhow!("No PK"))?
        .to_vec();
    let _sk = storage
        .get_active_sk()
        .ok_or_else(|| anyhow::anyhow!("No SK"))?
        .to_vec();

    // No Mutex needed for insert_record as it takes &self now
    let storage = Arc::new(storage);
    let mut handles = Vec::new();

    tracing::info!("Starting stress test: 1,000 concurrent insertions...");
    for i in 0..1000 {
        let storage_clone = Arc::clone(&storage);
        let pk_clone = pk.clone();
        let handle = tokio::spawn(async move {
            let mut data = HashMap::new();
            data.insert("key".to_string(), format!("val_{i}"));
            let record = Record {
                id: format!("doc_{i}"),
                data,
                vector: Some(vec![i as f32; 128]),
            };

            // Storage is Arc<WolfDbStorage>
            storage_clone
                .insert_record("stress".to_string(), record, pk_clone)
                .await
                .expect("Insert failed");
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }

    tracing::info!("Stress test: verifying results...");
    let counts = storage.get_info()?;
    tracing::info!("Final stats: {counts}");

    assert!(
        counts["vector_records"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing count"))?
            >= 1000
    );
    Ok(())
}
