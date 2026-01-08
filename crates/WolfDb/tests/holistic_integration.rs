//! Holistic integration tests for `WolfDb` covering initialization, ingestion, search, and recovery.

use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;
use std::collections::HashMap;
use tempfile::tempdir;

/// Tests the entire user journey from database creation to recovery.
#[tokio::test]
#[allow(clippy::unwrap_used, clippy::expect_used)]
async fn test_holistic_user_journey() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path_buf = dir.path().to_owned();
    let path = path_buf.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    let password = "SuperSecretWolfPassword";

    // 1. Initialization
    {
        let mut storage = WolfDbStorage::open(path)?;
        storage
            .initialize_keystore(password, None)?;
    }

    // 2. Data Ingestion
    let rec1_id = {
        let mut storage = WolfDbStorage::open(path)?;
        storage.unlock(password, None)?;

        let mut data = HashMap::new();
        data.insert("name".to_string(), "Alpha Wolf".to_string());
        data.insert("role".to_string(), "Leader".to_string());

        let record = Record {
            id: "wolf_001".to_string(),
            data,
            vector: Some(vec![1.0, 0.0, 0.0]),
        };
        let rid = record.id.clone();

        let pk = storage.get_active_pk().ok_or_else(|| anyhow::anyhow!("No PK"))?.to_vec();
        storage
            .insert_record("pack".to_string(), record, pk)
            .await?;
        storage.save()?;
        rid
    };

    // 3. Retrieval and Similarity Search
    {
        let mut storage = WolfDbStorage::open(path)?;
        storage.unlock(password, None)?;

        let sk = storage.get_active_sk().ok_or_else(|| anyhow::anyhow!("No SK"))?.to_vec();
        let retrieved = storage
            .get_record("pack".to_string(), rec1_id.clone(), sk.clone())
            .await?
            .ok_or_else(|| anyhow::anyhow!("Record not found"))?;

        assert_eq!(retrieved.id, rec1_id);
        assert_eq!(retrieved.data.get("name").ok_or_else(|| anyhow::anyhow!("Missing name"))?, "Alpha Wolf");

        // Similarity search
        let query_vec = vec![0.9, 0.1, 0.0];
        let results = storage
            .search_similar_records("pack".to_string(), query_vec, 5, sk)
            .await?;

        assert!(!results.is_empty());
        assert_eq!(results[0].0.id, rec1_id);
    }

    // 4. Recovery Flow
    {
        let mut storage = WolfDbStorage::open(path)?;
        storage.unlock(password, None)?;

        let backup_blob = storage
            .generate_recovery_backup("RecoveryPin123")?;

        // Simulate new machine/installation
        let dir2 = tempdir()?;
        let path_buf2 = dir2.path().to_owned();
        let path2 = path_buf2.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path 2"))?;
        let mut storage2 = WolfDbStorage::open(path2)?;

        storage2
            .recover_from_backup(&backup_blob, "RecoveryPin123", "NewMasterPass")?;

        storage2
            .unlock("NewMasterPass", None)?;
        assert!(storage2.get_active_pk().is_some());
    }
    Ok(())
}
