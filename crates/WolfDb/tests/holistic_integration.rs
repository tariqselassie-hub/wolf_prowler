use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;
use std::collections::HashMap;
use tempfile::tempdir;

#[tokio::test]
async fn test_holistic_user_journey() {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().to_str().unwrap();
    let password = "SuperSecretWolfPassword";

    // 1. Initialization
    {
        let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
        storage
            .initialize_keystore(password, None)
            .expect("Init failed");
    }

    // 2. Data Ingestion
    let rec1_id = {
        let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
        storage.unlock(password, None).expect("Unlock failed");

        let mut data = HashMap::new();
        data.insert("name".to_string(), "Alpha Wolf".to_string());
        data.insert("role".to_string(), "Leader".to_string());

        let record = Record {
            id: "wolf_001".to_string(),
            data,
            vector: Some(vec![1.0, 0.0, 0.0]),
        };
        let rid = record.id.clone();

        let pk = storage.get_active_pk().unwrap().to_vec();
        storage
            .insert_record("pack", &record, &pk)
            .expect("Insert failed");
        storage.save().expect("Save failed");
        rid
    };

    // 3. Retrieval and Similarity Search
    {
        let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
        storage.unlock(password, None).expect("Unlock failed");

        let sk = storage.get_active_sk().unwrap().to_vec();
        let retrieved = storage
            .get_record("pack", &rec1_id, &sk)
            .expect("Get failed")
            .expect("Record not found");

        assert_eq!(retrieved.id, rec1_id);
        assert_eq!(retrieved.data.get("name").unwrap(), "Alpha Wolf");

        // Similarity search
        let query_vec = vec![0.9, 0.1, 0.0];
        let results = storage
            .search_similar_records("pack", &query_vec, 5, &sk)
            .expect("Search failed");

        assert!(results.len() >= 1);
        assert_eq!(results[0].0.id, rec1_id);
    }

    // 4. Recovery Flow
    {
        let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
        storage.unlock(password, None).expect("Unlock failed");

        let backup_blob = storage
            .generate_recovery_backup("RecoveryPin123")
            .expect("Backup failed");

        // Simulate new machine/installation
        let dir2 = tempdir().expect("Failed to create second temp dir");
        let path2 = dir2.path().to_str().unwrap();
        let mut storage2 = WolfDbStorage::open(path2).expect("Failed to open storage 2");

        storage2
            .recover_from_backup(&backup_blob, "RecoveryPin123", "NewMasterPass")
            .expect("Recovery failed");

        storage2
            .unlock("NewMasterPass", None)
            .expect("Unlock failed after recovery");
        assert!(storage2.get_active_pk().is_some());
    }
}
