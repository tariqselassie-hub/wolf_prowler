//! Selective indexing policy tests for `WolfDb`.

use wolf_db::storage::{WolfDbStorage, IndexingPolicy};
use wolf_db::storage::model::Record;
use std::collections::HashMap;
use tempfile::tempdir;

/// Tests the selective indexing policy to ensure only specified fields are indexed.
///
/// # Errors
///
/// Returns an error if database operations fail.
#[tokio::test]
async fn test_selective_indexing_policy() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path_buf = dir.path().to_owned();
    let path = path_buf.to_str().ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    let mut storage = WolfDbStorage::open(path)?;
    
    // Initialize keystore
    storage.initialize_keystore("password", None)?;
    storage.unlock("password", None)?;
    
    let pk = storage.get_active_pk().ok_or_else(|| anyhow::anyhow!("No PK"))?.to_vec();
    let sk = storage.get_active_sk().ok_or_else(|| anyhow::anyhow!("No SK"))?.to_vec();

    let table_all = "test_all".to_string();
    let table_selected = "test_selected".to_string();
    let table_none = "test_none".to_string();

    // 1. Set Policies
    storage.set_indexing_policy(table_all.clone(), IndexingPolicy::All).await?;
    storage.set_indexing_policy(table_selected.clone(), IndexingPolicy::Selected(vec!["name".into()])).await?;
    storage.set_indexing_policy(table_none.clone(), IndexingPolicy::None).await?;

    // 2. Create Record with multiple fields
    let mut data = HashMap::new();
    data.insert("name".to_string(), "Wolf".to_string());
    data.insert("role".to_string(), "Hunter".to_string());
    data.insert("age".to_string(), "5".to_string());
    
    let record = Record {
        id: "rec1".to_string(),
        data: data.clone(),
        vector: None,
    };

    // 3. Insert into all tables
    storage.insert_record(table_all.clone(), record.clone(), pk.clone()).await?;
    storage.insert_record(table_selected.clone(), record.clone(), pk.clone()).await?;
    storage.insert_record(table_none.clone(), record.clone(), pk.clone()).await?;

    // 4. Verify Indexing behavior via find_by_metadata
    
    // CASE A: Table All - Should find by 'role' and 'name'
    let res = storage.find_by_metadata(table_all.clone(), "role".into(), "Hunter".into(), sk.clone()).await?;
    assert_eq!(res.len(), 1, "Should find record by role in All policy");
    
    // CASE B: Table Selected - Should find by 'name', but NOT by 'role'
    let res = storage.find_by_metadata(table_selected.clone(), "name".into(), "Wolf".into(), sk.clone()).await?;
    assert_eq!(res.len(), 1, "Should find record by name in Selected policy");

    let res = storage.find_by_metadata(table_selected.clone(), "role".into(), "Hunter".into(), sk.clone()).await?;
    assert_eq!(res.len(), 0, "Should NOT find record by role in Selected policy (role not indexed)");

    // CASE C: Table None - Should find by NOTHING
    let res = storage.find_by_metadata(table_none.clone(), "name".into(), "Wolf".into(), sk.clone()).await?;
    assert_eq!(res.len(), 0, "Should NOT find record by name in None policy");

    // 5. Verify Persistence of Policy
    // Re-open storage
    drop(storage);
    let mut storage2 = WolfDbStorage::open(path)?;
    storage2.unlock("password", None)?;
    
    // Insert new record into selected table and verify policy is still active
    let record2 = Record {
        id: "rec2".to_string(),
        data: data.clone(),
        vector: None,
    };
    storage2.insert_record(table_selected.clone(), record2, pk).await?;
    
    let res = storage2.find_by_metadata(table_selected.clone(), "role".into(), "Hunter".into(), sk.clone()).await?;
    assert_eq!(res.len(), 0, "Policy persistence check: role should still not be indexed");
    
    let res = storage2.find_by_metadata(table_selected.clone(), "name".into(), "Wolf".into(), sk.clone()).await?;
    assert_eq!(res.len(), 2, "Policy persistence check: name should be indexed (now 2 records)");

    Ok(())
}
