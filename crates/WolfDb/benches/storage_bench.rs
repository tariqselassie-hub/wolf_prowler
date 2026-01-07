mod criterion_config;
use crate::criterion_config::wolf_db_bench_config;
use criterion::{Criterion, criterion_group, criterion_main};
use std::collections::HashMap;
use tempfile::tempdir;
use wolf_db::storage::WolfDbStorage;
use wolf_db::storage::model::Record;

fn bench_storage_ingestion(c: &mut Criterion) {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().to_str().unwrap();
    let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
    let password = "WolfPassword123";
    storage
        .initialize_keystore(password, None)
        .expect("Init failed");

    let pk = storage.get_active_pk().unwrap().to_vec();

    c.bench_function("storage_insert_record", |b| {
        b.iter(|| {
            let record = Record {
                id: uuid::Uuid::new_v4().to_string(),
                data: HashMap::new(),
                vector: Some(vec![rand::random::<f32>(); 128]),
            };
            storage.insert_record("bench", &record, &pk).unwrap();
        })
    });
}

fn bench_vector_search(c: &mut Criterion) {
    let dir = tempdir().expect("Failed to create temp dir");
    let path = dir.path().to_str().unwrap();
    let mut storage = WolfDbStorage::open(path).expect("Failed to open storage");
    let password = "WolfPassword123";
    storage
        .initialize_keystore(password, None)
        .expect("Init failed");

    let pk = storage.get_active_pk().unwrap().to_vec();

    // Pre-fill with 100 records
    for i in 0..100 {
        let record = Record {
            id: format!("doc_{}", i),
            data: HashMap::new(),
            vector: Some(vec![rand::random::<f32>(); 128]),
        };
        storage.insert_record("search_bench", &record, &pk).unwrap();
    }

    let sk = storage.get_active_sk().unwrap().to_vec();
    let query_vec = vec![0.5f32; 128];

    c.bench_function("vector_search_k5_n100", |b| {
        b.iter(|| {
            storage
                .search_similar_records("search_bench", &query_vec, 5, &sk)
                .unwrap()
        })
    });
}

criterion_group! {
    name = benches;
    config = wolf_db_bench_config();
    targets = bench_storage_ingestion, bench_vector_search
}
criterion_main!(benches);
