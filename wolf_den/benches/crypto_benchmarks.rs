//! Cryptographic benchmarking suite for Wolf Den

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use wolf_den::{
    hash::{create_hasher, HashFunction},
    kdf::{create_kdf, KdfType},
    SecurityLevel,
};

const TEST_DATA_1KB: &[u8] = &[0u8; 1024];
const TEST_PASSWORD: &[u8] = b"benchmark_password_12345";
const TEST_SALT: &[u8] = b"benchmark_salt_67890";

fn bench_hash_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_functions");

    // BLAKE3 benchmarks
    group.bench_function("blake3_1kb", |b| {
        let hasher = create_hasher(HashFunction::Blake3, SecurityLevel::Standard).unwrap();
        b.iter(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async { hasher.digest(black_box(TEST_DATA_1KB)).await.unwrap() })
        })
    });

    group.finish();
}

fn bench_kdf_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf_functions");

    // PBKDF2 benchmarks
    group.bench_function("pbkdf2_256bit", |b| {
        let kdf = create_kdf(KdfType::Pbkdf2, SecurityLevel::Standard).unwrap();
        b.iter(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                kdf.derive_key(
                    black_box(TEST_PASSWORD),
                    black_box(TEST_SALT),
                    black_box(32),
                )
                .await
                .unwrap()
            })
        })
    });

    group.finish();
}

criterion_group!(benches, bench_hash_functions, bench_kdf_functions);
criterion_main!(benches);
