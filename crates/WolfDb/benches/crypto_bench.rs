#![allow(missing_docs)]
//! Cryptographic benchmarks for `WolfDb`.

use wolf_db::crypto::aes;
mod criterion_config;
use crate::criterion_config::wolf_db_bench_config;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use wolf_db::crypto::kem;
use wolf_db::crypto::signature;

/// Benchmarks Kyber key encapsulation and decapsulation.
#[allow(clippy::unwrap_used, clippy::semicolon_if_nothing_returned)]
fn bench_kyber(c: &mut Criterion) {
    let (sk, pk) = kem::generate_keypair().unwrap();

    c.bench_function("kyber_encapsulate", |b| {
        b.iter(|| kem::encapsulate_key(black_box(&pk)).unwrap());
    });

    let (ct, _ss) = kem::encapsulate_key(&pk).unwrap();
    c.bench_function("kyber_decapsulate", |b| {
        b.iter(|| kem::decapsulate_key(black_box(&ct), black_box(&sk)).unwrap());
    });
}

/// Benchmarks Dilithium signature generation and verification.
#[allow(clippy::unwrap_used, clippy::semicolon_if_nothing_returned)]
fn bench_dilithium(c: &mut Criterion) {
    let (sk, pk) = signature::generate_keypair().unwrap();
    let msg = b"WolfDb integrity test message benchmark";

    c.bench_function("dilithium_sign", |b| {
        b.iter(|| {
             let keys = signature::reconstruct_keypair(black_box(&sk), black_box(&pk)).unwrap();
             let _ = signature::sign_with_keypair(black_box(&keys), black_box(msg));
        });
    });

    let sig = signature::sign_message(msg, &sk).unwrap();
    c.bench_function("dilithium_verify", |b| {
        b.iter(|| {
            signature::verify_signature(black_box(msg), black_box(&sig), black_box(&pk)).unwrap();
        });
    });
}

/// Benchmarks AES-256-GCM encryption.
#[allow(clippy::unwrap_used, clippy::semicolon_if_nothing_returned)]
fn bench_aes(c: &mut Criterion) {
    let key = [0u8; 32];
    let data = vec![0u8; 1024]; // 1KB

    c.bench_function("aes_encrypt_1kb", |b| {
        b.iter(|| aes::encrypt(black_box(&data), black_box(&key)).unwrap());
    });
}

criterion_group! {
    name = benches;
    config = wolf_db_bench_config();
    targets = bench_kyber, bench_dilithium, bench_aes
}
criterion_main!(benches);
