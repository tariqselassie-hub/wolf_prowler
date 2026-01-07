use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fips203::ml_kem_1024;
use fips203::traits::KeyGen;
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen as DsaKeyGen, Signer, Verifier};
use shared::{decrypt_from_client, encrypt_for_sentinel};

fn bench_dsa_keygen(c: &mut Criterion) {
    c.bench_function("ML-DSA-44 KeyGen", |b| {
        b.iter(|| ml_dsa_44::KG::try_keygen().unwrap())
    });
}

fn bench_dsa_sign(c: &mut Criterion) {
    let (_, sk) = ml_dsa_44::KG::try_keygen().unwrap();
    let msg = b"Hello World";
    let ctx = b"";

    c.bench_function("ML-DSA-44 Sign", |b| {
        b.iter(|| sk.try_sign(black_box(msg), black_box(ctx)).unwrap())
    });
}

fn bench_dsa_verify(c: &mut Criterion) {
    let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
    let msg = b"Hello World";
    let ctx = b"";
    let sig = sk.try_sign(msg, ctx).unwrap();

    c.bench_function("ML-DSA-44 Verify", |b| {
        b.iter(|| pk.verify(black_box(msg), black_box(&sig), black_box(ctx)))
    });
}

fn bench_kem_keygen(c: &mut Criterion) {
    c.bench_function("ML-KEM-1024 KeyGen", |b| {
        b.iter(|| ml_kem_1024::KG::try_keygen().unwrap())
    });
}

fn bench_encryption_flow(c: &mut Criterion) {
    let (pk, _sk) = ml_kem_1024::KG::try_keygen().unwrap();
    let data = b"Secret Command Payload";

    c.bench_function("Encrypt (KEM+AES)", |b| {
        b.iter(|| encrypt_for_sentinel(black_box(data), black_box(&pk)))
    });
}

fn bench_decryption_flow(c: &mut Criterion) {
    let (pk, sk) = ml_kem_1024::KG::try_keygen().unwrap();
    let data = b"Secret Command Payload";
    let encrypted = encrypt_for_sentinel(data, &pk);

    c.bench_function("Decrypt (KEM+AES)", |b| {
        b.iter(|| decrypt_from_client(black_box(&encrypted), black_box(&sk)).unwrap())
    });
}

criterion_group!(
    benches,
    bench_dsa_keygen,
    bench_dsa_sign,
    bench_dsa_verify,
    bench_kem_keygen,
    bench_encryption_flow,
    bench_decryption_flow
);
criterion_main!(benches);
