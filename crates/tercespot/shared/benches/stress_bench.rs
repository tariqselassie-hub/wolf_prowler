#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fips203::ml_kem_1024;
use fips203::traits::KeyGen;
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen as DSAKeyGen, Signer, Verifier};
use shared::{decrypt_from_client, encrypt_for_sentinel, parse_and_evaluate, Role};
use std::collections::HashSet;

/// Benchmark: Full end-to-end command submission pipeline
fn bench_end_to_end_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end_pipeline");

    // Setup: Generate keys
    let (pk_kem, sk_kem) = ml_kem_1024::KG::try_keygen().unwrap();
    let (pk_dsa, sk_dsa) = ml_dsa_44::KG::try_keygen().unwrap();
    let command = b"systemctl restart nginx";

    group.bench_function("complete_submission_flow", |b| {
        b.iter(|| {
            // 1. Encrypt command
            let encrypted = encrypt_for_sentinel(black_box(command), black_box(&pk_kem));

            // 2. Sign encrypted payload
            let signature = sk_dsa.try_sign(black_box(&encrypted), b"").unwrap();

            // 3. Verify signature
            let verified = pk_dsa.verify(black_box(&encrypted), black_box(&signature), b"");
            assert!(verified);

            // 4. Decrypt command
            let decrypted = decrypt_from_client(black_box(&encrypted), black_box(&sk_kem)).unwrap();
            assert_eq!(decrypted, command);
        });
    });

    group.finish();
}

/// Benchmark: Policy Evaluation
fn bench_policy_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_evaluation");
    let mut roles = HashSet::new();
    roles.insert(Role::DevOps);
    roles.insert(Role::ComplianceManager);

    let expression = "Role:DevOps AND Role:ComplianceManager";

    group.bench_function("evaluate_complex_policy", |b| {
        b.iter(|| {
            let _ = parse_and_evaluate(black_box(expression), black_box(&roles)).unwrap();
        });
    });
    group.finish();
}

criterion_group!(benches, bench_end_to_end_pipeline, bench_policy_evaluation);
criterion_main!(benches);
