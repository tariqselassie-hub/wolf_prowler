//! Proof of Work and Cryptography Benchmark
//!
//! This binary benchmarks the performance of:
//! 1.  **ML-KEM-1024**: Key encapsulation (`KeyGen`, Encaps, Decaps).
//! 2.  **AES-GCM**: Symmetric encryption using the KEM-derived shared secret.
//!
//! It measures the time taken for:
//! - Sentinel key generation.
//! - Client data encryption (KEM encaps + AES encrypt).
//! - Sentinel data decryption (KEM decaps + AES decrypt).
//!
//! The results are printed to stdout as a report.

use fips203::ml_kem_1024;
use fips203::traits::KeyGen;

use shared::{decrypt_from_client, encrypt_for_sentinel};
use std::fmt::Write;
use std::time::Instant;

#[allow(clippy::expect_used)]
fn main() {
    let mut report = String::new();
    let _ = writeln!(report, "=== PQC + AES Latency Benchmark ===");

    // 1. KeyGen
    let start_kg = Instant::now();
    let (pk, sk) = ml_kem_1024::KG::try_keygen().expect("KeyGen failed");
    let dur_kg = start_kg.elapsed();
    let _ = writeln!(report, "KeyGen: {dur_kg:.2?}");

    let data = b"Detecting anomalous movement in Sector 7";

    // 2. Encrypt (Client Side)
    let start_enc = Instant::now();
    let blob = encrypt_for_sentinel(data, &pk);
    let dur_enc = start_enc.elapsed();
    let _ = writeln!(report, "Encrypt (Encap+AES): {dur_enc:.2?}");

    // 3. Decrypt (Sentinel Side)
    let start_dec = Instant::now();
    let decrypted = decrypt_from_client(&blob, &sk).expect("Decrypt failed");
    let dur_dec = start_dec.elapsed();
    let _ = writeln!(report, "Decrypt (Decap+AES): {dur_dec:.2?}");

    assert_eq!(data.as_slice(), decrypted.as_slice());

    let _ = writeln!(report, "-----------------------------------");
    tracing::info!("{report}");
}
