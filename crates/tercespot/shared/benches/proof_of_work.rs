use fips203::ml_kem_1024;
use fips203::traits::KeyGen;

use shared::{decrypt_from_client, encrypt_for_sentinel};
use std::fs::File;
use std::io::Write;
use std::time::Instant;

fn main() {
    println!("Starting Proof-of-Work Benchmark...");
    let iterations = 50_000;

    // Setup
    let (pk, sk) = ml_kem_1024::KG::try_keygen().unwrap();
    let data = b"Proof-of-Work Data Payload";

    let start = Instant::now();

    for i in 0..iterations {
        let encrypted = encrypt_for_sentinel(data, &pk);
        let decrypted = decrypt_from_client(&encrypted, &sk).expect("Decryption failed");
        assert_eq!(decrypted, data);

        if (i + 1) % 5000 == 0 {
            println!("Completed {}/{} cycles...", i + 1, iterations);
        }
    }

    let duration = start.elapsed();
    let avg_per_op = duration.as_secs_f64() / iterations as f64;
    let ops_per_sec = iterations as f64 / duration.as_secs_f64();

    let report = format!(
        "TersecPot Proof-of-Work Benchmark Report\n\
        ========================================\n\
        Date: {}\n\
        Total Iterations: {}\n\
        Total Time: {:.2?}\n\
        Average Time per Cycle: {:.6} s\n\
        Throughput: {:.2} ops/s\n\
        \n\
        System Status: READY for High-Load Operations.\n",
        chrono::Local::now().to_rfc2822(),
        iterations,
        duration,
        avg_per_op,
        ops_per_sec
    );

    let mut file =
        File::create("../../proof_of_work_report.txt").expect("Failed to create report file");
    file.write_all(report.as_bytes())
        .expect("Failed to write report");

    println!("\nBenchmark Complete!");
    println!("{}", report);
}
