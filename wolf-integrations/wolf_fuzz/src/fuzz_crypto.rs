//! Fuzzing target for Wolf Den Cryptography

use rand::{thread_rng, Rng};
use wolf_den::{CryptoEngine, SecurityLevel};

/// Main entry point for the crypto fuzzer.
pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iterations = if args.len() > 1 {
        args[1].parse::<usize>().unwrap_or(1000)
    } else {
        1000
    };

    println!(
        "🐺 Starting Crypto Fuzzer running for {} iterations...",
        iterations
    );
    let mut rng = thread_rng();

    let harness = |data: &[u8]| {
        // 1. Fuzz Hashing
        if let Ok(engine) = CryptoEngine::new(SecurityLevel::Standard) {
            let _ = engine.hash(data);

            // 2. Fuzz MAC
            let _ = engine.compute_mac(data);

            // 3. Fuzz Key Derivation (using parts of input)
            if data.len() >= 4 {
                let salt = &data[0..4];
                let _ = engine.derive_key(data, salt, 32);
            }
        }
    };

    for i in 0..iterations {
        let len = rng.gen_range(1..1024);
        let mut bytes = vec![0u8; len];
        rng.fill(&mut bytes[..]);

        harness(&bytes);

        if i % 100 == 0 {
            println!("  Fuzzed {} iterations...", i);
        }
    }

    println!("✅ Crypto Fuzzing complete.");
}
