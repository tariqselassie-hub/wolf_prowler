//! Fuzzing target for Wolf Den Cryptography

use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl_bolts::AsSlice;
use wolf_den::{CryptoEngine, SecurityLevel};
use rand::{Rng, thread_rng};

pub fn main() {
    println!("🐺 Starting Crypto Fuzzer...");
    let mut rng = thread_rng();

    let harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let data = target.as_slice();

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

    for i in 0..1000 {
        let len = rng.gen_range(1..1024);
        let mut bytes = vec![0u8; len];
        rng.fill(&mut bytes[..]);
        
        let input = BytesInput::new(bytes);
        harness(&input);
        
        if i % 100 == 0 {
            println!("  Fuzzed {} iterations...", i);
        }
    }
    
    println!("✅ Crypto Fuzzing complete.");
}
