//! Fuzzing target for Wolf Security Event Validation

use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl_bolts::AsSlice;
use wolfsec::{SecurityEvent, SecurityEventType, SecuritySeverity};
use rand::{Rng, thread_rng};

pub fn main() {
    println!("🐺 Starting Security Event Fuzzer...");
    let mut rng = thread_rng();

    let harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let data = target.as_slice();

        // 1. Fuzz Event Deserialization
        if let Ok(event) = serde_json::from_slice::<SecurityEvent>(data) {
            let _ = event.severity;
            let _ = event.description;
        }

        // 2. Fuzz Event Construction from raw bytes
        if let Ok(desc) = std::str::from_utf8(data) {
            let _ = SecurityEvent::new(
                SecurityEventType::SuspiciousActivity,
                SecuritySeverity::High,
                desc.to_string()
            );
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

    println!("✅ Security Fuzzing complete.");
}