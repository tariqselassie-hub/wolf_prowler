//! Fuzzing target for Wolf Security Event Validation

use rand::{thread_rng, Rng};
use wolfsec::{SecurityEvent, SecurityEventType, SecuritySeverity};

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iterations = if args.len() > 1 {
        args[1].parse::<usize>().unwrap_or(1000)
    } else {
        1000
    };

    println!(
        "🐺 Starting Security Event Fuzzer running for {} iterations...",
        iterations
    );
    let mut rng = thread_rng();

    let harness = |data: &[u8]| {
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
                desc.to_string(),
            );
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

    println!("✅ Security Fuzzing complete.");
}
