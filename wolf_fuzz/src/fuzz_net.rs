//! Fuzzing target for Wolf Net Protocol

use rand::{thread_rng, Rng};
use wolf_net::Message;

/// Main entry point for the network stack fuzzer.
pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iterations = if args.len() > 1 {
        args[1].parse::<usize>().unwrap_or(1000)
    } else {
        1000
    };

    println!(
        "🐺 Starting Network Protocol Fuzzer running for {} iterations...",
        iterations
    );
    let mut rng = thread_rng();

    let harness = |data: &[u8]| {
        // Target: Message Deserialization
        if let Ok(msg) = serde_json::from_slice::<Message>(data) {
            let _ = msg.id;
            let _ = msg.version;
            // Fuzz inner message type
            match msg.message_type {
                wolf_net::message::MessageType::Chat { content } => {
                    let _ = content;
                }
                wolf_net::message::MessageType::Data { data, .. } => {
                    let _ = data;
                }
                _ => {}
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

    println!("✅ Network Fuzzing complete.");
}
