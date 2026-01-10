//! Fuzzing target for Wolf Net Protocol

use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl_bolts::AsSlice;
use wolf_net::Message;
use rand::{Rng, thread_rng};

pub fn main() {
    println!("🐺 Starting Network Protocol Fuzzer...");
    let mut rng = thread_rng();

    let harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let data = target.as_slice();

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

    println!("✅ Network Fuzzing complete.");
}
