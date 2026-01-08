use anyhow::Result;
use lock_prowler::algorithms::{NonceReuseAlgorithm, WeakRsaAlgorithm};
use lock_prowler::crypto::AlgorithmRunner;
use lock_prowler::metadata;
use std::env;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    println!("--- Lock Prowler: BitLocker Recovery Assistant ---");

    if args.len() < 2 {
        println!("Usage: lock_prowler <image_path>");
        return Ok(());
    }

    let image_path = &args[1];
    println!("Analyzing image: {}", image_path);

    let data = fs::read(image_path)?;

    match metadata::BitLockerMetadata::parse(&data) {
        Ok(meta) => {
            println!("\n[+] Found BitLocker Metadata!");
            println!("    Version: {:X}", meta.header.version);
            println!("    Metadata Size: {} bytes", meta.header.metadata_size);
            println!(
                "    Last Entry Offset: 0x{:X}",
                meta.header.last_entry_offset
            );

            println!("\n[+] Metadata Entries Found: {}", meta.entries.len());
            for (i, entry) in meta.entries.iter().enumerate() {
                println!(
                    "    Entry #{} - Type: {:?}, Size: {} bytes",
                    i + 1,
                    entry.entry_type,
                    entry.size
                );
            }

            println!("\n[+] Key Protectors Identified: {}", meta.protectors.len());
            for (i, protector) in meta.protectors.iter().enumerate() {
                println!(
                    "    Protector #{} - Type: {:?}, ID: {}",
                    i + 1,
                    protector.p_type,
                    hex::encode(protector.id)
                );
            }

            // Initialize and run recovery algorithms
            let mut runner = AlgorithmRunner::new();
            runner.register(Box::new(NonceReuseAlgorithm));
            runner.register(Box::new(WeakRsaAlgorithm));

            runner.run_all(&meta);

            // Persist session to WolfDb
            println!("\n[+] Persisting Session to WolfDb...");
            let mut store = lock_prowler::storage::WolfStore::new("wolf.db").await?;

            if !store.is_initialized() {
                println!("    Initializing new secure storage...");
                let password = dialoguer::Password::new()
                    .with_prompt("Set Master Password")
                    .with_confirmation("Confirm Password", "Passwords do not match")
                    .interact()?;
                store.initialize(&password).await?;
            } else {
                let password = dialoguer::Password::new()
                    .with_prompt("Unlock WolfDb")
                    .interact()?;
                store.unlock(&password).await?;
            }

            let mut session_data = std::collections::HashMap::new();
            session_data.insert("image_path".to_string(), image_path.to_string());
            session_data.insert("meta_version".to_string(), format!("{}", meta.header.version));
            session_data.insert("protector_count".to_string(), format!("{}", meta.protectors.len()));
            
            let session_id = format!("session_{}", uuid::Uuid::new_v4());
            store.save_session(&session_id, session_data).await?;
        }
        Err(e) => {
            println!("Error parsing metadata: {}", e);
        }
    }

    Ok(())
}
