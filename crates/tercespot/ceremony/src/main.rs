//! Ceremony CLI tool.
//!
//! This crate provides a CLI tool for performing key generation ceremonies.

use clap::Parser;
use dialoguer::{Input, Select};
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen as SigningKeyGen, SerDes};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use shared::Role;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(
        long,
        help = "Path to test configuration file for non-interactive mode"
    )]
    test_config: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TestConfig {
    n: usize,
    roles: Vec<String>,
    usb_paths: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct AuthorizedKeys {
    ceremony_id: String,
    timestamp: u64,
    officers: Vec<OfficerKey>,
}

#[derive(Serialize, Deserialize)]
struct OfficerKey {
    role: Role,
    public_key_hex: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("🔐 TersecPot Four-Eyes Vault Key Ceremony Tool");

    let (n, roles, usb_paths) = if let Some(config_path) = args.test_config {
        println!("🤖 Running in TEST mode with config: {}", config_path);
        let config_str = fs::read_to_string(config_path)?;
        let config: TestConfig = serde_json::from_str(&config_str)?;
        let roles = config
            .roles
            .iter()
            .map(|r| match r.as_str() {
                "DevOps" => Role::DevOps,
                "ComplianceManager" => Role::ComplianceManager,
                "SecurityOfficer" => Role::SecurityOfficer,
                _ => panic!("Invalid role in test config"),
            })
            .collect();
        (config.n, roles, config.usb_paths)
    } else {
        println!("⚠️  Ensure this system is air-gapped (no network connections)!");
        println!();

        // Prompt for number of officers
        let n: usize = Input::new()
            .with_prompt("Enter number of officers (N)")
            .validate_with(|input: &String| -> Result<(), &str> {
                match input.parse::<usize>() {
                    Ok(num) if num > 0 => Ok(()),
                    _ => Err("Please enter a positive integer"),
                }
            })
            .interact_text()?
            .parse()
            .unwrap();

        // Prompt for roles for each officer
        let mut roles = Vec::new();
        let role_options = vec!["DevOps", "ComplianceManager", "SecurityOfficer"];
        for i in 1..=n {
            let selection = Select::new()
                .with_prompt(format!("Select role for Officer {}", i))
                .items(&role_options)
                .interact()?;
            let role = match selection {
                0 => Role::DevOps,
                1 => Role::ComplianceManager,
                2 => Role::SecurityOfficer,
                _ => unreachable!(),
            };
            roles.push(role);
        }

        // Prompt for USB mount points
        let mut usb_paths = Vec::new();
        for i in 1..=n {
            let path: String = Input::new()
                .with_prompt(format!(
                    "Enter mount point for Officer {} USB (e.g., /media/officer{})",
                    i, i
                ))
                .validate_with(|input: &String| -> Result<(), &str> {
                    if Path::new(input).exists() && Path::new(input).is_dir() {
                        // Check if writable by trying to create a temp file
                        let test_file = format!("{}/test_write", input);
                        match fs::write(&test_file, b"test") {
                            Ok(_) => {
                                fs::remove_file(&test_file).ok();
                                Ok(())
                            }
                            Err(_) => Err("USB path is not writable"),
                        }
                    } else {
                        Err("USB path does not exist or is not a directory")
                    }
                })
                .interact_text()?;
            usb_paths.push(path);
        }
        (n, roles, usb_paths)
    };

    // Generate ceremony ID
    let ceremony_id = format!(
        "ceremony_{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    );

    // Generate keys
    println!("\n🔑 Generating ML-DSA-44 keypairs...");
    let mut private_keys = Vec::new();
    let mut public_keys = Vec::new();
    for i in 0..n {
        let (pk, sk) =
            ml_dsa_44::KG::try_keygen().map_err(|e| anyhow::anyhow!("Keygen failed: {}", e))?;
        let pk_hex = hex::encode(pk.into_bytes());
        let sk_bytes = sk.into_bytes();
        private_keys.push(sk_bytes);
        public_keys.push((roles[i].clone(), pk_hex));
        println!("✓ Generated keypair for Officer {} ({:?})", i + 1, roles[i]);
    }

    // Write private keys to USBs
    println!("\n💾 Writing private keys to USB drives...");
    for i in 0..n {
        let usb_path = &usb_paths[i];
        let key_file = format!("{}/officer_key", usb_path);
        fs::write(&key_file, &private_keys[i])?;
        println!("✓ Private key written to {}", key_file);
    }

    // Create authorized_keys archive
    println!("\n📄 Creating authorized_keys archive...");
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let officers = public_keys
        .into_iter()
        .map(|(role, pk_hex)| OfficerKey {
            role,
            public_key_hex: pk_hex,
        })
        .collect();
    let authorized_keys = AuthorizedKeys {
        ceremony_id: ceremony_id.clone(),
        timestamp,
        officers,
    };
    let json = serde_json::to_string_pretty(&authorized_keys)?;
    let archive_hash = sha2::Sha256::digest(json.as_bytes());
    let archive_path = "authorized_keys.json";
    fs::write(archive_path, &json)?;
    println!("✓ Authorized keys archive created: {}", archive_path);

    // Compute and display hashes for integrity
    for i in 0..n {
        let hash = sha2::Sha256::digest(&private_keys[i]);
        println!(
            "🔒 Officer {} private key SHA256: {}",
            i + 1,
            hex::encode(hash)
        );
    }
    println!("🔒 Authorized keys SHA256: {}", hex::encode(archive_hash));

    // Wipe sensitive data
    println!("\n🧹 Wiping sensitive data from memory...");
    for sk in &mut private_keys {
        sk.zeroize();
    }
    private_keys.clear();

    println!("✅ Key ceremony completed successfully!");
    println!("📋 Ceremony ID: {}", ceremony_id);
    println!("🕒 Timestamp: {}", timestamp);
    println!("🔑 Keys generated: {}", n);
    println!("💡 Distribute USB drives to respective officers.");
    println!("💡 Store the authorized_keys.json securely for the vault setup.");

    Ok(())
}
