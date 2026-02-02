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

#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    tracing::info!("🔐 TersecPot Four-Eyes Vault Key Ceremony Tool");

    let (n, roles, usb_paths) = if let Some(config_path) = args.test_config {
        tracing::info!("🤖 Running in TEST mode with config: {}", config_path);
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
        tracing::info!("⚠️  Ensure this system is air-gapped (no network connections)!");
        tracing::info!("---");

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
            .parse()?;

        // Prompt for roles for each officer
        let mut roles = Vec::new();
        let role_options = vec!["DevOps", "ComplianceManager", "SecurityOfficer"];
        for i in 1..=n {
            let selection = Select::new()
                .with_prompt(format!("Select role for Officer {i}"))
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
                    "Enter mount point for Officer {i} USB (e.g., /media/officer{i})"
                ))
                .validate_with(|input: &String| -> Result<(), &str> {
                    if Path::new(input).exists() && Path::new(input).is_dir() {
                        // Check if writable by trying to create a temp file
                        let test_file = format!("{input}/test_write");
                        match fs::write(&test_file, b"test") {
                            Ok(()) => {
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
    tracing::info!("\n🔑 Generating ML-DSA-44 keypairs...");
    let mut private_keys = Vec::new();
    let mut public_keys = Vec::new();
    for (i, role) in roles.iter().enumerate().take(n) {
        let (pk, sk) =
            ml_dsa_44::KG::try_keygen().map_err(|e| anyhow::anyhow!("Keygen failed: {e}"))?;
        let pk_hex = hex::encode(pk.into_bytes());
        let sk_bytes = sk.into_bytes();
        private_keys.push(sk_bytes);
        public_keys.push((role.clone(), pk_hex));
        tracing::info!(
            "✓ Generated keypair for Officer {} ({:?})",
            i.saturating_add(1),
            role
        );
    }

    // Write private keys to USBs
    tracing::info!("\n💾 Writing private keys to USB drives...");
    for (i, usb_path) in usb_paths.iter().enumerate().take(n) {
        let key_file = format!("{usb_path}/officer_key");
        if let Some(sk) = private_keys.get(i) {
            fs::write(&key_file, sk)?;
            tracing::info!("✓ Private key written to {}", key_file);
        }
    }

    // Create authorized_keys archive
    tracing::info!("\n📄 Creating authorized_keys archive...");
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
    tracing::info!("✓ Authorized keys archive created: {}", archive_path);

    // Compute and display hashes for integrity
    for (i, sk) in private_keys.iter().enumerate().take(n) {
        let hash = sha2::Sha256::digest(sk);
        tracing::info!(
            "🔒 Officer {} private key SHA256: {}",
            i.saturating_add(1),
            hex::encode(hash)
        );
    }
    tracing::info!("🔒 Authorized keys SHA256: {}", hex::encode(archive_hash));

    // Wipe sensitive data
    tracing::info!("\n🧹 Wiping sensitive data from memory...");
    for sk in &mut private_keys {
        sk.zeroize();
    }
    private_keys.clear();

    tracing::info!("✅ Key ceremony completed successfully!");
    tracing::info!("📋 Ceremony ID: {}", ceremony_id);
    tracing::info!("🕒 Timestamp: {}", timestamp);
    tracing::info!("🔑 Keys generated: {}", n);
    tracing::info!("💡 Distribute USB drives to respective officers.");
    tracing::info!("💡 Store the authorized_keys.json securely for the vault setup.");

    Ok(())
}
