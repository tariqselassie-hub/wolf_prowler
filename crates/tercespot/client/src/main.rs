//! Submitter client entry point.
//!
//! This crate provides the submitter CLI for interacting with the Sentinel system.

use clap::{Parser, Subcommand};
use fips203::ml_kem_1024;
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes};
use shared::{encrypt_for_sentinel, load_kem_public_key, postbox_path, Role, SK_SIZE};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use submitter::{
    append_signature_to_partial, create_partial_command, is_partial_complete, load_partial_command,
    partial_to_signed, save_partial_command, sign_data,
};

#[derive(Parser)]
#[command(name = "tercespot")]
#[command(about = "TersecPot client for secure command submission")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Submit a command with multi-party signing
    Submit {
        /// Create initial partial file for command
        #[arg(long)]
        partial: Option<String>,

        /// Append signature to existing partial file
        #[arg(long)]
        append: Option<String>,

        /// Submit completed signed command
        #[arg(long)]
        submit: Option<String>,

        /// Output file for partial command (default: <command>.partial)
        #[arg(long)]
        output: Option<String>,

        /// Number of required signers (default: 2)
        #[arg(long, default_value = "2")]
        signers: usize,

        /// Role for signature (DevOps, ComplianceManager, SecurityOfficer)
        #[arg(long)]
        role: Option<String>,

        /// Private key file path (default: postbox/private_key)
        #[arg(long)]
        key: Option<String>,

        /// Public key file path for verification (default: postbox/authorized_keys/client_key)
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Generate a new keypair
    Keygen {
        /// Output path for private key (default: postbox/private_key)
        #[arg(long)]
        out: Option<String>,
    },
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Submit {
            partial,
            append,
            submit,
            output,
            signers,
            role,
            key,
            pubkey,
        } => {
            let postbox = postbox_path();
            ensure_postbox(&postbox)?;

            if let Some(command) = partial {
                handle_partial(&postbox, &command, signers, output)?;
            } else if let Some(partial_file) = append {
                handle_append(&postbox, &partial_file, role, key, pubkey)?;
            } else if let Some(signed_file) = submit {
                handle_submit(&postbox, &signed_file)?;
            } else {
                eprintln!("Error: Must specify --partial, --append, or --submit");
                std::process::exit(1);
            }
        }
        Commands::Keygen { out } => {
            let postbox = postbox_path();
            ensure_postbox(&postbox)?;
            let key_path = out.unwrap_or_else(|| format!("{}/private_key", postbox));
            handle_keygen(&postbox, &key_path)?;
        }
    }

    Ok(())
}

fn ensure_postbox(postbox: &str) -> std::io::Result<()> {
    if !Path::new(postbox).exists() {
        std::fs::create_dir_all(postbox)?;
    }
    Ok(())
}

fn handle_partial(
    postbox: &str,
    command: &str,
    signers: usize,
    output: Option<String>,
) -> std::io::Result<()> {
    println!("[CLIENT] Creating partial command for: {}", command);

    // Load KEM public key
    let kem_pk_path = format!("{}/kem_public_key", postbox);
    let kem_pk = load_kem_public_key_wait(&kem_pk_path)?;

    // Load and increment sequence - RESERVING it now
    let seq_path = format!("{}/.client_seq", postbox);
    let mut seq = load_sequence(&seq_path);
    seq += 1;

    // Write reserved sequence back immediately
    let mut f_seq = File::create(&seq_path)?;
    f_seq.write_all(&seq.to_le_bytes())?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    // Construct plaintext
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&seq.to_le_bytes());
    plaintext.extend_from_slice(&ts.to_le_bytes());
    plaintext.extend_from_slice(command.as_bytes());

    // Encrypt
    let encrypted_payload = encrypt_for_sentinel(&plaintext, &kem_pk);

    // Create partial
    let partial = create_partial_command(command.to_string(), encrypted_payload, signers)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Save
    let output_file = output.unwrap_or_else(|| format!("{}.partial", sanitize_filename(command)));
    save_partial_command(&output_file, &partial)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    println!("Partial command saved to: {}", output_file);
    println!("Required signatures: {}", signers);
    println!("Reserved Sequence: {}", seq);

    Ok(())
}

fn handle_append(
    postbox: &str,
    partial_file: &str,
    role_str: Option<String>,
    key_path: Option<String>,
    pubkey_path: Option<String>,
) -> std::io::Result<()> {
    println!("[CLIENT] Appending signature to: {}", partial_file);

    // Load partial
    let mut partial = load_partial_command(partial_file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Get role
    let role = if let Some(r) = role_str {
        parse_role(&r)?
    } else {
        prompt_role()?
    };

    // Load private key
    let key_file = key_path.unwrap_or_else(|| format!("{}/private_key", postbox));
    let signing_key = load_private_key(&key_file)?;

    // Sign
    let sig = sign_data(&signing_key, &partial.encrypted_payload);

    // Wipe key from memory (simplified)
    drop(signing_key);

    // Public key for verification
    let pubkey_file =
        pubkey_path.unwrap_or_else(|| format!("{}/authorized_keys/client_key", postbox));

    // Append
    partial = append_signature_to_partial(partial, sig, role, &pubkey_file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Save back
    save_partial_command(partial_file, &partial)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    println!(
        "Signature appended. Current signatures: {}/{}",
        partial.signatures.iter().filter(|s| s.is_some()).count(),
        partial.required_signers
    );

    if is_partial_complete(&partial) {
        println!("Command is now fully signed. Use --submit to submit.");
    }

    Ok(())
}

fn handle_submit(postbox: &str, signed_file: &str) -> std::io::Result<()> {
    println!("[CLIENT] Submitting signed command: {}", signed_file);

    // Load partial
    let partial = load_partial_command(signed_file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    if !is_partial_complete(&partial) {
        eprintln!("Error: Command is not fully signed");
        std::process::exit(1);
    }

    // Convert to signed
    let signed_data = partial_to_signed(&partial)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Use Timestamp for unique filename to avoid ordering confusion
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time errors")
        .as_millis();

    // Write to postbox
    let filename = format!("{}/cmd_{}.bin", postbox, ts);
    let mut file = File::create(&filename)?;
    file.write_all(&signed_data)?;

    println!("Command submitted successfully to {}", filename);

    Ok(())
}

fn load_kem_public_key_wait(path: &str) -> std::io::Result<ml_kem_1024::EncapsKey> {
    loop {
        match load_kem_public_key(path) {
            Ok(k) => return Ok(k),
            Err(_) => {
                println!("[CLIENT] Waiting for Sentinel Identity (KEM Key)...");
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn load_sequence(seq_path: &str) -> u64 {
    if Path::new(seq_path).exists() {
        let mut file = File::open(seq_path).unwrap();
        let mut bytes = [0u8; 8];
        file.read_exact(&mut bytes).unwrap();
        u64::from_le_bytes(bytes)
    } else {
        0
    }
}

fn load_private_key(path: &str) -> std::io::Result<ml_dsa_44::PrivateKey> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; SK_SIZE];
    file.read_exact(&mut bytes)?;
    ml_dsa_44::PrivateKey::try_from_bytes(bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid private key"))
}

fn parse_role(role_str: &str) -> std::io::Result<Role> {
    match role_str {
        "DevOps" => Ok(Role::DevOps),
        "ComplianceManager" => Ok(Role::ComplianceManager),
        "SecurityOfficer" => Ok(Role::SecurityOfficer),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid role",
        )),
    }
}

fn prompt_role() -> std::io::Result<Role> {
    println!("Select role:");
    println!("1. DevOps");
    println!("2. ComplianceManager");
    println!("3. SecurityOfficer");

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice: u32 = input
        .trim()
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid choice"))?;

    match choice {
        1 => Ok(Role::DevOps),
        2 => Ok(Role::ComplianceManager),
        3 => Ok(Role::SecurityOfficer),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid choice",
        )),
    }
}

fn handle_keygen(postbox: &str, sk_path: &str) -> std::io::Result<()> {
    println!("[CLIENT] Generating new ML-DSA-44 Keypair...");

    // Generate
    let (pk, sk) = ml_dsa_44::KG::try_keygen()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Keygen failed"))?;

    // Save Private Key
    let mut f_sk = File::create(sk_path)?;
    f_sk.write_all(&sk.into_bytes())?;
    println!("Private Key saved to: {}", sk_path);

    // Save Public Key (to authorized_keys/client_key for test convenience)
    let auth_dir = format!("{}/authorized_keys", postbox);
    fs::create_dir_all(&auth_dir)?;
    let pk_path = format!("{}/client_key", auth_dir);

    // We need to save the PK in a way Sentinel can read. Sentinel loads all files in authorized_keys dir.
    // Sentinel expects raw bytes of the pubkey.
    let mut f_pk = File::create(&pk_path)?;
    f_pk.write_all(&pk.into_bytes())?;
    println!("Public Key saved to: {}", pk_path);

    Ok(())
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
