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

        /// Role for signature (`DevOps`, `ComplianceManager`, `SecurityOfficer`)
        #[arg(long)]
        role: Option<String>,

        /// Private key file path (default: `postbox/private_key`)
        #[arg(long)]
        key: Option<String>,

        /// Public key file path for verification (default: `postbox/authorized_keys/client_key`)
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Generate a new keypair
    Keygen {
        /// Output path for private key (default: `postbox/private_key`)
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
                tracing::info!("Error: Must specify --partial, --append, or --submit");
                std::process::exit(1);
            }
        }
        Commands::Keygen { out } => {
            let postbox = postbox_path();
            ensure_postbox(&postbox)?;
            let key_path = out.unwrap_or_else(|| format!("{postbox}/private_key"));
            handle_keygen(&postbox, &key_path)?;
        }
    }

    Ok(())
}

fn ensure_postbox(postbox: &str) -> std::io::Result<()> {
    if !Path::new(postbox).exists() {
        fs::create_dir_all(postbox)?;
    }
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
fn handle_partial(
    postbox: &str,
    command: &str,
    signers: usize,
    output: Option<String>,
) -> std::io::Result<()> {
    tracing::info!("[CLIENT] Creating partial command for: {}", command);

    // Load KEM public key
    let kem_pk_path = format!("{postbox}/kem_public_key");
    let kem_pk = load_kem_public_key_wait(&kem_pk_path)?;

    // Load and increment sequence - RESERVING it now
    let seq_path = format!("{postbox}/.client_seq");
    let mut seq = load_sequence(&seq_path)?;
    seq = seq.saturating_add(1);

    // Write reserved sequence back immediately
    let mut priv_key_file = File::create(&seq_path)?;
    priv_key_file.write_all(&seq.to_le_bytes())?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| {
            tracing::error!("Time went backwards");
            Duration::from_secs(0)
        })
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

    tracing::info!("Partial command saved to: {}", output_file);
    tracing::info!("Required signatures: {}", signers);
    tracing::info!("Reserved Sequence: {}", seq);

    Ok(())
}

fn handle_append(
    postbox: &str,
    partial_file: &str,
    role_str: Option<String>,
    key_path: Option<String>,
    pubkey_path: Option<String>,
) -> std::io::Result<()> {
    tracing::info!("[CLIENT] Appending signature to: {}", partial_file);

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
    let key_file = key_path.unwrap_or_else(|| format!("{postbox}/private_key"));
    let signing_key = load_private_key(&key_file)?;

    // Sign
    let sig = sign_data(&signing_key, &partial.encrypted_payload);

    // Wipe key from memory (simplified)
    drop(signing_key);

    // Public key for verification
    let pubkey_file =
        pubkey_path.unwrap_or_else(|| format!("{postbox}/authorized_keys/client_key"));

    // Append
    partial = append_signature_to_partial(partial, sig, role, &pubkey_file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Save back
    save_partial_command(partial_file, &partial)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    tracing::info!(
        "Signature appended. Current signatures: {}/{}",
        partial.signatures.iter().filter(|s| s.is_some()).count(),
        partial.required_signers
    );

    if is_partial_complete(&partial) {
        tracing::info!("Command is now fully signed. Use --submit to submit.");
    }

    Ok(())
}

fn handle_submit(postbox: &str, signed_file: &str) -> std::io::Result<()> {
    tracing::info!("[CLIENT] Submitting signed command: {}", signed_file);

    // Load partial
    let partial = load_partial_command(signed_file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    if !is_partial_complete(&partial) {
        tracing::info!("Error: Command is not fully signed");
        std::process::exit(1);
    }

    // Convert to signed
    let signed_data = partial_to_signed(&partial)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Use Timestamp for unique filename to avoid ordering confusion
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| {
            tracing::error!("Time errors");
            Duration::from_millis(0)
        })
        .as_millis();

    // Write to postbox
    let filename = format!("{postbox}/cmd_{ts}.bin");
    let mut file = File::create(&filename)?;
    file.write_all(&signed_data)?;

    tracing::info!("Command submitted successfully to {}", filename);

    Ok(())
}

fn load_kem_public_key_wait(path: &str) -> std::io::Result<ml_kem_1024::EncapsKey> {
    loop {
        if let Ok(k) = load_kem_public_key(path) {
            return Ok(k);
        }
        tracing::info!("[CLIENT] Waiting for Sentinel Identity (KEM Key)...");
        thread::sleep(Duration::from_secs(2));
    }
}

fn load_sequence(seq_path: &str) -> std::io::Result<u64> {
    if Path::new(seq_path).exists() {
        let mut file = File::open(seq_path).map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut bytes = [0u8; 8];
        file.read_exact(&mut bytes)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(u64::from_le_bytes(bytes))
    } else {
        Ok(0)
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

#[allow(clippy::cognitive_complexity)]
fn prompt_role() -> std::io::Result<Role> {
    tracing::info!("Select role:");
    tracing::info!("1. DevOps");
    tracing::info!("2. ComplianceManager");
    tracing::info!("3. SecurityOfficer");

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
    tracing::info!("[CLIENT] Generating new ML-DSA-44 Keypair...");

    // Generate
    let (pk, sk) =
        ml_dsa_44::KG::try_keygen().map_err(|_| std::io::Error::other("Keygen failed"))?;

    // Save Private Key
    let mut private_key_file = File::create(sk_path)?;
    private_key_file.write_all(&sk.into_bytes())?;
    tracing::info!("Private Key saved to: {}", sk_path);

    // Save Public Key (to authorized_keys/client_key for test convenience)
    let auth_dir = format!("{postbox}/authorized_keys");
    fs::create_dir_all(&auth_dir)?;
    let pk_path = format!("{auth_dir}/client_key");

    // We need to save the PK in a way Sentinel can read. Sentinel loads all files in authorized_keys dir.
    // Sentinel expects raw bytes of the pubkey.
    let mut public_key_output = File::create(&pk_path)?;
    public_key_output.write_all(&pk.into_bytes())?;
    tracing::info!("Public Key saved to: {}", pk_path);

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
