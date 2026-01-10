//! Sentinel Daemon Library
//!
//! This library provides the core functionality for the Sentinel daemon,
//! which implements multi-party authorization for privileged commands using
//! post-quantum cryptography (ML-DSA-44 signatures and ML-KEM-1024 encryption).
//!
//! Key features:
//! - Multi-signature verification with configurable thresholds
//! - Policy-based authorization with time and geo-fencing
//! - Privacy-preserving audit logging
//! - Pulse-based authentication for physical presence verification

use fips204::ml_dsa_44; // Using specific parameter set
use fips204::traits::{SerDes, Verifier};
use serde::{Deserialize, Serialize};
use shared::{
    parse_and_evaluate, parse_command_metadata, CommandMetadata, Policy, PolicyConfig, Role,
    SEQ_SIZE, SIG_SIZE, TS_SIZE,
};
use std::collections::{HashMap, HashSet};
use std::io::BufRead;
/// File system monitoring for command files
pub mod file_watcher;

// Add imports needed for the daemon logic
use fips203::ml_kem_1024;
use fips203::traits::{KeyGen, SerDes as KemSerDes};
use privacy::{AuditStatus, PrivacyAuditLogger, PrivacyConfig, PrivacyValidator};

use shared::{decrypt_from_client, load_policy_config, postbox_path, KEM_SK_SIZE};
use std::{fs, process::Command, thread, time::Duration};
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::sleep;

/// Pulse authentication methods for physical presence verification
pub mod pulse;
use pulse::PulseMethod;

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

#[derive(Clone)]
struct PendingSignature {
    key_hex: String,
    #[allow(dead_code)]
    signature: [u8; shared::SIG_SIZE],
    #[allow(dead_code)]
    timestamp: u64,
}

#[derive(Clone)]
struct PendingCommand {
    #[allow(dead_code)]
    seq: u64, // Keep as u64
    #[allow(dead_code)]
    ts: u64,
    cmd: String,
    #[allow(dead_code)]
    ciphertext: Vec<u8>,
    signatures: Vec<PendingSignature>,
}

/// Loads authorized keys and role mappings from a JSON file
///
/// # Arguments
/// * `path` - Path to the `authorized_keys.json` file
///
/// # Returns
/// A tuple of (public keys, role mappings) where role mappings map key hex to role names
pub fn load_authorized_keys<P: AsRef<std::path::Path>>(
    path: P,
) -> std::io::Result<(Vec<ml_dsa_44::PublicKey>, HashMap<String, Vec<String>>)> {
    let content = std::fs::read_to_string(path)?;
    let auth_keys: AuthorizedKeys = serde_json::from_str(&content)?;
    let mut keys = Vec::new();
    let mut role_mappings = HashMap::new();
    for officer in auth_keys.officers {
        let pk_bytes = hex::decode(&officer.public_key_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let pk_array: [u8; shared::PK_SIZE] = pk_bytes.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key length")
        })?;
        let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_array).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid public key")
        })?;
        keys.push(pk);
        role_mappings.insert(officer.public_key_hex, vec![format!("{:?}", officer.role)]);
    }
    Ok((keys, role_mappings))
}

/// Parses the wire format: [Count] || [Sig1] || ... || [Body]
#[must_use] 
pub fn parse_wire_format(data: &[u8]) -> Option<(Vec<[u8; SIG_SIZE]>, Vec<u8>)> {
    if data.is_empty() {
        return None;
    }
    let count = data[0] as usize;
    let sigs_len = count * SIG_SIZE;

    if data.len() < 1 + sigs_len {
        return None;
    }

    let mut signatures = Vec::with_capacity(count);
    let mut offset = 1;

    for _ in 0..count {
        let sig_bytes = &data[offset..offset + SIG_SIZE];
        let sig_array: [u8; SIG_SIZE] = sig_bytes.try_into().ok()?;
        signatures.push(sig_array);
        offset += SIG_SIZE;
    }

    let body = data[offset..].to_vec();
    Some((signatures, body))
}

/// Verifies an ML-DSA-44 signature against the given body and public key
///
/// # Arguments
/// * `body` - The message body to verify
/// * `sig` - The signature bytes
/// * `public_key` - The public key to use for verification
///
/// # Returns
/// true if the signature is valid, false otherwise
#[must_use] 
pub fn verify_signature(
    body: &[u8],
    sig: &[u8; SIG_SIZE],
    public_key: &ml_dsa_44::PublicKey,
) -> bool {
    public_key.verify(body, sig, b"tersec")
}

/// Parses the plaintext into (Seq, Ts, Command).
#[must_use] 
pub fn parse_plaintext(data: &[u8]) -> Option<(u64, u64, String)> {
    if data.len() < SEQ_SIZE + TS_SIZE {
        return None;
    }
    let (seq_bytes, rest) = data.split_at(SEQ_SIZE);
    let (ts_bytes, cmd_bytes) = rest.split_at(TS_SIZE);

    let seq = u64::from_le_bytes(seq_bytes.try_into().ok()?);
    let ts = u64::from_le_bytes(ts_bytes.try_into().ok()?);
    let cmd = String::from_utf8_lossy(cmd_bytes).to_string();

    Some((seq, ts, cmd))
}

/// Checks for a pulse token in the provided reader.
pub fn check_pulse<R: BufRead>(reader: &mut R, token: &str, timeout_secs: u64) -> bool {
    // Poll loop: timeout_secs * 10 iterations (100ms sleep)
    for _ in 0..(timeout_secs * 10) {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF, wait and retry
                thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                if line.contains(token) {
                    return true;
                }
            }
            Err(_) => break,
        }
    }
    false
}

use chrono::{Datelike, Local, Timelike};
use shared::{PulseMetadata, TimeWindow};

/// Evaluates if a command is authorized based on policies and verified signatures
pub fn evaluate_policies(
    cmd: &str,
    verified_keys: &[String], // Public key hexes that signed
    policy_config: &PolicyConfig,
    pulse_metadata: Option<&PulseMetadata>,
) -> Result<(), String> {
    let metadata = parse_command_metadata(cmd).unwrap_or(CommandMetadata {
        role: "default".to_string(),
        operation: "execute".to_string(),
        resource: "system".to_string(),
        parameters: HashMap::new(),
    });

    // Find applicable policies
    let applicable_policies: Vec<&Policy> = policy_config
        .policies
        .iter()
        .filter(|p| {
            (p.roles.contains(&"*".to_string()) || p.roles.contains(&metadata.role))
                && (p.operations.contains(&"*".to_string())
                    || p.operations.contains(&metadata.operation))
                && (p.resources.contains(&"*".to_string())
                    || p.resources.contains(&metadata.resource))
        })
        .collect();

    if applicable_policies.is_empty() {
        return Err("No applicable policy found".to_string());
    }

    // Check each applicable policy
    for policy in applicable_policies {
        // Check threshold
        if !check_policy_threshold(policy, verified_keys, policy_config)? {
            return Err(format!("Policy '{}' threshold not met", policy.name));
        }

        // Check approval expression if present
        if let Some(ref expr) = policy.approval_expression {
            let mut roles_present = HashSet::new();
            for key_hex in verified_keys {
                if let Some(roles) = policy_config.role_mappings.get(key_hex) {
                    for role_str in roles {
                        match role_str.as_str() {
                            "DevOps" => {
                                roles_present.insert(Role::DevOps);
                            }
                            "ComplianceManager" => {
                                roles_present.insert(Role::ComplianceManager);
                            }
                            "SecurityOfficer" => {
                                roles_present.insert(Role::SecurityOfficer);
                            }
                            _ => {}
                        }
                    }
                }
            }
            if !parse_and_evaluate(expr, &roles_present)? {
                return Err(format!(
                    "Policy '{}' approval expression not satisfied",
                    policy.name
                ));
            }
        }

        if !check_policy_conditions(policy, &metadata, pulse_metadata)? {
            return Err(format!("Policy '{}' conditions not satisfied", policy.name));
        }
    }

    Ok(())
}

fn check_policy_threshold(
    policy: &Policy,
    verified_keys: &[String],
    policy_config: &PolicyConfig,
) -> Result<bool, String> {
    // Count how many verified keys have the required roles
    let mut authorized_count = 0;
    for key_hex in verified_keys {
        if let Some(roles) = policy_config.role_mappings.get(key_hex) {
            if roles.iter().any(|r| policy.roles.contains(r)) {
                authorized_count += 1;
            }
        }
    }

    Ok(authorized_count >= policy.threshold)
}

fn check_policy_conditions(
    policy: &Policy,
    _metadata: &CommandMetadata,
    pulse_metadata: Option<&PulseMetadata>,
) -> Result<bool, String> {
    use shared::PolicyCondition;

    for condition in &policy.conditions {
        match condition {
            PolicyCondition::RequireApproval(_role) => {
                // This would need additional context about approvals
                // For now, assume satisfied
            }
            PolicyCondition::MaxFrequency(_) => {
                // Would need to track operation frequency
                // For now, assume satisfied
            }
            PolicyCondition::IpWhitelist(_) => {
                // Would need client IP context
                // For now, assume satisfied
            }
            PolicyCondition::TimeBound(window) => {
                if !check_time_window(window) {
                    return Err(format!(
                        "Time window not met. Allowed: {}-{} on {:?}",
                        window.start_time, window.end_time, window.days
                    ));
                }
            }
            PolicyCondition::GeoBound(fence) => {
                if let Some(meta) = pulse_metadata {
                    if !fence.allowed_regions.contains(&meta.location) {
                        return Err(format!(
                            "GeoFence failed. Location '{}' not in allowed regions {:?}",
                            meta.location, fence.allowed_regions
                        ));
                    }
                } else {
                    // Pre-check mode: We implicitly pass here because we expect
                    // the caller to call us AGAIN with metadata before execution.
                    // This creates a potential risk if caller logic is flawed,
                    // but it's required for the "Wait for Pulse" flow.
                }
            }
        }
    }

    Ok(true)
}

fn check_time_window(window: &TimeWindow) -> bool {
    let now = Local::now();
    let current_weekday = now.weekday().to_string().to_lowercase(); // e.g. "mon", "tue", "sat"

    // 1. Check Day
    // Chrono returns "Mon", "Tue" etc. We allow full names "Monday", "Tuesday" by checking starts_with
    let day_allowed = window
        .days
        .iter()
        .any(|d| d.to_lowercase().starts_with(&current_weekday));
    if !day_allowed {
        return false;
    }

    // 2. Check Time
    // Parse "HH:MM"
    fn parse_hhmm(s: &str) -> Option<(u32, u32)> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        let h = parts[0].parse().ok()?;
        let m = parts[1].parse().ok()?;
        Some((h, m))
    }

    let (start_h, start_m) = match parse_hhmm(&window.start_time) {
        Some(t) => t,
        None => return false,
    };
    let (end_h, end_m) = match parse_hhmm(&window.end_time) {
        Some(t) => t,
        None => return false,
    };

    let now_h = now.hour();
    let now_m = now.minute();
    let now_mins = now_h * 60 + now_m;
    let start_mins = start_h * 60 + start_m;
    let end_mins = end_h * 60 + end_m;

    now_mins >= start_mins && now_mins <= end_mins
}

// =========================================================================
//  MAIN DAEMON LOGIC EXPOSED AS LIBRARY
// =========================================================================

/// Starts the Sentinel daemon which monitors for signed command files and executes authorized commands
///
/// The daemon watches the postbox directory for command files signed with ML-DSA-44 keys,
/// validates them against policies, and executes approved commands as root.
///
/// # Returns
/// An IO result indicating success or failure
pub async fn start_sentinel() -> std::io::Result<()> {
    let postbox = postbox_path();
    let auth_keys_path = format!("{postbox}/authorized_keys.json");
    let kem_sk_path = format!("{postbox}/kem_private_key");
    let kem_pk_path = format!("{postbox}/kem_public_key");
    let policies_path = format!("{postbox}/policies.toml");
    let audit_log_path = format!("{postbox}/audit_logs");
    let audit_key_path = format!("{postbox}/audit_key.pub");

    // Ensure Audit Key exists (In real world, Auditor provides this. We generate for demo)
    if !std::path::Path::new(&audit_key_path).exists() {
        println!("[SENTINEL] Generating new Auditor Identity (Demo Mode)...");
        let (pk, sk) = ml_kem_1024::KG::try_keygen().expect("Audit Keygen failed");

        // Save Public Key for Daemon to use
        fs::write(&audit_key_path, pk.into_bytes())?;

        // Save Private Key for verification scripts (In real world, this stays with Auditor)
        let audit_sk_path = format!("{postbox}/audit_key.priv");
        fs::write(&audit_sk_path, sk.into_bytes())?;
        println!("[SENTINEL] Auditor Keys saved to {postbox}");
    }

    // Initialize privacy audit logger
    let privacy_config = PrivacyConfig {
        syslog_endpoint: audit_log_path.clone(),
        alert_channels: vec![
            "sms".to_string(),
            "email".to_string(),
            "pagerduty".to_string(),
        ],
        pii_patterns: vec![
            r"\b\d{3}-\d{2}-\d{4}\b".to_string(), // SSN pattern
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b".to_string(), // Email pattern
        ],
        privacy_mode: true,
        audit_key_path: audit_key_path.clone(),
    };

    let privacy_logger = PrivacyAuditLogger::new(privacy_config.clone())?; // Clone config for validator access if needed, or re-use patterns

    // Initialize Privacy Validator
    let privacy_validator = PrivacyValidator::new(&privacy_config.pii_patterns)?;

    // Determine Threshold M
    let m_str = std::env::var("TERSEC_M").unwrap_or_else(|_| "1".to_string());
    let threshold_m: usize = m_str.parse().unwrap_or(1);

    // Load Authorized Keys and Roles
    let (mut authorized_keys, mut role_mappings) = if std::path::Path::new(&auth_keys_path).exists()
    {
        match load_authorized_keys(&auth_keys_path) {
            Ok((keys, mappings)) => {
                println!(
                    "[SENTINEL] Loaded {} authorized keys with roles",
                    keys.len()
                );
                (keys, mappings)
            }
            Err(e) => {
                println!("[SENTINEL] Warning: Failed to load authorized keys: {e}");
                (Vec::new(), HashMap::new())
            }
        }
    } else {
        println!("[SENTINEL] No authorized_keys.json found, waiting...");
        (Vec::new(), HashMap::new())
    };

    // Load Policy Configuration
    let mut policy_config = if std::path::Path::new(&policies_path).exists() {
        match load_policy_config(&policies_path) {
            Ok(mut config) => {
                // Merge role mappings from authorized_keys.json
                for (key, roles) in role_mappings {
                    config.role_mappings.insert(key, roles);
                }
                println!("[SENTINEL] Loaded {} policies", config.policies.len());
                Some(config)
            }
            Err(e) => {
                println!("[SENTINEL] Warning: Failed to load policies: {e}");
                None
            }
        }
    } else {
        println!("[SENTINEL] No policy file found, using legacy mode");
        None
    };

    // 1. Load Authorized Signing Keys (Poll until at least 1? or M?)
    println!(
        "[SENTINEL] Threshold: {threshold_m} Signature(s) Required"
    );

    // Map to hold pending commands: seq -> PendingCommand
    let mut pending_commands: HashMap<u64, PendingCommand> = HashMap::new();

    // Create key_hexes for lookup
    let mut key_hexes: Vec<String> = authorized_keys
        .iter()
        .map(|pk| hex::encode(pk.clone().into_bytes()))
        .collect();

    // 2. Load or Generate Daemon's KEM Private Key
    let kem_sk = if std::path::Path::new(&kem_sk_path).exists() {
        use std::io::Read;
        let mut file = fs::File::open(&kem_sk_path)?;
        let mut bytes = [0u8; KEM_SK_SIZE];
        file.read_exact(&mut bytes)?;
        ml_kem_1024::DecapsKey::try_from_bytes(bytes).expect("Invalid KEM private key")
    } else {
        println!("[SENTINEL] Generating new KEM Identity...");
        let (pk, sk) = ml_kem_1024::KG::try_keygen().expect("KEM Keygen failed");

        use std::io::Write;
        let mut f_sk = fs::File::create(&kem_sk_path)?;
        f_sk.write_all(&sk.clone().into_bytes())?;

        let mut f_pk = fs::File::create(&kem_pk_path)?;
        f_pk.write_all(&pk.into_bytes())?;

        println!("[SENTINEL] KEM Keys saved to {postbox}");
        sk
    };

    // Determine pulse method at startup
    let pulse_method = PulseMethod::from_env();
    let state_path = format!("{postbox}/.sentinel_state");

    println!(
        "[SENTINEL] Protecting root. Algorithm: Sig(ML-DSA-44) + Enc(ML-KEM-1024 + AES-256-GCM)"
    );

    // Set up file watcher
    let (event_sender, mut event_receiver) = unbounded_channel();

    let file_watcher_config = file_watcher::WatchConfig {
        watch_dir: postbox.clone(),
        file_pattern: Some("cmd_".to_string()),
        recursive: false,
        debounce_delay_ms: 100,
    };

    let watcher = file_watcher::FileWatcher::new(file_watcher_config, event_sender);

    // Start the file watcher
    if let Err(e) = watcher.start() {
        eprintln!("[SENTINEL] Failed to start file watcher: {e}");
        return Err(std::io::Error::other(e));
    }

    // Main event loop
    loop {
        // Reload authorized keys if file changed (simple check)
        if std::path::Path::new(&auth_keys_path).exists() && authorized_keys.is_empty() {
            match load_authorized_keys(&auth_keys_path) {
                Ok((keys, mappings)) => {
                    authorized_keys = keys;
                    role_mappings = mappings;
                    key_hexes = authorized_keys
                        .iter()
                        .map(|pk| hex::encode(pk.clone().into_bytes()))
                        .collect();
                    if let Some(ref mut config) = policy_config {
                        config.role_mappings = role_mappings.clone();
                    }
                    println!(
                        "[SENTINEL] Reloaded {} authorized keys",
                        authorized_keys.len()
                    );
                }
                Err(e) => {
                    println!("[SENTINEL] Failed to reload keys: {e}");
                }
            }
        }

       // Allow running even without auth keys initially, but warn
       // (Removed the block loop for better embedding experience)
        // if authorized_keys.is_empty() {
        //     sleep(Duration::from_secs(1)).await;
        //     continue;
        // }

        // Load Last Seen Sequence
        let mut last_seq = 0u64;
        if let Ok(mut file) = fs::File::open(&state_path) {
            use std::io::Read;
            let mut bytes = [0u8; 8];
            if file.read_exact(&mut bytes).is_ok() {
                last_seq = u64::from_le_bytes(bytes);
            }
        }

        // Process file system events
        // Use try_recv loop to process current batch, then sleep small amount
        while let Ok(event) = event_receiver.try_recv() {
            match event {
                file_watcher::FileSystemEvent::Created(file_name) => {
                    let file_path = format!("{postbox}/{file_name}");
                    process_file(
                        &file_path,
                        &kem_sk,
                        &authorized_keys,
                        &key_hexes,
                        &mut pending_commands,
                        &mut last_seq,
                        &state_path,
                        &policy_config,
                        &privacy_logger,
                        &privacy_validator,
                        &pulse_method,
                        threshold_m,
                    )
                    .await;
                }
                file_watcher::FileSystemEvent::Modified(file_name) => {
                    let file_path = format!("{postbox}/{file_name}");
                    process_file(
                        &file_path,
                        &kem_sk,
                        &authorized_keys,
                        &key_hexes,
                        &mut pending_commands,
                        &mut last_seq,
                        &state_path,
                        &policy_config,
                        &privacy_logger,
                        &privacy_validator,
                        &pulse_method,
                        threshold_m,
                    )
                    .await;
                }
                file_watcher::FileSystemEvent::Deleted(file_name) => {
                    println!("[SENTINEL] File deleted: {file_name}");
                }
                file_watcher::FileSystemEvent::Error(error_msg) => {
                    eprintln!("[SENTINEL] File watcher error: {error_msg}");
                }
            }
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn process_file(
    file_path: &str,
    kem_sk: &ml_kem_1024::DecapsKey,
    authorized_keys: &[fips204::ml_dsa_44::PublicKey],
    key_hexes: &[String],
    pending_commands: &mut std::collections::HashMap<u64, PendingCommand>,
    last_seq: &mut u64,
    state_path: &str,
    policy_config: &Option<PolicyConfig>,
    privacy_logger: &PrivacyAuditLogger,
    privacy_validator: &PrivacyValidator,
    pulse_method: &PulseMethod,
    threshold_m: usize,
) {
    let data = match fs::read(file_path) {
        Ok(d) => d,
        Err(_) => return,
    };

    // 1. Parse Wire Format -> Get Signatures & Ciphertext
    if let Some((signatures, ciphertext)) = parse_wire_format(&data) {
        if signatures.is_empty() {
            println!("[DROP] No signatures found");
            let _ = fs::remove_file(file_path);
            return;
        }

        // 2. Verify signatures and find which keys signed
        let mut verified_sigs = Vec::new();
        for sig in &signatures {
            for (idx, pk) in authorized_keys.iter().enumerate() {
                if verify_signature(&ciphertext, sig, pk) {
                    let key_hex = key_hexes[idx].clone();
                    // Avoid duplicates in this batch
                    if !verified_sigs.iter().any(|(k, _)| *k == key_hex) {
                        verified_sigs.push((key_hex, *sig));
                    }
                    break;
                }
            }
        }

        if verified_sigs.is_empty() {
            println!("[DROP] No valid signatures found in package");
        } else {
            println!(
                "[AUTH] Verified {} signature(s) from package",
                verified_sigs.len()
            );

            // 3. Decrypt
            if let Some(plaintext) = decrypt_from_client(&ciphertext, kem_sk) {
                // 4. Parse plaintext
                if let Some((seq, ts, cmd)) = parse_plaintext(&plaintext) {
                    if seq <= *last_seq {
                        println!("[DROP] Replay: Seq {seq} <= {last_seq}");
                        let _ = fs::remove_file(file_path);
                        return;
                    }

                    // 5. Add to pending or create new
                    let pending = pending_commands
                        .entry(seq)
                        .or_insert_with(|| PendingCommand {
                            seq,
                            ts,
                            cmd: cmd.clone(),
                            ciphertext: ciphertext.clone(),
                            signatures: Vec::new(),
                        });

                    // Add new unique signatures
                    let mut added_new = false;
                    for (key_hex, sig) in verified_sigs {
                        if pending.signatures.iter().any(|s| s.key_hex == key_hex) {
                            println!(
                                "[INFO] Duplicate signature from key {} ignored",
                                &key_hex[..8]
                            );
                        } else {
                            println!("[COLLECT] Added signature from key {}", &key_hex[..8]);
                            pending.signatures.push(PendingSignature {
                                key_hex,
                                signature: sig,
                                timestamp: ts,
                            });
                            added_new = true;
                        }
                    }

                    if added_new {
                        println!(
                            "[COLLECT] Seq {}: {}/{} signatures collected",
                            seq,
                            pending.signatures.len(),
                            threshold_m
                        );

                        // Check if we have enough signatures
                        if pending.signatures.len() >= threshold_m {
                            // Evaluate static policies
                            let policy_static_ok = if let Some(ref config) = policy_config {
                                let verified_key_hexes: Vec<String> = pending
                                    .signatures
                                    .iter()
                                    .map(|s| s.key_hex.clone())
                                    .collect();

                                // First pass: Static/Time checks (no pulse metadata)
                                match evaluate_policies(
                                    &pending.cmd,
                                    &verified_key_hexes,
                                    config,
                                    None,
                                ) {
                                    Ok(()) => {
                                        println!(
                                            "[POLICY] Static Authorization granted for seq {seq}"
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        println!(
                                            "[POLICY] Static Authorization denied for seq {seq}: {e}"
                                        );
                                        false
                                    }
                                }
                            } else {
                                true // No policies, allow
                            };

                            if policy_static_ok {
                                println!(
                                    "[AUTHORIZED M={}/{}] New Command: {} (Seq: {}). Awaiting Pulse...",
                                    pending.signatures.len(),
                                    threshold_m,
                                    pending.cmd,
                                    seq
                                );

                                // Wait for Pulse
                                if let Some(pulse_metadata) = pulse_method.wait_for_pulse() {
                                    // Second pass: Dynamic checks (GeoFence with pulse metadata)
                                    let mut dynamic_ok = true;
                                    if let Some(ref config) = policy_config {
                                        let verified_key_hexes: Vec<String> = pending
                                            .signatures
                                            .iter()
                                            .map(|s| s.key_hex.clone())
                                            .collect();
                                        if let Err(e) = evaluate_policies(
                                            &pending.cmd,
                                            &verified_key_hexes,
                                            config,
                                            Some(&pulse_metadata),
                                        ) {
                                            println!(
                                                "[POLICY] Dynamic (Geo) Authorization denied: {e}"
                                            );
                                            dynamic_ok = false;
                                        }
                                    }

                                    if dynamic_ok {
                                        // PII Check
                                        if let Err(e) =
                                            privacy_validator.validate_privacy(&pending.cmd)
                                        {
                                            println!(
                                                "[PRIVACY] Command blocked by PII check: {e}"
                                            );
                                            let _ = privacy_logger
                                                .log_command_execution(
                                                    &pending.cmd,
                                                    AuditStatus::Rejected(format!(
                                                        "PII Violation: {e}"
                                                    )),
                                                    false,
                                                )
                                                .await;
                                            pending_commands.remove(&seq);
                                            let _ = fs::remove_file(file_path);
                                            return;
                                        }

                                        // Check if this is an emergency command (break-glass)
                                        let emergency_mode = pending.cmd.contains("emergency")
                                            || pending.cmd.contains("break-glass");

                                        execute_as_root(
                                            &pending.cmd,
                                            privacy_logger,
                                            emergency_mode,
                                        )
                                        .await;
                                        // Update State
                                        *last_seq = seq;
                                        if let Ok(mut f) = fs::File::create(state_path) {
                                            use std::io::Write;
                                            let _ = f.write_all(&last_seq.to_le_bytes());
                                        }
                                        // Remove from pending
                                        pending_commands.remove(&seq);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    println!("[DROP] Malformed Plaintext");
                }
            } else {
                println!("[DROP] Decryption Failed");
            }
        }
    } else {
        println!("[DROP] Invalid Wire Format");
    }
    let _ = fs::remove_file(file_path);
}

async fn execute_as_root(cmd: &str, privacy_logger: &PrivacyAuditLogger, emergency_mode: bool) {
    println!("[EXEC] Running: {cmd}");
    let output = Command::new("sh").arg("-c").arg(cmd).output();
    let _ = fs::write("/tmp/sentinel_history.log", format!("{output:?}"));

    // Log to privacy audit system
    let status = if let Ok(output) = output {
        if output.status.success() {
            AuditStatus::Success
        } else {
            AuditStatus::Failed(format!("Exit code: {}", output.status.code().unwrap_or(-1)))
        }
    } else {
        AuditStatus::Failed("Command execution failed".to_string())
    };

    // Log synchronously for now
    if let Err(e) = privacy_logger
        .log_command_execution(cmd, status, emergency_mode)
        .await
    {
        eprintln!("Failed to log command execution: {e}");
    }
}

// Keep existing tests
#[cfg(test)]
mod tests {
    use super::*;
    use fips204::ml_dsa_44;
    use fips204::traits::{KeyGen, Signer};

    #[test]
    fn test_parse_and_verify() {
        let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();

        let payload = b"encrypted_stuff";
        let sig = sk.try_sign(payload, b"tersec").unwrap();

        // Construct: Count(1) || Sig || Body
        let mut data = Vec::new();
        data.push(1);
        data.extend_from_slice(&sig);
        data.extend_from_slice(payload);

        let (sigs, body) = parse_wire_format(&data).expect("Parse failed");

        assert_eq!(sigs.len(), 1);
        assert_eq!(body, payload);

        // Verify
        assert!(verify_signature(&body, &sigs[0], &pk));
    }

    #[test]
    fn test_parse_plaintext() {
        let seq = 42u64;
        let ts = 100u64;
        let cmd = "cmd";
        let mut data = Vec::new();
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(&ts.to_le_bytes());
        data.extend_from_slice(cmd.as_bytes());

        let (p_seq, p_ts, p_cmd) = parse_plaintext(&data).unwrap();
        assert_eq!(p_seq, seq);
        assert_eq!(p_ts, ts);
        assert_eq!(p_cmd, cmd);
    }

    #[test]
    fn test_check_pulse_found() {
        use std::io::Cursor;
        let data = "Existing logs\nUNLOCK_COMMAND_B7A2\n";
        let mut reader = Cursor::new(data);
        assert!(check_pulse(&mut reader, "UNLOCK_COMMAND_B7A2", 1));
    }

    #[test]
    fn test_load_authorized_keys() {
        use serde::{Deserialize, Serialize};
        use std::fs;
        use tempfile::NamedTempFile;

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

        // Create test data
        let (pk, _sk) = ml_dsa_44::KG::try_keygen().unwrap();
        let pk_bytes = pk.into_bytes();
        let pk_hex = hex::encode(pk_bytes);

        let auth_keys = AuthorizedKeys {
            ceremony_id: "test_ceremony".to_string(),
            timestamp: 1234567890,
            officers: vec![OfficerKey {
                role: Role::DevOps,
                public_key_hex: pk_hex.clone(),
            }],
        };

        let json = serde_json::to_string(&auth_keys).unwrap();
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), &json).unwrap();

        // Test loading
        let (keys, role_mappings) = load_authorized_keys(temp_file.path()).unwrap();

        assert_eq!(keys.len(), 1);
        assert_eq!(role_mappings.len(), 1);
        assert_eq!(role_mappings[&pk_hex], vec!["DevOps".to_string()]);
    }

    #[test]
    fn test_parse_wire_format_invalid() {
        // Test with empty data
        assert!(parse_wire_format(&[]).is_none());

        // Test with insufficient data for signatures
        let data = vec![1]; // Count=1, but no signature data
        assert!(parse_wire_format(&data).is_none());

        // Test with count=0, which is valid (no signatures)
        let data = vec![0, 1, 2, 3]; // Count 0, body=[1,2,3]
        assert!(parse_wire_format(&data).is_some());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let (pk, _sk) = ml_dsa_44::KG::try_keygen().unwrap();
        let (_pk2, sk2) = ml_dsa_44::KG::try_keygen().unwrap();

        let payload = b"test";
        let sig = sk2.try_sign(payload, b"tersec").unwrap();

        // Wrong key
        assert!(!verify_signature(payload, &sig, &pk));
    }

    #[test]
    fn test_parse_plaintext_invalid() {
        // Too short
        assert!(parse_plaintext(&[]).is_none());

        // Insufficient length
        let data = vec![1, 2, 3, 4, 5, 6, 7]; // Less than 16 bytes
        assert!(parse_plaintext(&data).is_none());
    }

    #[test]
    fn test_evaluate_policies() {
        use shared::{CommandMetadata, PolicyCondition, TimeWindow};
        use std::collections::HashMap;

        let policy_config = PolicyConfig {
            policies: vec![Policy {
                name: "test_policy".to_string(),
                roles: vec!["admin".to_string()],
                operations: vec!["restart".to_string()],
                resources: vec!["apache".to_string()],
                threshold: 1,
                conditions: vec![],
                time_windows: None,
                approval_expression: Some("Role:DevOps".to_string()),
            }],
            role_mappings: HashMap::from([(
                "pk1".to_string(),
                vec!["admin".to_string(), "DevOps".to_string()],
            )]),
        };

        let cmd = "#TERSEC_META:{\"role\":\"admin\",\"operation\":\"restart\",\"resource\":\"apache\",\"parameters\":{}}\nsystemctl restart apache2";
        let verified_keys = vec!["pk1".to_string()];

        let result = evaluate_policies(cmd, &verified_keys, &policy_config, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_evaluate_policies_no_match() {
        let policy_config = PolicyConfig {
            policies: vec![],
            role_mappings: std::collections::HashMap::new(),
        };

        let cmd = "systemctl restart apache2";
        let verified_keys = vec![];

        let result = evaluate_policies(cmd, &verified_keys, &policy_config, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No applicable policy"));
    }

    #[test]
    fn test_check_policy_threshold() {
        let policy = Policy {
            name: "test".to_string(),
            roles: vec!["admin".to_string()],
            operations: vec![],
            resources: vec![],
            threshold: 2,
            conditions: vec![],
            time_windows: None,
            approval_expression: None,
        };

        let mut role_mappings = std::collections::HashMap::new();
        role_mappings.insert("pk1".to_string(), vec!["admin".to_string()]);
        role_mappings.insert("pk2".to_string(), vec!["admin".to_string()]);

        let policy_config = PolicyConfig {
            policies: vec![],
            role_mappings,
        };

        // Test below threshold
        let verified_keys = vec!["pk1".to_string()];
        assert!(!check_policy_threshold(&policy, &verified_keys, &policy_config).unwrap());

        // Test at threshold
        let verified_keys = vec!["pk1".to_string(), "pk2".to_string()];
        assert!(check_policy_threshold(&policy, &verified_keys, &policy_config).unwrap());
    }

    #[test]
    fn test_check_time_window() {
        let window = TimeWindow {
            start_time: "00:00".to_string(),
            end_time: "23:59".to_string(),
            days: vec![
                "monday".to_string(),
                "tuesday".to_string(),
                "wednesday".to_string(),
                "thursday".to_string(),
                "friday".to_string(),
                "saturday".to_string(),
                "sunday".to_string(),
            ],
        };
        assert!(check_time_window(&window)); // Should pass assuming valid time parsing

        let invalid_window = TimeWindow {
            start_time: "00:00".to_string(),
            end_time: "00:01".to_string(),
            days: vec![], // No days allowed
        };
        assert!(!check_time_window(&invalid_window));
    }
}
