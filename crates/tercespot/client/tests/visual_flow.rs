//! Visual flow integration tests for the submitter client.
//!
//! This module contains end-to-end integration tests that simulate the visual command flow.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn visual_end_to_end_flow() {
    println!("\n=== VISUAL TEST: Crypto Pulse (Challenge-Response) ===");

    // 1. Setup Env and Paths
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let test_dir = format!("/tmp/tersec_visual_test_{}", now);
    let postbox = format!("{}/postbox", test_dir);
    let auth_keys_dir = format!("{}/authorized_keys", postbox);
    let history_file = "/tmp/sentinel_history.log";

    println!("[1] Setting up test environment at {}...", test_dir);
    // Clean up potentially
    if Path::new(&test_dir).exists() {
        let _ = fs::remove_dir_all(&test_dir);
    }
    fs::create_dir_all(&auth_keys_dir).expect("Failed to create postbox/auth_keys");
    let _ = fs::remove_file(history_file);

    // 2. Spawn Pulse Device FIRST (to generate pulse keys)
    println!("[2] Spawning Pulse Device...");
    let mut device = Command::new("cargo")
        .args(&["run", "-p", "submitter", "--bin", "pulse_device", "--quiet"])
        .env("TERSEC_POSTBOX", &postbox)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start device");

    // Wait for Pulse PK to appear
    let pk_pulse_path = format!("{}/pulse_pk", postbox);
    println!("Waiting for Pulse PK at {}...", pk_pulse_path);
    let mut loaded = false;
    for _ in 0..10 {
        if Path::new(&pk_pulse_path).exists() {
            println!("[SETUP] Pulse PK found.");
            loaded = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    if !loaded {
        device.kill().unwrap();
        panic!("Pulse Device failed to generate key");
    }

    // 3. Spawn Sentinel (PULSE_MODE=CRYPTO)
    println!("[3] Spawning Sentinel (Crypto Mode)...");
    let mut sentinel = Command::new("cargo")
        .args(&["run", "-p", "sentinel", "--quiet"])
        .env("TERSEC_POSTBOX", &postbox)
        .env("TERSEC_PULSE_MODE", "CRYPTO")
        .env("TERSEC_M", "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start sentinel");

    // Give it a moment to startup
    thread::sleep(Duration::from_secs(2));

    // 4. Run Submitter Workflow (M=1)
    println!("[4] Running Submitter Workflow...");

    // 4a. Keygen
    println!("  [4a] Generating Keys...");
    let keygen_status = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "submitter",
            "--bin",
            "submitter",
            "--quiet",
            "keygen",
        ])
        .env("TERSEC_POSTBOX", &postbox)
        .status()
        .expect("Failed to run keygen");
    assert!(keygen_status.success(), "Keygen failed");

    // 4a-2. MANUALLY CREATE authorized_keys.json (Daemon expects this, Submitter creates dir)
    println!("  [4a-2] Creating authorized_keys.json for Daemon...");
    let client_key_path = format!("{}/authorized_keys/client_key", postbox);
    let pk_bytes = fs::read(&client_key_path).expect("Failed to read client key");
    let pk_hex: String = pk_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let json_content = format!(
        r#"{{
        "ceremony_id": "VISUAL_TEST",
        "timestamp": {},
        "officers": [
            {{
                "role": "DevOps",
                "public_key_hex": "{}"
            }}
        ]
    }}"#,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        pk_hex
    );

    let auth_json_path = format!("{}/authorized_keys.json", postbox);
    fs::write(&auth_json_path, json_content).expect("Failed to write authorized_keys.json");

    // 4b. Create Partial
    println!("  [4b] Creating Partial Command...");
    let cmd_str = "echo test_execution";
    let partial_path = format!("{}/cmd.partial", test_dir);

    let partial_cmd = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "submitter",
            "--bin",
            "submitter",
            "--quiet",
            "submit",
            "--partial",
            cmd_str,
            "--signers",
            "1",
            "--output",
            &partial_path,
        ])
        .env("TERSEC_POSTBOX", &postbox)
        .status()
        .expect("Failed to create partial");
    assert!(partial_cmd.success(), "Create partial failed");

    // 4c. Sign (Append)
    println!("  [4c] Signing Command...");
    let sign_cmd = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "submitter",
            "--bin",
            "submitter",
            "--quiet",
            "submit",
            "--append",
            &partial_path,
            "--role",
            "DevOps", // Assuming default key path is used
        ])
        .env("TERSEC_POSTBOX", &postbox)
        .status()
        .expect("Failed to sign");
    assert!(sign_cmd.success(), "Signing failed");

    // 4d. Submit
    println!("  [4d] Submitting Command...");
    let submit_cmd = Command::new("cargo")
        .args(&[
            "run",
            "-p",
            "submitter",
            "--bin",
            "submitter",
            "--quiet",
            "submit",
            "--submit",
            &partial_path,
        ])
        .env("TERSEC_POSTBOX", &postbox)
        .status()
        .expect("Failed to submit");
    assert!(submit_cmd.success(), "Submission failed");

    // Copy generated key to auth keys (submitter saves to authorized_keys/client_key)
    // Wait for authorization and execution
    println!("[5] Waiting for Challenge-Response Execution...");
    
    // Poll for the history file instead of fixed sleep
    let mut executed = false;
    for _ in 0..30 {
        if Path::new(history_file).exists() {
            executed = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    if executed {
        // Give it a moment to finish writing
        thread::sleep(Duration::from_secs(1));
    }

    // 5. Verify Execution
    if Path::new(history_file).exists() {
        let output = fs::read_to_string(history_file).unwrap();
        println!(">>> SUCCESS: System executed command! Output captured:");
        println!("{}", output);
    } else {
        println!(">>> FAILURE: Execution history file not found.");
        sentinel.kill().unwrap();
        device.kill().unwrap();
        panic!("Test failed: Execution did not occur.");
    }

    // Teardown
    sentinel.kill().unwrap();
    device.kill().unwrap();
    println!("=== Test Complete ===\n");
}
