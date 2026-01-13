#![allow(missing_docs)]
use fips204::ml_dsa_44; // FIPS 204 crate
use fips204::traits::{KeyGen, SerDes, Signer};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

#[allow(clippy::cognitive_complexity)]
fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("[DEVICE] Pulse Device Simulation Started...");

    let postbox = std::env::var("TERSEC_POSTBOX").unwrap_or_else(|_| "/tmp/postbox".to_string());
    let challenge_path = format!("{postbox}/pulse_challenge.bin");
    let response_path = format!("{postbox}/pulse_response.bin");
    let sk_path = format!("{postbox}/pulse_sk");
    let pk_path = format!("{postbox}/pulse_pk");

    // 1. Load or Generate Device Key
    let sk = if Path::new(&sk_path).exists() {
        tracing::info!("[DEVICE] Loading existing Device Key...");
        let bytes = fs::read(&sk_path).unwrap_or_else(|e| {
            tracing::error!("Failed to read sk: {e}");
            std::process::exit(1);
        });
        let bytes_array: [u8; 2560] = bytes.try_into().unwrap_or_else(|_| {
            tracing::error!("Invalid sk size");
            std::process::exit(1);
        });
        ml_dsa_44::PrivateKey::try_from_bytes(bytes_array).unwrap_or_else(|e| {
            tracing::error!("Invalid sk: {e}");
            std::process::exit(1);
        })
    } else {
        tracing::info!("[DEVICE] Generating NEW Device Key...");
        let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap_or_else(|e| {
            tracing::error!("Keygen failed: {e}");
            std::process::exit(1);
        });
        fs::write(&sk_path, sk.clone().into_bytes()).unwrap_or_else(|e| {
            tracing::error!("Failed to write sk: {e}");
            std::process::exit(1);
        });
        fs::write(&pk_path, pk.into_bytes()).unwrap_or_else(|e| {
            tracing::error!("Failed to write pk: {e}");
            std::process::exit(1);
        });
        tracing::info!("[DEVICE] Key generated and saved public key to postbox.");
        sk
    };

    tracing::info!("[DEVICE] Standing by for Challenges...");

    #[allow(clippy::infinite_loop)]
    loop {
        if Path::new(&challenge_path).exists() {
            // Read Challenge
            if let Ok(challenge) = fs::read(&challenge_path) {
                tracing::info!("[DEVICE] Challenge Received: {} bytes", challenge.len());

                // Sign
                let signature = sk
                    .try_sign(&challenge, b"tersec_pulse")
                    .unwrap_or_else(|e| {
                        tracing::error!("Signing failed: {e}");
                        std::process::exit(1);
                    });

                // Respond
                if let Err(e) = fs::write(&response_path, signature) {
                    tracing::error!("[DEVICE] Failed to write response: {e}");
                } else {
                    tracing::info!("[DEVICE] Response Sent.");
                    // Wait for challenge to disappear so we don't sign 1000 times
                    while Path::new(&challenge_path).exists() {
                        thread::sleep(Duration::from_millis(100));
                    }
                    tracing::info!("[DEVICE] Challenge cleared. Resuming standby.");
                }
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}
