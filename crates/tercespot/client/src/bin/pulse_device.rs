#![allow(missing_docs)]
use fips204::ml_dsa_44; // FIPS 204 crate
use fips204::traits::{KeyGen, SerDes, Signer};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

fn main() {
    println!("[DEVICE] Pulse Device Simulation Started...");

    let postbox = std::env::var("TERSEC_POSTBOX").unwrap_or_else(|_| "/tmp/postbox".to_string());
    let challenge_path = format!("{}/pulse_challenge.bin", postbox);
    let response_path = format!("{}/pulse_response.bin", postbox);
    let sk_path = format!("{}/pulse_sk", postbox);
    let pk_path = format!("{}/pulse_pk", postbox);

    // 1. Load or Generate Device Key
    let sk = if Path::new(&sk_path).exists() {
        println!("[DEVICE] Loading existing Device Key...");
        let bytes = fs::read(&sk_path).expect("Failed to read sk");
        let bytes_array: [u8; 2560] = bytes.try_into().expect("Invalid sk size");
        ml_dsa_44::PrivateKey::try_from_bytes(bytes_array).expect("Invalid sk")
    } else {
        println!("[DEVICE] Generating NEW Device Key...");
        let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
        fs::write(&sk_path, sk.clone().into_bytes()).unwrap();
        fs::write(&pk_path, pk.into_bytes()).unwrap();
        println!("[DEVICE] Key generated and saved public key to postbox.");
        sk
    };

    println!("[DEVICE] Standing by for Challenges...");

    loop {
        if Path::new(&challenge_path).exists() {
            // Read Challenge
            match fs::read(&challenge_path) {
                Ok(challenge) => {
                    println!("[DEVICE] Challenge Received: {} bytes", challenge.len());

                    // Sign
                    let signature = sk.try_sign(&challenge, b"tersec_pulse").unwrap();

                    // Respond
                    if let Err(e) = fs::write(&response_path, &signature) {
                        println!("[DEVICE] Failed to write response: {}", e);
                    } else {
                        println!("[DEVICE] Response Sent.");
                        // Wait for challenge to disappear so we don't sign 1000 times
                        while Path::new(&challenge_path).exists() {
                            thread::sleep(Duration::from_millis(100));
                        }
                        println!("[DEVICE] Challenge cleared. Resuming standby.");
                    }
                }
                Err(_) => {}
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}
