use crate::check_pulse;
use fips204::ml_dsa_44; // For verifying signature
use fips204::traits::{SerDes, Verifier};
use shared::postbox_path;
use std::fs;
use std::io::{BufReader, Seek, SeekFrom};
use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

/// Configures which pulse method to use for physical presence verification
pub enum PulseMethod {
    /// USB-based pulse: waits for a file to appear on a USB device
    Usb(String),
    /// Web-based pulse: scans web server logs for a specific token
    Web(String),
    /// TCP-based pulse: waits for a connection on a specified port
    Tcp(u16),
    /// Cryptographic challenge-response pulse using digital signatures
    Crypto,
}

impl PulseMethod {
    /// Creates a `PulseMethod` from environment variables `TERSEC_PULSE_MODE` and `TERSEC_PULSE_ARG`
    ///
    /// Supported modes: USB, WEB, TCP, CRYPTO. Defaults to WEB if not specified.
    #[must_use]
    pub fn from_env() -> Self {
        let mode = std::env::var("TERSEC_PULSE_MODE").unwrap_or_else(|_| "WEB".to_string());
        let arg = std::env::var("TERSEC_PULSE_ARG").unwrap_or_else(|_| String::new());

        match mode.trim().to_uppercase().as_str() {
            "USB" => {
                let path = if arg.is_empty() {
                    "/mnt/usb/pulse_key".to_string()
                } else {
                    arg
                };
                Self::Usb(path)
            }
            "TCP" => {
                let port = arg.parse().unwrap_or(9999);
                Self::Tcp(port)
            }
            "CRYPTO" => Self::Crypto,
            _ => {
                // Default to WEB
                let path = if arg.is_empty() {
                    "/var/log/nginx/access.log".to_string()
                } else {
                    arg
                };
                Self::Web(path)
            }
        }
    }

    /// Waits for a pulse signal based on the configured method
    ///
    /// # Returns
    /// `PulseMetadata` if pulse is detected within timeout, None otherwise
    #[must_use]
    pub fn wait_for_pulse(&self) -> Option<shared::PulseMetadata> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match self {
            Self::Usb(path) => {
                if wait_for_usb(path) {
                    Some(shared::PulseMetadata {
                        timestamp,
                        location: "Local".to_string(), // USB implies physical access
                        method: "USB".to_string(),
                    })
                } else {
                    None
                }
            }
            Self::Web(path) => {
                if wait_for_web_log(path) {
                    Some(shared::PulseMetadata {
                        timestamp,
                        location: "US-East".to_string(), // Mocked for Web Pulse
                        method: "WEB".to_string(),
                    })
                } else {
                    None
                }
            }
            Self::Tcp(port) => {
                if wait_for_tcp(*port) {
                    Some(shared::PulseMetadata {
                        timestamp,
                        location: "Remote".to_string(), // Mocked
                        method: "TCP".to_string(),
                    })
                } else {
                    None
                }
            }
            Self::Crypto => {
                if wait_for_crypto() {
                    Some(shared::PulseMetadata {
                        timestamp,
                        location: "SecureEnclave".to_string(),
                        method: "CRYPTO".to_string(),
                    })
                } else {
                    None
                }
            }
        }
    }
}

fn wait_for_usb(path_str: &str) -> bool {
    tracing::info!("[PULSE] Waiting for USB key file at: {path_str}");
    for _ in 0..30 {
        if Path::new(path_str).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

fn wait_for_web_log(path: &str) -> bool {
    tracing::info!("[PULSE] Scanning Web Log at: {path}");
    // Start at current end (or 0 if missing)
    let mut current_pos = match fs::File::open(path) {
        Ok(f) => f.metadata().map(|m| m.len()).unwrap_or(0),
        Err(_) => 0,
    };

    // Poll for ~30 seconds
    for _ in 0..30 {
        if let Ok(mut file) = fs::File::open(path) {
            if file.seek(SeekFrom::Start(current_pos)).is_ok() {
                let mut reader = BufReader::new(file);
                if check_pulse(&mut reader, "UNLOCK_COMMAND_B7A2", 1) {
                    return true;
                }
                if let Ok(new_pos) = reader.stream_position() {
                    current_pos = new_pos;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

fn wait_for_tcp(port: u16) -> bool {
    tracing::info!("[PULSE] Waiting for TCP connection on port {port}...");
    let listener = match TcpListener::bind(format!("0.0.0.0:{port}")) {
        Ok(l) => l,
        Err(e) => {
            tracing::info!("Failed to bind TCP: {e}");
            return false;
        }
    };
    listener.set_nonblocking(true).ok();

    for _ in 0..30 {
        match listener.accept() {
            Ok(_) => return true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            Err(e) => {
                tracing::info!("TCP Accept Error: {e}");
                return false;
            }
        }
    }
    false
}

fn wait_for_crypto() -> bool {
    tracing::info!("[PULSE] Active Challenge-Response (Crypto Mode)...");

    let postbox = postbox_path();
    let challenge_path = format!("{postbox}/pulse_challenge.bin");
    let response_path = format!("{postbox}/pulse_response.bin");
    let pk_path = format!("{postbox}/pulse_pk");

    // 1. Load Pulse Public Key (Trusted)
    let pk_bytes = if let Ok(b) = fs::read(&pk_path) {
        b
    } else {
        tracing::info!("[PULSE] Error: pulse_pk not found in postbox.");
        return false;
    };
    let pk_array: [u8; 1312] = if let Ok(a) = pk_bytes.try_into() {
        a
    } else {
        tracing::info!("[PULSE] Error: Invalid pulse_pk size.");
        return false;
    };
    let pk = if let Ok(k) = ml_dsa_44::PublicKey::try_from_bytes(pk_array) {
        k
    } else {
        tracing::info!("[PULSE] Error: Invalid pulse_pk format.");
        return false;
    };

    // 2. Generate Challenge (32 bytes random)
    // We use a simple randomness here (OS RNG would be better)
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let challenge_str = format!("CHALLENGE_{nanos}");
    let challenge = challenge_str.as_bytes();

    // Write Challenge
    if let Err(e) = fs::write(&challenge_path, challenge) {
        tracing::info!("[PULSE] Failed to write challenge: {e}");
        return false;
    }

    tracing::info!("[PULSE] Challenge Issued. Waiting for signature on response...");

    // 3. Poll for Response
    for _ in 0..30 {
        if Path::new(&response_path).exists() {
            // Read Response (Should be Signature)
            // Sig size is 2420
            let sig_bytes = if let Ok(b) = fs::read(&response_path) {
                b
            } else {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            };

            if sig_bytes.len() == 2420 {
                let sig_array: [u8; 2420] = sig_bytes.try_into().unwrap();
                if pk.verify(challenge, &sig_array, b"tersec_pulse") {
                    tracing::info!("[PULSE] VALID RESPONSE! Pulse Confirmed.");
                    let _ = fs::remove_file(&challenge_path);
                    let _ = fs::remove_file(&response_path);
                    return true;
                }
                tracing::info!("[PULSE] Invalid Signature on Response.");
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    tracing::info!("[PULSE] Timeout waiting for crypto response.");
    let _ = fs::remove_file(&challenge_path);
    false
}
