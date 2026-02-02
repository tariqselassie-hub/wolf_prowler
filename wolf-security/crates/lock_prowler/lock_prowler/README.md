# Lock Prowler: Forensic Engine

> **Status**: Production Ready (Version 0.1.0)
> **Purpose**: BitLocker Metadata Extraction & Recovery
> **Role**: Forensic Agent

Lock Prowler is the forensic core of the ecosystem. It specializes in parsing, analyzing, and recovering data from BitLocker-encrypted volumes (FVE). It can operate as a library or a standalone CLI agent.

## 🏗️ Architecture

Lock Prowler is modularized to handle different stages of the forensic process:

1.  **FVE Parser (`metadata` / `sharding`)**:
    *   Zero-copy parsing of Volume Master Keys (VMK) and Full Volume Encryption (FVE) headers.
    *   Identification of Key Protectors (TPM, DRA, Recovery Password).
2.  **Attack Strategies (`algorithms`)**:
    *   **Nonce Reuse**: Statistical analysis to detect reused standard nonces in AES-CBC streams.
    *   **Weak RSA**: Heuristic scanning for known vulnerable RSA key generation patterns.
3.  **Headless Agent (`headless`)**:
    *   Automated mode for deployed sensors.
    *   Continuously scans attached volumes and reports to `wolf_web`.

## 💻 Usage

### CLI Mode

```bash
# Analyze a disk image
cargo run --release -- analyze /path/to/disk.img

# Attempt recovery using a dictionary
cargo run --release -- recover /path/to/disk.img --wordlist rockyou.txt
```

### Library Integration

```rust
use lock_prowler::headless::{HeadlessWolfProwler, HeadlessConfig};

async fn start_agent(store: WolfStore) {
    let config = HeadlessConfig::default();
    let prowler = HeadlessWolfProwler::new(config, store);
    
    // Start background scanning
    prowler.run().await;
}
```

## 📦 Modules

*   `algorithms`: Cryptanalysis logic.
*   `headless`: Automation and reporting.
*   `sharding`: Metadata parsing.
*   `vault`: Secure storage interface (wraps `wolf_db`).
