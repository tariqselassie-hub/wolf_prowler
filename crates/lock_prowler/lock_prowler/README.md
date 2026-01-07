# lock_prowler (Core & CLI)

The core engine and command-line interface for the Lock Prowler BitLocker recovery suite.

## Features
- **FVE Parser**: Detailed extraction of BitLocker Metadata (FVE Headers, Entry Tables).
- **Key Protector Identification**: Support for TPM, DRA, and Password-based protectors.
- **Recovery Algorithms**:
    - **Nonce Reuse**: Detection and exploitation of cryptographic nonce reuse.
    - **Weak RSA Analysis**: Heuristic identification of exploitable RSA parameters.

## Usage
```bash
cargo run -- <image_path>
```

## Architecture
This crate is designed to be used both as a standalone library (`lib.rs`) and as a CLI application (`main.rs`). It is a dependency for the `lock_prowler_dashboard` Fullstack application.
