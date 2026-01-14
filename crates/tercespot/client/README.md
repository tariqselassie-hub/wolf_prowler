# Submitter (Client)

The **Submitter** CLI tool is used by operators to package and sign commands for the TersecPot system.

## Features
*   **Key Generation**: Generates ephemeral **ML-DSA-87** keypairs.
*   **Encryption**: Encrypts commands for the Sentinel using **ML-KEM-1024**.
*   **Signing**: Signs the encrypted package (Encrypt-then-Sign).
*   **Multi-Party Support**: capable of `partial` signing and `append` flows for M-of-N authorization.

## Usage

### 1. Key Generation
```bash
# Generate private key and output public key to authorized_keys
cargo run -p submitter -- keygen --out ./private_key
```

### 2. Submit Command (Single User)
```bash
cargo run -p submitter -- "systemctl restart nginx"
```

### 3. Multi-Party Submission
```bash
# User A: Create Partial
cargo run -p submitter -- submit --partial "reboot" --output reboot.partial

# User B: Append Signature
cargo run -p submitter -- submit --append reboot.partial --role SecurityOfficer

# User C: Submit
cargo run -p submitter -- submit --submit reboot.partial
```
