# Sentinel (Daemon)

The **Sentinel** is the root of trust in the TersecPot system. It runs on the secure host and is responsible for:
1.  **Verifying Signatures**: Enforces M-of-N authorization using **ML-DSA-87** (FIPS 204).
2.  **Decrypting Commands**: Uses **ML-KEM-1024** (FIPS 203) private key to decrypt command packages.
3.  **Pulse Monitoring**: Blocks execution until an out-of-band "Pulse" signal (Web, USB, or TCP) is verified.
4.  **Policy Enforcement**: Checks role-based access control (RBAC) against `policies.toml`.
5.  **Privacy Preservation**: Automatically strips PII from commands and generates **Encrypted Audit Logs** (Zero-Knowledge) for compliance.

## Configuration
Configure via environment variables:

| Variable | Description |
|----------|-------------|
| `TERSEC_POSTBOX` | Directory for command exchange. |
| `TERSEC_M` | Number of required signatures (default: 1). |
| `TERSEC_PULSE_MODE` | Pulse Method: `WEB`, `USB`, `TCP`, `CRYPTO`. |
| `TERSEC_LOG` | Path to access log (for WEB pulse). |

## Running
```bash
cargo run -p sentinel
```
