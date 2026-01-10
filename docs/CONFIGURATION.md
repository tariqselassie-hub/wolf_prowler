# Wolf Prowler Configuration Guide

This document details the configuration options for the Wolf Prowler ecosystem.

## Global Configuration (`settings.toml`)

The primary configuration file is `settings.toml` located in the project root.

```toml
[server]
port = 8080
host = "0.0.0.0"

[logging]
level = "info"
file = "logs/wolf_prowler.log"

[security]
level = "standard"  # Options: low, standard, high
enable_ai = true

[crypto]
default_hash = "blake3"
default_kdf = "argon2"
```

## Environment Variables

Override default settings using environment variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `WOLF_PROWLER_PORT` | HTTP Server Port | `8080` |
| `WOLF_PROWLER_HOST` | Bind Address | `0.0.0.0` |
| `WOLF_LOG_LEVEL` | Logging Verbosity | `info` |
| `DATABASE_URL` | Database Connection String | (Required for SQLx) |

## TersecPot Configuration

TersecPot components use specific environment variables for the "Blind Command-Bus".

| Variable | Description |
|----------|-------------|
| `TERSEC_POSTBOX` | Path to the shared command directory |
| `TERSEC_M` | Number of required signatures (M-of-N) |
| `TERSEC_PULSE_MODE` | Pulse mechanism (`WEB`, `USB`, `CRYPTO`) |

## Feature Flags

Enable/Disable functionality at compile time via `Cargo.toml`.

- `ml-full`: Enables ONNX Runtime and Linfa for AI detection.
- `advanced_reporting`: Enables plotting and PDF report generation.
- `cloud_security`: Enables AWS/Azure/GCP integration.
