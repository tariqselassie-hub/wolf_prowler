# Privacy Module

The **Privacy Module** ensures GDPR compliance and zero-knowledge audit logging.

## Features
*   **PII Stripping**: Automatically detects and redacts PII (SSN, Email, Phone) from command strings before execution or logging.
*   **Encrypted Audit Logs**: Logs command intents in an encrypted format. Only auditors holding the corresponding private key can reveal the PII for forensic analysis.
*   **Zero-Knowledge**: The system operator cannot see the sensitive data in the logs.

## Configuration
Controlled via `PrivacyConfig` struct in `daemon/src/main.rs`.
