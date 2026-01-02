# Cryptography Features

The cryptographic core of Wolf Prowler provides military-grade encryption and secure identity management.

## Components

### `wolf_den` (Crypto Core)
A pure Rust cryptographic library designed for maximum performance and security.
- **Symmetric Encryption**: AES-GCM, ChaCha20Poly1305.
- **Asymmetric Encryption**: Curve25519, X25519-Dalek, P-256 (NIST).
- **Hashing & MAC**: BLAKE3, SHA-2, SHA-3, HMAC, Poly1305.
- **Key Derivation**: PBKDF2, Scrypt, Argon2, HKDF.
- **Security**: Full `zeroize` support for sensitive memory handling.

### `wolfsec` (Advanced Security)
- **Identity Management**: Ed25519-based node identities.
- **Certificate Management**: Automated X509 generation and parsing.
- **Key Management**: Secure storage and rotation protocols.
- **Zero-Knowledge Utilities**: Foundations for private audits.
