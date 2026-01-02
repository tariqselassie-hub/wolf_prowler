# Wolf Den - Cryptographic Engine

**Status**: ✅ Production Ready | **Version**: 1.0

Wolf Den provides military-grade cryptographic operations with configurable security levels for the Wolf Prowler platform.

## 🔐 Features

- **Multi-Level Security**
  - `Low` (128-bit AES-GCM) - Development/Testing
  - `Medium` (192-bit AES-GCM) - Production Default
  - `High` (256-bit AES-GCM/ChaCha20-Poly1305) - Maximum Security

- **Compliance**
  - NIST FIPS 140-3 Levels 1-3
  - NSA CNSA Suite compliant (High mode)
  - Quantum-resistant 256-bit symmetric encryption

- **Key Management**
  - Automatic key rotation (1 hour for High, 1 day for Medium)
  - Secure key derivation with Argon2id
  - Session timeout enforcement

- **Algorithms**
  - AES-256-GCM (NSA approved for TOP SECRET)
  - ChaCha20-Poly1305 (IETF RFC 8439)
  - Argon2id password hashing

## 🚀 Quick Start

```rust
use wolf_den::{WolfDen, SecurityLevel};

// Initialize with high security
let den = WolfDen::new(SecurityLevel::High)?;

// Encrypt data
let plaintext = b"sensitive data";
let encrypted = den.encrypt(plaintext)?;

// Decrypt data
let decrypted = den.decrypt(&encrypted)?;
assert_eq!(plaintext, &decrypted[..]);
```

## 📦 Installation

```toml
[dependencies]
wolf_den = { path = "../wolf_den" }
```

## 🔧 Configuration

```rust
// Set security level via environment
std::env::set_var("WOLF_SECURITY_LEVEL", "high");

// Or programmatically
let den = WolfDen::new(SecurityLevel::High)?;
```

## 🛡️ Security Levels

| Level | Key Size | Cipher | Classification | Use Case |
|-------|----------|--------|----------------|----------|
| **Low** | 128-bit | AES-128-GCM | FIPS 140-3 Level 1 | Development/Testing |
| **Medium** | 192-bit | AES-192-GCM | NSA SECRET equivalent | Production (Default) |
| **High** | 256-bit | AES-256-GCM / ChaCha20 | NSA TOP SECRET | Maximum Security |

## 📄 License

MIT License - See [LICENSE](../LICENSE) for details.
