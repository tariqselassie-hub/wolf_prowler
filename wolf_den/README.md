# Wolf Den: Cryptographic Engine

> **Status**: Production Ready (Version 0.1.0)
> **Compliance**: FIPS 140-3 Levels 1-3 Support
> **Key Tech**: AES-GCM, ChaCha20-Poly1305, Argon2id, BLAKE3

Wolf Den is the "Pure Crypto" core of the Wolf Prowler ecosystem. It provides a configurable `CryptoEngine` that abstracts best-in-class algorithms behind simple, secure-by-default interfaces.

## 🏗️ Architecture

Wolf Den uses a **Builder Pattern** to construct a `CryptoEngine` tailored to specific security or performance constraints.

- **Engine Facade**: `CryptoEngine` unifies Hashing, KDF, MAC, and Symmetric Encryption.
- **Security Levels**: pre-defined sets of key sizes and iteration counts.
    - `Minimum` (128-bit) - Optimized for legacy/IoT.
    - `Standard` (192-bit) - Default Production.
    - `Maximum` (256-bit) - NSA Top Secret spec.

### Primitives

| Category | High Perf | Maximum Security |
| --- | --- | --- |
| **Symmetric** | ChaCha20-Poly1305 | AES-256-GCM |
| **Hashing** | BLAKE3 | SHA3-512 |
| **KDF** | HKDF | Argon2id |
| **MAC** | Poly1305 | HMAC-SHA512 |

## 💻 Usage

### Initialization (Builder)

```rust
use wolf_den::{CryptoEngine, SecurityLevel, HashFunction};

fn init_crypto() -> anyhow::Result<CryptoEngine> {
    // 1. Precise Control
    let engine = CryptoEngine::builder()
        .with_security_level(SecurityLevel::Maximum)
        .with_hash_function(HashFunction::Sha3_512)
        .build()?;
        
    // 2. OR use Presets
    let fast_engine = CryptoEngine::high_performance().build()?;
    
    Ok(engine)
}
```

### Encryption Cycle

```rust
fn secure_payload(engine: &CryptoEngine, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Encrypts using the configured cipher suite (e.g., AES-256-GCM)
    // Automatically handles Nonce generation and tag appending.
    let encrypted = engine.encrypt(data)?;
    Ok(encrypted)
}
```

## 📦 Dependencies

*   `aes-gcm` / `chacha20poly1305`: AEAD ciphers.
*   `argon2`: Memory-hard password hashing.
*   `blake3`: fast cryptographic hashing.
*   `ed25519-dalek`: Digital signatures.

## 🔒 Guarantee

Wolf Den ensures **Type Safety** for cryptographic operations. It prevents mixing security levels or using uninitialized engines. All keys are zeroized on drop.
