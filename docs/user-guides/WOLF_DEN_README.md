# 🐺 Wolf Den - Cryptographic Foundation

> **State-of-the-art cryptographic library for secure P2P networking**

[![Crates.io](https://img.shields.io/crates/v/wolf_den.svg)](https://crates.io/crates/wolf_den)
[![Documentation](https://docs.rs/wolf_den/badge.svg)](https://docs.rs/wolf_den)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Build Status](https://github.com/wolf-prowler/wolf_den/workflows/CI/badge.svg)](https://github.com/wolf-prowler/wolf_den/actions)

Wolf Den is a comprehensive, modern cryptographic library designed specifically for secure peer-to-peer networking. It provides enterprise-grade security with a focus on performance, memory safety, and resistance to side-channel attacks.

## 🛡️ Security Features

### **Core Cryptography**
- **Authenticated Encryption**: ChaCha20-Poly1305, AES-256-GCM
- **Key Exchange**: X25519, P-256, P-384, secp256k1
- **Digital Signatures**: Ed25519, ECDSA (P-256, P-384, secp256k1)
- **Hash Functions**: BLAKE3, SHA-2, SHA-3, RIPEMD-160
- **Message Authentication**: HMAC, Poly1305

### **Advanced Security**
- **Perfect Forward Secrecy**: Automatic key rotation and ratcheting
- **Zero-Knowledge Proofs**: Privacy-preserving protocols
- **Post-Quantum Ready**: Framework for quantum-resistant algorithms
- **Memory Protection**: Secure memory allocation and zeroization
- **Side-Channel Resistance**: Constant-time operations
- **Secure Randomness**: Multiple entropy sources with fallbacks

### **Network Security**
- **Key Derivation**: HKDF, PBKDF2, scrypt, Argon2
- **Authenticated Key Exchange**: Noise protocol framework
- **Session Management**: Secure session establishment and maintenance
- **Identity Management**: Decentralized identity and authentication

## 🚀 Quick Start

### **Installation**

```toml
[dependencies]
wolf_den = "0.1.0"
```

For full features:
```toml
[dependencies]
wolf_den = { version = "0.1.0", features = ["std", "serde", "tokio"] }
```

### **Basic Usage**

```rust
use wolf_den::{
    CryptoEngine, KeyPair, CipherSuite, HashFunction,
    SecureRandom, MemoryProtection
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize cryptographic engine
    let crypto = CryptoEngine::builder()
        .cipher_suite(CipherSuite::ChaCha20Poly1305)
        .hash_function(HashFunction::Blake3)
        .memory_protection(MemoryProtection::Strict)
        .build()?;

    // Generate secure key pair
    let key_pair = crypto.generate_key_pair(KeyType::Ed25519)?;
    
    // Encrypt data
    let plaintext = b"Hello, secure world!";
    let ciphertext = crypto.encrypt(plaintext, &key_pair.public_key())?;
    
    // Decrypt data
    let decrypted = crypto.decrypt(&ciphertext, &key_pair.private_key())?;
    
    assert_eq!(plaintext, &decrypted[..]);
    
    Ok(())
}
```

### **Secure Communication**

```rust
use wolf_den::{
    SecureChannel, KeyExchange, NoiseProtocol, 
    AuthenticationMethod
};

// Create secure channel with Noise protocol
let channel = SecureChannel::builder()
    .protocol(NoiseProtocol::NK)
    .key_exchange(KeyExchange::X25519)
    .authentication(AuthenticationMethod::Ed25519)
    .build()?;

// Perform handshake
let session = channel.handshake(&remote_public_key).await?;

// Send encrypted message
let message = b"Secure message";
let encrypted = session.encrypt_message(message)?;
channel.send(&encrypted).await?;

// Receive and decrypt message
let received = channel.receive().await?;
let decrypted = session.decrypt_message(&received)?;
```

## 🏗️ Architecture

### **Core Components**

```
wolf_den/
├── crypto/           # Core cryptographic primitives
│   ├── symmetric/    # Symmetric encryption (AES, ChaCha20)
│   ├── asymmetric/  # Asymmetric cryptography (ECC, RSA)
│   ├── hash/        # Hash functions and MACs
│   ├── kdf/         # Key derivation functions
│   └── random/      # Secure randomness
├── protocols/        # High-level protocols
│   ├── noise/       # Noise protocol framework
│   ├── tls/         # TLS-like protocols
│   └── custom/      # Custom protocol implementations
├── keystore/         # Key management and storage
├── identity/         # Identity and authentication
├── zero_knowledge/    # Zero-knowledge proof systems
└── utils/            # Utilities and helpers
```

### **Security Design Principles**

1. **Memory Safety**: All sensitive data is stored in protected memory
2. **Constant-Time**: All cryptographic operations are constant-time
3. **Forward Secrecy**: Automatic key rotation and ratcheting
4. **Side-Channel Resistance**: Resistance to timing and cache attacks
5. **Fail-Safe**: All operations fail securely without leaking information

## 🔐 Cryptographic Primitives

### **Symmetric Encryption**

```rust
use wolf_den::symmetric::{Cipher, CipherMode};

// ChaCha20-Poly1305 encryption
let cipher = Cipher::new_chacha20poly1305(&key)?;
let ciphertext = cipher.encrypt(plaintext, &nonce, &aad)?;

// AES-256-GCM encryption
let cipher = Cipher::new_aes256gcm(&key)?;
let ciphertext = cipher.encrypt(plaintext, &nonce, &aad)?;
```

### **Asymmetric Cryptography**

```rust
use wolf_den::asymmetric::{KeyPair, SignatureScheme};

// Ed25519 key pair
let key_pair = KeyPair::generate_ed25519()?;
let signature = key_pair.sign(message)?;

// ECDSA key pair (P-256)
let key_pair = KeyPair::generate_p256()?;
let signature = key_pair.sign(message)?;
```

### **Key Exchange**

```rust
use wolf_den::asymmetric::{KeyExchange, EphemeralKey};

// X25519 key exchange
let alice_key = EphemeralKey::generate_x25519()?;
let bob_key = EphemeralKey::generate_x25519()?;

let shared_secret = alice_key.exchange(&bob_key.public_key())?;
```

### **Hashing**

```rust
use wolf_den::hash::{Hasher, HashFunction};

// BLAKE3 hashing
let hash = Hasher::blake3().digest(data)?;

// HMAC
let hmac = Hasher::hmac_sha256(&key).digest(data)?;
```

## 🔑 Key Management

### **Key Generation**

```rust
use wolf_den::keystore::{KeyStore, KeyType, KeyPurpose};

let keystore = KeyStore::new()?;

// Generate encryption key
let enc_key = keystore.generate_key(
    KeyType::ChaCha20Poly1305,
    KeyPurpose::Encryption
)?;

// Generate signing key
let sign_key = keystore.generate_key(
    KeyType::Ed25519,
    KeyPurpose::Signing
)?;
```

### **Key Storage**

```rust
use wolf_den::keystore::{SecureStorage, KeyMetadata};

let storage = SecureStorage::new()?;

// Store key with metadata
storage.store_key(&key, KeyMetadata {
    name: "main_encryption_key".to_string(),
    purpose: KeyPurpose::Encryption,
    created_at: chrono::Utc::now(),
})?;

// Retrieve key
let retrieved_key = storage.get_key("main_encryption_key")?;
```

## 🌐 Network Protocols

### **Noise Protocol Framework**

```rust
use wolf_den::protocols::noise::{NoiseBuilder, NoisePattern};

// Noise NK pattern
let noise = NoiseBuilder::new()
    .pattern(NoisePattern::NK)
    .prologue(b"wolf_prowler")
    .build()?;

// Perform handshake
let handshake_state = noise.initiator_handshake(&static_key, &remote_public_key)?;
let transport = handshake_state.finalize()?;
```

### **Secure Sessions**

```rust
use wolf_den::protocols::{SecureSession, SessionConfig};

let session = SecureSession::new(SessionConfig {
    cipher_suite: CipherSuite::ChaCha20Poly1305,
    hash_function: HashFunction::Blake3,
    key_rotation_interval: Duration::from_secs(3600),
})?;

// Encrypt message
let encrypted = session.encrypt_message(message)?;

// Decrypt message
let decrypted = session.decrypt_message(&encrypted)?;
```

## 🔬 Zero-Knowledge Proofs

### **Range Proofs**

```rust
use wolf_den::zero_knowledge::{RangeProof, Prover, Verifier};

let prover = Prover::new();
let verifier = Verifier::new();

// Create range proof
let proof = prover.create_range_proof(value, min, max)?;

// Verify range proof
let is_valid = verifier.verify_range_proof(&proof, min, max)?;
```

### **Schnorr Signatures**

```rust
use wolf_den::zero_knowledge::{SchnorrSignature, Signer};

let signer = Signer::new(&secret_key);
let signature = signer.schnorr_sign(message)?;

let is_valid = signature.verify(&public_key, message)?;
```

## 🛡️ Security Best Practices

### **Memory Protection**

```rust
use wolf_den::security::{SecureBytes, MemoryProtection};

let mut secure_data = SecureBytes::new(
    sensitive_data,
    MemoryProtection::Strict
)?;

// Automatically zeroized on drop
```

### **Constant-Time Operations**

```rust
use wolf_den::security::constant_time_eq;

// Constant-time comparison
let is_equal = constant_time_eq(&data1, &data2);
```

### **Secure Randomness**

```rust
use wolf_den::random::{SecureRandom, RandomnessSource};

let rng = SecureRandom::new(RandomnessSource::Hybrid)?;
let random_bytes = rng.random_bytes(32)?;
```

## 🔧 Configuration

### **Environment Variables**

```bash
# Memory protection level
export WOLF_DEN_MEMORY_PROTECTION=strict

# Randomness source
export WOLF_DEN_RANDOMNESS_SOURCE=hybrid

# Key storage backend
export WOLF_DEN_KEYSTORE_BACKEND=encrypted_file

# Logging level
export WOLF_DEN_LOG_LEVEL=info
```

### **Configuration File**

```toml
[wolf_den]
memory_protection = "strict"
randomness_source = "hybrid"
log_level = "info"

[wolf_den.crypto]
default_cipher_suite = "chacha20poly1305"
default_hash_function = "blake3"
key_rotation_interval = 3600

[wolf_den.keystore]
backend = "encrypted_file"
storage_path = "/var/lib/wolf_den/keys"
encryption_key_derivation = "argon2id"

[wolf_den.protocols]
noise_pattern = "NK"
session_timeout = 86400
max_message_size = 1048576
```

## 📊 Performance

### **Benchmarks**

| Operation | Performance | Security Level |
|-----------|-------------|----------------|
| ChaCha20-Poly1305 | ~1.5 GB/s | 256-bit |
| AES-256-GCM | ~2.0 GB/s | 256-bit |
| BLAKE3 | ~3.0 GB/s | 256-bit |
| X25519 | ~100K ops/s | 256-bit |
| Ed25519 | ~50K ops/s | 256-bit |

### **Memory Usage**

| Component | Base Usage | Peak Usage |
|-----------|------------|------------|
| Crypto Engine | ~50KB | ~200KB |
| Key Store | ~100KB | ~1MB |
| Session Cache | ~200KB | ~5MB |
| Protocol State | ~50KB | ~500KB |

## 🧪 Testing

### **Run Tests**

```bash
# Run all tests
cargo test

# Run with specific features
cargo test --features "serde tokio"

# Run benchmarks
cargo bench

# Run property-based tests
cargo test --features "unstable" proptest
```

### **Test Coverage**

```bash
# Generate coverage report
cargo tarpaulin --out Html

# View coverage
open tarpaulin-report.html
```

## 📚 Documentation

- **[API Documentation](https://docs.rs/wolf_den)** - Complete API reference
- **[Security Guide](docs/security.md)** - Security considerations and best practices
- **[Protocol Guide](docs/protocols.md)** - Protocol implementations and usage
- **[Performance Guide](docs/performance.md)** - Performance optimization tips
- **[Examples](examples/)** - Code examples and tutorials

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**

```bash
# Clone repository
git clone https://github.com/wolf-prowler/wolf_den.git
cd wolf_den

# Install dependencies
cargo build

# Run tests
cargo test

# Run linting
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## 📄 License

This project is licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

at your option.

## 🔗 Related Projects

- **[Wolf Prowler](https://github.com/wolf-prowler/wolf_prowler)** - Main P2P networking project
- **[Wolf Pack](https://github.com/wolf-prowler/wolf_pack)** - Network utilities and tools
- **[Wolf Howl](https://github.com/wolf-prowler/wolf_howl)** - Messaging and communication

## 🆘 Support

- **[Issues](https://github.com/wolf-prowler/wolf_den/issues)** - Bug reports and feature requests
- **[Discussions](https://github.com/wolf-prowler/wolf_den/discussions)** - Community discussions
- **[Discord](https://discord.gg/wolfprowler)** - Real-time chat support

---

**Built with ❤️ by the Wolf Prowler team**

> *In the digital wilderness, security is our den.*
