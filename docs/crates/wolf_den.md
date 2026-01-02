# Wolf Den - Cryptographic Engine

## Overview

Wolf Den is the cryptographic foundation of the Wolf Prowler project, providing secure and performant cryptographic operations for all system components. It implements modern cryptographic primitives with a focus on security, performance, and ease of use.

## Features

### Core Cryptographic Operations

- **Hashing**: Blake3, SHA-2, SHA-3 families
- **Key Derivation**: Argon2, PBKDF2, Scrypt, HKDF
- **Message Authentication**: HMAC, Poly1305, CMAC, Blake2b-MAC
- **Random Generation**: Cryptographically secure random bytes
- **Memory Protection**: Secure memory handling for sensitive data

### Security Levels

Wolf Den provides configurable security levels for different use cases:

- **Low**: Fast operations for non-critical data
- **Standard**: Balanced security and performance (default)
- **High**: Maximum security for sensitive operations
- **Paranoid**: Maximum security with performance overhead

## Architecture

### Core Components

```
wolf_den/
├── lib.rs              # Main library interface
├── engine.rs           # CryptoEngine orchestrator
├── hash.rs             # Hashing implementations
├── kdf.rs              # Key derivation functions
├── mac.rs              # Message authentication codes
├── memory.rs           # Secure memory handling
├── error.rs            # Error types and handling
└── builder.rs          # Configuration builder
```

### CryptoEngine

The `CryptoEngine` is the main entry point that coordinates all cryptographic operations:

```rust
use wolf_den::{CryptoEngine, SecurityLevel};

let engine = CryptoEngine::new(SecurityLevel::Standard)?;
let hash = engine.hash(b"data", HashFunction::Blake3).await?;
let key = engine.derive_key(b"password", b"salt", 32).await?;
```

## API Reference

### Hashing Operations

```rust
// Blake3 hashing (recommended for performance)
let hash = engine.hash(data, HashFunction::Blake3).await?;

// SHA-256 hashing
let hash = engine.hash(data, HashFunction::Sha256).await?;

// SHA-3 hashing
let hash = engine.hash(data, HashFunction::Sha3_256).await?;
```

### Key Derivation

```rust
// Argon2id (recommended for password hashing)
let key = engine.derive_key(
    password, 
    salt, 
    32,  // 32-byte key
    KdfType::Argon2
).await?;

// PBKDF2 (fallback compatibility)
let key = engine.derive_key(
    password, 
    salt, 
    32,
    KdfType::Pbkdf2
).await?;
```

### Message Authentication

```rust
// HMAC with SHA-256
let mac = engine.mac(
    message_data,
    secret_key,
    MacType::HmacSha256
).await?;

// Poly1305 (fast and secure)
let mac = engine.mac(
    message_data,
    secret_key,
    MacType::Poly1305
).await?;
```

### Secure Random Generation

```rust
// Generate cryptographically secure random bytes
let random_data = engine.generate_random(32).await?;

// Generate random string
let random_string = engine.generate_random_string(16).await?;
```

## Security Considerations

### Memory Protection

Wolf Den implements secure memory handling for sensitive data:

```rust
use wolf_den::SecureBytes;

// Protected memory that's zeroized on drop
let protected = SecureBytes::new(sensitive_data, MemoryProtection::Strict);

// Use the protected data
let data_slice = protected.as_slice();

// Automatically zeroized when dropped
```

### Side-Channel Protection

- Constant-time operations for sensitive comparisons
- Memory zeroization for sensitive data
- Timing attack resistant implementations

### Algorithm Selection

- **Blake3**: Recommended for general hashing (fast, secure, modern)
- **Argon2id**: Recommended for password hashing (memory-hard)
- **HMAC-SHA256**: Recommended for MAC operations (widely supported)
- **Poly1305**: Recommended for high-performance MAC (fast, secure)

## Performance

### Benchmarks

| Operation | Algorithm | Performance (ops/sec) |
|-----------|-----------|---------------------|
| Hashing   | Blake3    | ~1,000,000          |
| Hashing   | SHA-256   | ~500,000            |
| KDF       | Argon2id  | ~1,000              |
| MAC       | Poly1305  | ~2,000,000          |
| Random    | CSPRNG    | ~10,000,000         |

### Optimization Tips

1. **Reuse CryptoEngine**: Create one instance and reuse it
2. **Choose Right Security Level**: Use Standard for most cases
3. **Blake3 for Hashing**: Fastest secure hash algorithm
4. **Batch Operations**: Process multiple items together when possible

## Configuration

### Builder Pattern

```rust
use wolf_den::CryptoEngineBuilder;

let engine = CryptoEngineBuilder::new()
    .security_level(SecurityLevel::High)
    .hash_function(HashFunction::Blake3)
    .kdf_type(KdfType::Argon2)
    .memory_protection(MemoryProtection::Strict)
    .build()?;
```

### Environment Variables

```bash
WOLF_DEN_SECURITY_LEVEL=standard
WOLF_DEN_HASH_FUNCTION=blake3
WOLF_DEN_KDF_TYPE=argon2
WOLF_DEN_MEMORY_PROTECTION=basic
```

## Error Handling

Wolf Den uses comprehensive error types for different failure modes:

```rust
use wolf_den::CryptoError;

match engine.hash(data, HashFunction::Blake3).await {
    Ok(hash) => println!("Hash: {}", hex::encode(hash)),
    Err(CryptoError::InvalidInput) => eprintln!("Invalid input data"),
    Err(CryptoError::MemoryError) => eprintln!("Memory allocation failed"),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Integration Examples

### Web Application

```rust
// Password hashing for user authentication
let password_hash = engine.derive_key(
    password.as_bytes(),
    user_salt.as_bytes(),
    32,
    KdfType::Argon2
).await?;

// Session token generation
let session_token = engine.generate_random(32).await?;
```

### API Security

```rust
// API request signing
let signature = engine.mac(
    request_body.as_bytes(),
    api_secret.as_bytes(),
    MacType::HmacSha256
).await?;

// Request verification
let is_valid = engine.verify_mac(
    received_signature,
    request_body.as_bytes(),
    api_secret.as_bytes(),
    MacType::HmacSha256
).await?;
```

## Testing

### Unit Tests

```bash
cargo test -p wolf_den
```

### Benchmarks

```bash
cargo bench -p wolf_den
```

### Security Tests

```bash
cargo test --features security_tests -p wolf_den
```

## Dependencies

- **blake3**: High-performance hashing
- **argon2**: Password hashing
- **ring**: Cryptographic primitives
- **zeroize**: Secure memory zeroization
- **rand**: Cryptographic random generation

## License

Wolf Den is licensed under the MIT License. See LICENSE.md for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Security Audit

Wolf Den has been designed with security in mind:

- ✅ Constant-time operations
- ✅ Memory zeroization
- ✅ Side-channel resistance
- ✅ Algorithm agility
- ✅ Comprehensive error handling

For security issues, please contact security@wolfprowler.org
