# Wolf Den Integration Guide

This guide explains how to use the Wolf Den cryptographic library integrated with Wolf Prowler.

## Overview

Wolf Den is a state-of-the-art cryptographic foundation that provides enterprise-grade security with a focus on performance, memory safety, and resistance to side-channel attacks. The integration with Wolf Prowler allows you to leverage these advanced cryptographic features in your P2P networking applications.

## Features

### Core Cryptographic Primitives
- **Authenticated Encryption**: ChaCha20-Poly1305, AES-256-GCM, AES-128-GCM
- **Key Exchange**: X25519, P-256, P-384, secp256k1
- **Digital Signatures**: Ed25519, ECDSA (P-256, P-384, secp256k1)
- **Hash Functions**: BLAKE3, SHA-2, SHA-3 families
- **Message Authentication**: HMAC, Poly1305

### Advanced Security Features
- **Perfect Forward Secrecy**: Automatic key rotation and ratcheting
- **Memory Protection**: Secure memory allocation and zeroization
- **Side-Channel Resistance**: Constant-time operations
- **Secure Randomness**: Multiple entropy sources with fallbacks
- **Key Derivation**: HKDF, PBKDF2, scrypt, Argon2
- **Identity Management**: Decentralized identity and authentication

## Quick Start

### Installation

Wolf Den is included as a local dependency in Wolf Prowler. No additional installation is required.

### Basic Usage

```rust
use wolf_prowler::{
    Config, CryptoConfig, WolfDenAdapterFactory
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration with Wolf Den enabled
    let config = Config {
        crypto: CryptoConfig {
            use_wolf_den: true,
            use_wolf_den_extended: true,
            cipher_suite: "ChaCha20Poly1305".to_string(),
            hash_function: "Blake3".to_string(),
            memory_protection: "Strict".to_string(),
        },
        ..Config::default()
    };

    // Create Wolf Den adapter
    let crypto_ops = WolfDenAdapterFactory::create_from_config(&config).await?;

    // Use cryptographic operations
    let plaintext = b"Hello, Wolf Den!";
    let key_pair = wolf_den::crypto::global_crypto_engine()
        .generate_key_pair(wolf_den::KeyType::X25519)
        .await?;

    // Encrypt
    let ciphertext = crypto_ops.encrypt(plaintext, key_pair.public_key()).await?;

    // Decrypt
    let decrypted = crypto_ops.decrypt(&ciphertext, key_pair.private_key()).await?;

    assert_eq!(plaintext.to_vec(), decrypted);
    Ok(())
}
```

## Integration Methods

### Method 1: Wolf Den Adapter Factory

The factory provides a simple way to create Wolf Den adapters based on configuration:

```rust
use wolf_prowler::{WolfDenAdapterFactory, Config};

// Create from configuration
let config = Config::default();
let crypto_ops = WolfDenAdapterFactory::create_from_config(&config).await?;

// Create basic adapter
let basic = WolfDenAdapterFactory::create_basic(crypto_config).await?;

// Create extended adapter
let extended = WolfDenAdapterFactory::create_extended(crypto_config).await?;
```

### Method 2: CryptoEngine Integration

Integrate Wolf Den with the existing CryptoEngine:

```rust
use wolf_prowler::{CryptoEngine, WolfDenAdapter};

// Create CryptoEngine
let engine = CryptoEngine::new(crypto_config).await?;

// Create Wolf Den adapter
let wolf_den_adapter = engine.create_wolf_den_adapter().await?;

// Create extended adapter
let extended_adapter = engine.create_extended_wolf_den_adapter().await?;
```

### Method 3: Direct Wolf Den Usage

Access Wolf Den features directly through the adapter:

```rust
use wolf_prowler::WolfDenAdapter;

let adapter = WolfDenAdapter::new(config).await?;
let engine = adapter.engine();

// Direct access to Wolf Den engine
let random_bytes = engine.generate_random_bytes(32).await?;
let hash = engine.hash(b"data").await?;
let health = engine.health_check().await?;
let stats = engine.get_stats().await?;
```

## Configuration

### Configuration Options

```rust
pub struct CryptoConfig {
    /// Enable Wolf Den cryptographic backend
    pub use_wolf_den: bool,
    /// Use extended Wolf Den features
    pub use_wolf_den_extended: bool,
    /// Default cipher suite
    pub cipher_suite: String,
    /// Default hash function
    pub hash_function: String,
    /// Memory protection level
    pub memory_protection: String,
}
```

### Supported Cipher Suites
- `"ChaCha20Poly1305"` - Modern, fast, secure
- `"AES256GCM"` - Industry standard
- `"AES128GCM"` - Faster but less secure

### Supported Hash Functions
- `"Blake3"` - Modern, fast, secure
- `"SHA256"` - Industry standard
- `"SHA512"` - Higher security
- `"SHA3_256"` - SHA-3 family
- `"SHA3_512"` - SHA-3 family

### Memory Protection Levels
- `"None"` - No additional protection
- `"Basic"` - Basic zeroization
- `"Strict"` - Memory locking and strict protection
- `"Maximum"` - Maximum protection available

## Advanced Features

### Extended Wolf Den Adapter

The extended adapter provides additional features:

```rust
use wolf_prowler::ExtendedWolfDenAdapter;

let adapter = ExtendedWolfDenAdapter::new(config).await?;

// Generate and store key pairs
let key_pair = adapter.generate_key_pair(KeyType::Ed25519).await?;

// Create identities
let identity = adapter.create_identity(key_pair.clone()).await?;

// Create secure sessions
let session = adapter.create_secure_session(key_pair).await?;

// Access keystore
let keystore = adapter.keystore();
let key_count = keystore.read().await.key_count().await;

// Access identity manager
let identity_manager = adapter.identity_manager();
let identities = identity_manager.read().await.list_identities().await?;
```

### Secure Sessions

Wolf Den provides secure session management:

```rust
let session = adapter.create_secure_session(key_pair).await?;

// Encrypt messages
let message = b"Secure message";
let encrypted = session.encrypt_message(message).await?;

// Decrypt messages
let decrypted = session.decrypt_message(&encrypted).await?;
```

### Identity Management

Manage decentralized identities:

```rust
// Create identity
let identity = adapter.create_identity(key_pair).await?;

// Retrieve identity
let retrieved = adapter.get_identity(&identity.id).await?;

// Verify identity
let verified = adapter.identity_manager()
    .read()
    .await
    .verify_identity(&identity.id).await?;
```

### Key Store

Securely manage cryptographic keys:

```rust
// Generate and store key
let key_pair = adapter.generate_key_pair(KeyType::Ed25519).await?;

// List stored keys
let keystore = adapter.keystore();
let key_ids = keystore.read().await.list_keys().await?;

// Retrieve stored key
if let Some(key_id) = key_ids.first() {
    let key_pair = keystore.read().await.get_key_pair(key_id).await?;
}
```

## Performance and Security

### Performance Characteristics

| Operation | Performance | Security Level |
|-----------|-------------|----------------|
| ChaCha20-Poly1305 | ~1.5 GB/s | 256-bit |
| AES-256-GCM | ~2.0 GB/s | 256-bit |
| BLAKE3 | ~3.0 GB/s | 256-bit |
| X25519 | ~100K ops/s | 256-bit |
| Ed25519 | ~50K ops/s | 256-bit |

### Security Features

1. **Memory Safety**: All sensitive data stored in protected memory
2. **Constant-Time**: All cryptographic operations are constant-time
3. **Forward Secrecy**: Automatic key rotation and ratcheting
4. **Side-Channel Resistance**: Resistance to timing and cache attacks
5. **Fail-Safe**: All operations fail securely without leaking information

## Error Handling

Wolf Den integration provides comprehensive error handling:

```rust
use wolf_prowler::core::Error;

match crypto_ops.encrypt(plaintext, public_key).await {
    Ok(ciphertext) => println!("Encryption successful"),
    Err(Error::Crypto(msg)) => eprintln!("Crypto error: {}", msg),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Testing

Run the integration tests:

```bash
# Run all tests
cargo test

# Run Wolf Den integration tests specifically
cargo test wolf_den_integration

# Run with output
cargo test -- --nocapture wolf_den_integration
```

Run the example:

```bash
cargo run --example wolf_den_integration
```

## Best Practices

### 1. Use Wolf Den by Default

```rust
let config = Config {
    crypto: CryptoConfig {
        use_wolf_den: true, // Enable for better security
        use_wolf_den_extended: true, // Enable for advanced features
        ..Default::default()
    },
    ..Config::default()
};
```

### 2. Choose Appropriate Security Levels

```rust
let crypto_config = CryptoConfig {
    cipher_suite: "ChaCha20Poly1305".to_string(), // Modern and fast
    hash_function: "Blake3".to_string(), // Modern and fast
    memory_protection: "Strict".to_string(), // Good security/performance balance
    ..Default::default()
};
```

### 3. Use Extended Features When Needed

```rust
// For applications needing identity management
let adapter = ExtendedWolfDenAdapter::new(config).await?;

// For simple cryptographic operations
let adapter = WolfDenAdapter::new(config).await?;
```

### 4. Handle Errors Gracefully

```rust
match crypto_ops.encrypt(data, public_key).await {
    Ok(encrypted) => {
        // Process encrypted data
    }
    Err(e) => {
        log::error!("Encryption failed: {}", e);
        // Handle error appropriately
    }
}
```

### 5. Use Secure Sessions for Communication

```rust
let session = adapter.create_secure_session(key_pair).await?;

// Session provides automatic key rotation and perfect forward secrecy
let encrypted = session.encrypt_message(message).await?;
```

## Migration Guide

### From Existing Crypto Implementation

1. **Update Configuration**:
   ```rust
   let config = Config {
       crypto: CryptoConfig {
           use_wolf_den: true,
           ..Default::default()
       },
       ..Config::default()
   };
   ```

2. **Replace Crypto Operations**:
   ```rust
   // Old
   let encrypted = old_crypto.encrypt(plaintext, key)?;
   
   // New
   let crypto_ops = WolfDenAdapterFactory::create_from_config(&config).await?;
   let encrypted = crypto_ops.encrypt(plaintext, key).await?;
   ```

3. **Add Advanced Features**:
   ```rust
   let extended_adapter = ExtendedWolfDenAdapter::new(config).await?;
   let session = extended_adapter.create_secure_session(key_pair).await?;
   ```

## Troubleshooting

### Common Issues

1. **Compilation Errors**: Ensure all dependencies are properly configured
2. **Runtime Errors**: Check configuration values are valid
3. **Performance Issues**: Use appropriate cipher suites and security levels

### Debugging

Enable debug logging:

```rust
env_logger::init();
```

Use health checks:

```rust
let health = adapter.health_check().await?;
if !health.is_healthy() {
    eprintln!("Wolf Den health check failed: {:?}", health);
}
```

## Examples

See the `examples/` directory for complete examples:

- `wolf_den_integration.rs` - Comprehensive integration example
- Basic usage patterns
- Advanced features demonstration

## API Reference

For complete API documentation, see:

- [Wolf Den API Documentation](../wolf_den/README.md)
- [Wolf Prowler API Documentation](../README.md)

## Support

For issues and questions:

1. Check the test cases for usage examples
2. Review the integration example
3. Consult the Wolf Den documentation
4. Check the error messages for specific issues

---

**Built with ❤️ by the Wolf Prowler team**

> *In the digital wilderness, security is our den.*
