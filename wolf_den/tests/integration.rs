//! Integration tests for Wolf Den
//!
//! Verifies the full cryptographic lifecycle including engine initialization,
//! identity persistence, signing, hashing, and encryption.

use wolf_den::{CryptoEngine, SecurityLevel};

#[test]
fn test_full_crypto_lifecycle() {
    // 1. Initialize Engine
    let engine = CryptoEngine::new(SecurityLevel::Standard).expect("Failed to init engine");

    // 2. Identity & Store
    let identity = engine.export_identity();
    assert_eq!(identity.len(), 32);

    let restored_engine = CryptoEngine::with_keypair(SecurityLevel::Standard, &identity)
        .expect("Failed to restore engine");

    // 3. Signing
    let message = b"Critical System Update";
    let signature = engine.sign_message(message);
    let public_key = engine.get_public_key();

    // Verify with restored engine (proving identity persistence)
    assert!(restored_engine
        .verify_signature(message, &signature, &public_key)
        .is_ok());

    // 4. Hashing
    let hash = engine.hash(message).unwrap();
    assert_eq!(hash.len(), 32);

    // 5. Encryption (Symmetric)
    // Note: CryptoEngine doesn't directly expose symmetric encryption yet,
    // it's exposed via `wolf_den::symmetric::create_cipher`.
    // But we can test the lower level API here too since it's an integration test.

    use wolf_den::{symmetric::create_cipher, CipherSuite};
    let cipher = create_cipher(CipherSuite::ChaCha20Poly1305, SecurityLevel::Standard).unwrap();
    let key = cipher.generate_key().unwrap();
    let nonce = vec![0u8; cipher.nonce_length()];

    let ciphertext = cipher.encrypt(message, &key, &nonce).unwrap();
    let decrypted = cipher.decrypt(&ciphertext, &key, &nonce).unwrap();

    assert_eq!(message.to_vec(), decrypted);
}
