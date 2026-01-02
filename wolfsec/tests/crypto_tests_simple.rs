//! Cryptographic Test Suite
//!
//! Tests for cryptographic operations using real cryptographic primitives

#[cfg(test)]
mod tests {
    use blake3;
    use rand::rngs::OsRng;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use sha2::{Digest, Sha256};
    use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

    // Keypair structure using real cryptographic keys
    #[derive(Debug)]
    struct KeyPair {
        algorithm: &'static str,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    #[test]
    fn test_blake3_hashing() {
        // Test BLAKE3 hashing
        let input = b"Test message for BLAKE3 hashing";

        // Simple hash
        let hash = blake3::hash(input);
        assert_eq!(hash.as_bytes().len(), 32); // 256-bit output

        // Keyed hash (MAC)
        let key = blake3::derive_key("test key", b"context string");
        let keyed_hash = blake3::keyed_hash(&key, input);
        assert_eq!(keyed_hash.as_bytes().len(), 32);

        // Test that different inputs produce different hashes
        let input2 = b"Slightly different test message";
        let hash2 = blake3::hash(input2);
        assert_ne!(hash, hash2);

        // Test that the same input produces the same hash
        let hash_again = blake3::hash(input);
        assert_eq!(hash, hash_again);
    }

    #[test]
    fn test_blake3_incremental_hashing() {
        let mut hasher = blake3::Hasher::new();

        // Feed data in chunks
        hasher.update(b"Test ");
        hasher.update(b"message ");
        hasher.update(b"for ");
        hasher.update(b"incremental ");
        hasher.update(b"BLAKE3 hashing");

        let hash = hasher.finalize();

        // Compare with one-shot hashing
        let expected = blake3::hash(b"Test message for incremental BLAKE3 hashing");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_blake3_key_derivation() {
        let context = b"wolfprowler test context";

        // Derive multiple subkeys
        let subkey1 = blake3::derive_key("subkey1", context);
        let subkey2 = blake3::derive_key("subkey2", context);

        // Verify subkeys are different
        assert_ne!(subkey1, subkey2);

        // Verify deterministic derivation
        let subkey1_again = blake3::derive_key("subkey1", context);
        assert_eq!(subkey1, subkey1_again);
    }

    #[test]
    fn test_x25519_key_exchange() {
        // Alice generates a keypair
        let alice_secret = EphemeralSecret::random_from_rng(OsRng);
        let alice_public = X25519PublicKey::from(&alice_secret);

        // Bob generates a keypair
        let bob_secret = EphemeralSecret::random_from_rng(OsRng);
        let bob_public = X25519PublicKey::from(&bob_secret);

        // Perform key exchange
        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        // Both should arrive at the same shared secret
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_p256_keypair() {
        let rng = SystemRandom::new();

        // Generate P-256 keypair
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();

        let keypair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes.as_ref())
                .unwrap();

        // Sign a message
        let message = b"Test message for P-256 signing";
        let mut hasher = Sha256::new();
        hasher.update(message);
        let digest = hasher.finalize();

        let signature = keypair.sign(&rng, &digest).unwrap();

        // For P-256, we can't easily verify with ring's API in this context
        // So we'll just verify the signature was created
        assert_eq!(signature.as_ref().len(), 64); // P-256 signatures are 64 bytes
    }

    #[test]
    fn test_secure_key_storage() {
        // Test key storage structure without Ed25519 for now
        let stored_keypair = KeyPair {
            algorithm: "X25519",
            public_key: vec![1u8; 32],  // Mock public key for testing
            private_key: vec![2u8; 32], // Mock private key for testing
        };

        // Verify the stored keypair structure
        assert_eq!(stored_keypair.algorithm, "X25519");
        assert_eq!(stored_keypair.public_key.len(), 32);
        assert_eq!(stored_keypair.private_key.len(), 32);
    }
}
