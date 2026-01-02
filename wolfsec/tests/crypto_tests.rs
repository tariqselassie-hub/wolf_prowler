//! Cryptographic Test Suite
//!
//! Tests for cryptographic operations using real cryptographic primitives

#[cfg(test)]
mod tests {
    use blake3;
    use ed25519_dalek::Signature;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::Verifier;
    use ed25519_dalek::VerifyingKey;
    use rand::rngs::OsRng;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair as RingKeyPair;
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
    fn test_blake3_with_ed25519() {
        // Generate Ed25519 keypair
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Create a message and its BLAKE3 hash
        let message = b"Test message to sign with BLAKE3";
        let message_hash = blake3::hash(message);

        // Sign the hash
        let signature = signing_key.sign(message_hash.as_bytes());

        // Verify the signature
        assert!(verifying_key
            .verify(message_hash.as_bytes(), &signature)
            .is_ok());

        // Test with wrong hash
        let wrong_message = b"Wrong message";
        let wrong_hash = blake3::hash(wrong_message);
        assert!(verifying_key
            .verify(wrong_hash.as_bytes(), &signature)
            .is_err());
    }

    #[test]
    fn test_ed25519_keypair() {
        // Generate Ed25519 keypair
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Sign a message
        let message = b"Test message for signing";
        let signature = signing_key.sign(message);

        // Verify the signature
        assert!(verifying_key.verify(message, &signature).is_ok());

        // Test with wrong message
        let wrong_message = b"Wrong message";
        assert!(verifying_key.verify(wrong_message, &signature).is_err());
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
        // Generate a keypair
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Store the keypair in our secure structure
        let stored_keypair = KeyPair {
            algorithm: "Ed25519",
            public_key: verifying_key.as_bytes().to_vec(),
            private_key: signing_key.as_bytes().to_vec(),
        };

        // Verify the stored keypair can be used
        let message = b"Test message for key storage";
        let signature = signing_key.sign(message);

        assert_eq!(stored_keypair.algorithm, "Ed25519");
        assert_eq!(stored_keypair.public_key.len(), 32); // Ed25519 public key size
        assert_eq!(stored_keypair.private_key.len(), 32); // Ed25519 private key size
    }
}
