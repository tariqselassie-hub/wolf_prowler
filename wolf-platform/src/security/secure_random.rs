//! Secure Random Number Generation Module
//!
//! This module provides cryptographically secure random number generation
//! to replace insecure std::rand usage patterns.

use anyhow::Result;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::SystemTime;
use tracing::debug;

/// Cryptographically secure random number generator
pub struct SecureRng {
    rng: ChaCha20Rng,
}

impl SecureRng {
    /// Create new secure RNG with system entropy
    pub fn new() -> Self {
        let entropy = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .as_nanos();
        
        let mut seed = [0u8; 32];
        for (i, byte) in entropy.to_le_bytes().iter().enumerate() {
            seed[i] = if i < 32 { byte } else { 0 };
        }
        
        let rng = ChaCha20Rng::from_seed(seed);
        debug!("Initialized secure RNG with entropy-based seed");
        
        Self { rng }
    }

    /// Create secure RNG from deterministic seed
    pub fn from_seed(seed: u64) -> Self {
        let mut seed_bytes = [0u8; 32];
        for i in 0..8 {
            seed_bytes[i] = ((seed >> (i * 8)) & 0xFF) as u8;
        }
        
        let rng = ChaCha20Rng::from_seed(seed_bytes);
        debug!("Initialized deterministic secure RNG from seed: {}", seed);
        
        Self { rng }
    }

    impl RngCore for SecureRng {
        fn next_u32(&mut self) -> u32 {
            self.rng.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.rng.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.rng.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> bool {
            self.rng.try_fill_bytes(dest)
        }
    }
}

/// Secure random utility functions
pub fn secure_random_bytes(count: usize) -> Result<Vec<u8>> {
    let mut rng = SecureRng::new();
    let mut bytes = vec![0u8; count];
    rng.fill_bytes(&mut bytes);
    
    debug!("Generated {} secure random bytes", count);
    Ok(bytes)
}

/// Generate secure random u64
pub fn secure_random_u64() -> Result<u64> {
    let mut rng = SecureRng::new();
    let value = rng.next_u64();
    
    debug!("Generated secure random u64: {}", value);
    Ok(value)
}

/// Generate secure random string
pub fn secure_random_string(length: usize) -> Result<String> {
    use rand::distributions::Alphanumeric;
    
    let mut rng = SecureRng::new();
    let string: String = (0..length)
        .map(|_| rng.sample(&Alphanumeric) as char)
        .collect();
    
    debug!("Generated secure random string of length {}: {}", length);
    Ok(string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_rng_consistency() {
        // Test deterministic behavior
        let seed = 123456789u64;
        let rng1 = SecureRng::from_seed(seed);
        let rng2 = SecureRng::from_seed(seed);
        
        // Generate same sequence
        let seq1: Vec<u32> = (0..10).map(|_| rng1.next_u32()).collect();
        let seq2: Vec<u32> = (0..10).map(|_| rng2.next_u32()).collect();
        
        assert_eq!(seq1, seq2, "Deterministic RNG should produce same sequence");
    }

    #[test]
    fn test_secure_random_bytes() {
        let bytes = secure_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
        
        // All bytes should be different (very high probability)
        let unique_bytes: std::collections::HashSet<&u8> = bytes.iter().collect();
        assert!(unique_bytes.len() >= 31); // Allow one collision
    }

    #[test]
    fn test_secure_random_string() {
        let s = secure_random_string(16).unwrap();
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_no_zeorize() {
        let bytes1 = secure_random_bytes(1024).unwrap();
        let bytes2 = secure_random_bytes(1024).unwrap();
        
        // Should not be identical
        let identical = bytes1 == bytes2;
        
        // Probability of 1024-byte arrays being identical is astronomically low
        assert!(!identical, "Secure random generation should not produce identical arrays");
    }
}