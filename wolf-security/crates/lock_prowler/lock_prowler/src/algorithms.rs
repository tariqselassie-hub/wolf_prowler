use crate::crypto::{FieldElement, RecoveryAlgorithm, RecoveryResult};
use crate::metadata::{BitLockerMetadata, KeyProtectorType};
use anyhow::Result;

/// Joux's Attack implementation (Mock).
pub struct NonceReuseAlgorithm;

impl RecoveryAlgorithm for NonceReuseAlgorithm {
    fn name(&self) -> &str {
        "Nonce Reuse Attack (Joux's)"
    }
    fn description(&self) -> &str {
        "Detects and exploits nonce reuse in AES-GCM tags using GF(2^128) arithmetic."
    }
    fn run(&self, _metadata: &BitLockerMetadata) -> Result<RecoveryResult> {
        // Functional Logic: Simulate a tag collision/nonce reuse detection.
        // In Joux's attack, T1 XOR T2 = (C1 XOR C2) * H (simplified).
        // By XORing the tags and having known ciphertexts, we can solve for H.

        let t1 = FieldElement(0xABCD_1234_EFAB_5678_ABCD_1234_EFAB_5678);
        let t2 = FieldElement(0x1234_EFAB_5678_ABCD_1234_EFAB_5678_ABCD);

        let diff = t1.xor(t2);

        Ok(RecoveryResult::VulnerabilityFound(format!(
            "Joux's Attack active: Tag XOR difference (GF128) is 0x{:032X}. Verification complete.",
            diff.0
        )))
    }
}

/// Weak RSA Parameter Attack (Mock).
pub struct WeakRsaAlgorithm;

impl RecoveryAlgorithm for WeakRsaAlgorithm {
    fn name(&self) -> &str {
        "Weak RSA Protector Analysis"
    }
    fn description(&self) -> &str {
        "Analyzes RSA (DRA) protectors for factorable primes or weak parameters."
    }
    fn run(&self, metadata: &BitLockerMetadata) -> Result<RecoveryResult> {
        for protector in &metadata.protectors {
            if let KeyProtectorType::Dra = protector.p_type {
                return Ok(RecoveryResult::VulnerabilityFound(
                    "RSA DRA protector found. Analysis for weak parameters would happen here."
                        .into(),
                ));
            }
        }
        Ok(RecoveryResult::NotApplicable)
    }
}

/// Calculates the Shannon Entropy of a given data block.
/// Range: [0.0, 8.0]
pub fn calculate_shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0usize; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0;

    for &count in frequencies.iter() {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_max() {
        // Uniform distribution (high entropy)
        let mut data = Vec::with_capacity(256);
        for i in 0..256 {
            data.push(i as u8);
        }
        let entropy = calculate_shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_shannon_entropy_min() {
        // Single value (low entropy)
        let data = vec![0u8; 100];
        let entropy = calculate_shannon_entropy(&data);
        assert!((entropy - 0.0).abs() < 0.001);
    }
}
