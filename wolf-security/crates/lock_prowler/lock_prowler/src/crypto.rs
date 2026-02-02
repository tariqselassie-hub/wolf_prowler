use crate::metadata::BitLockerMetadata;
use anyhow::Result;

/// Represents an element in the Galois Field GF(2^128) using polynomial representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement(pub u128);

impl FieldElement {
    /// Multiplies two elements in GF(2^128) using the GCM polynomial: x^128 + x^7 + x^2 + x + 1.
    pub fn multiply(self, other: FieldElement) -> FieldElement {
        let mut a = self.0;
        let mut b = other.0;
        let mut r = 0u128;

        for _ in 0..128 {
            if (b & 1) != 0 {
                r ^= a;
            }
            let overflow = (a & (1 << 127)) != 0;
            a <<= 1;
            if overflow {
                // Reduction polynomial for GCM
                a ^= 0x00000000000000000000000000000087;
            }
            b >>= 1;
        }
        FieldElement(r)
    }

    pub fn xor(self, other: FieldElement) -> FieldElement {
        FieldElement(self.0 ^ other.0)
    }
}

/// The outcome of an attempted recovery algorithm.
#[derive(Debug)]
pub enum RecoveryResult {
    /// A potential key or subkey was found.
    Success { key: Vec<u8>, message: String },
    /// a vulnerability was detected, but no key material was recovered.
    VulnerabilityFound(String),
    /// The algorithm is not applicable to the given metadata.
    NotApplicable,
}

/// Trait for BitLocker recovery algorithms.
pub trait RecoveryAlgorithm {
    /// The unique name of the algorithm.
    fn name(&self) -> &str;

    /// A brief description of what the algorithm does.
    fn description(&self) -> &str;

    /// Executes the recovery algorithm against the provided metadata.
    fn run(&self, metadata: &BitLockerMetadata) -> Result<RecoveryResult>;
}

/// A registry or runner for multiple recovery algorithms.
pub struct AlgorithmRunner {
    algorithms: Vec<Box<dyn RecoveryAlgorithm>>,
}

impl AlgorithmRunner {
    pub fn new() -> Self {
        Self {
            algorithms: Vec::new(),
        }
    }

    pub fn register(&mut self, algo: Box<dyn RecoveryAlgorithm>) {
        self.algorithms.push(algo);
    }

    pub fn run_all(&self, metadata: &BitLockerMetadata) {
        println!(
            "\nAttempting recovery with {} algorithms...",
            self.algorithms.len()
        );
        for algo in &self.algorithms {
            println!("--- Running: {} ---", algo.name());
            match algo.run(metadata) {
                Ok(RecoveryResult::Success { key, message }) => {
                    println!("[SUCCESS] {}", message);
                    println!("Recovered Key: {}", hex::encode(key));
                }
                Ok(RecoveryResult::VulnerabilityFound(msg)) => {
                    println!("[WARNING] Vulnerability Detected: {}", msg);
                }
                Ok(RecoveryResult::NotApplicable) => {
                    println!("[INFO] Not applicable.");
                }
                Err(e) => {
                    println!("[ERROR] Algorithm failed: {}", e);
                }
            }
        }
    }
}
