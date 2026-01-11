//! Cryptographic utilities for Air Gap Bridge

use crate::error::{AirGapError, Result};
use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Verifier};

/// Length of the ML-DSA-44 public key in bytes
pub const PK_SIZE: usize = 1312;
/// Length of the ML-DSA-44 signature in bytes
pub const SIG_SIZE: usize = 2420;

/// Verify signature using FIPS204 (ML-DSA-44)
///
/// # Errors
/// Returns an error if the input is invalid or key parsing fails.
pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    if data.is_empty() {
        return Err(AirGapError::Crypto("Data is empty".to_string()));
    }

    if public_key.len() != PK_SIZE {
        return Err(AirGapError::Crypto(format!(
            "Invalid public key length: expected {PK_SIZE}, got {}",
            public_key.len()
        )));
    }

    if signature.len() != SIG_SIZE {
        return Err(AirGapError::Crypto(format!(
            "Invalid signature length: expected {SIG_SIZE}, got {}",
            signature.len()
        )));
    }

    let pk_array: [u8; PK_SIZE] = public_key
        .try_into()
        .map_err(|_| AirGapError::Crypto("Failed to convert public key to array".to_string()))?;

    let sig_array: [u8; SIG_SIZE] = signature
        .try_into()
        .map_err(|_| AirGapError::Crypto("Failed to convert signature to array".to_string()))?;

    let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_array)
        .map_err(|e| AirGapError::Crypto(format!("Failed to parse public key: {e:?}")))?;

    Ok(pk.verify(data, &sig_array, b""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::{KeyGen, Signer};

    #[test]
    fn test_verify_signature_valid() {
        // Generate keypair
        let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
        let message = b"Hello, World!";

        // Sign message
        let sig = sk.try_sign(message, b"").unwrap();

        // Verify using our function
        let pk_bytes = pk.into_bytes();
        let sig_bytes = sig;

        let result = verify_signature(message, &sig_bytes, &pk_bytes);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_signature_invalid_signature() {
        let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
        let message = b"Hello, World!";
        let sig = sk.try_sign(message, b"").unwrap();

        let pk_bytes = pk.into_bytes();
        let mut sig_bytes = sig;

        // Tamper with signature
        sig_bytes[0] ^= 0xFF;

        let result = verify_signature(message, &sig_bytes, &pk_bytes);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_signature_invalid_message() {
        let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
        let message = b"Hello, World!";
        let sig = sk.try_sign(message, b"").unwrap();

        let pk_bytes = pk.into_bytes();
        let sig_bytes = sig;

        let wrong_message = b"Goodbye, World!";

        let result = verify_signature(wrong_message, &sig_bytes, &pk_bytes);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_signature_invalid_lengths() {
        let message = b"test";
        let valid_sig = [0u8; SIG_SIZE];
        let valid_pk = [0u8; PK_SIZE];

        // Invalid PK length
        let result = verify_signature(message, &valid_sig, &[0u8; PK_SIZE - 1]);
        assert!(
            matches!(result, Err(AirGapError::Crypto(msg)) if msg.contains("Invalid public key length"))
        );

        // Invalid Sig length
        let result = verify_signature(message, &[0u8; SIG_SIZE - 1], &valid_pk);
        assert!(
            matches!(result, Err(AirGapError::Crypto(msg)) if msg.contains("Invalid signature length"))
        );
    }

    #[test]
    fn test_verify_signature_empty_data() {
        let result = verify_signature(&[], &[0u8; SIG_SIZE], &[0u8; PK_SIZE]);
        assert!(matches!(result, Err(AirGapError::Crypto(msg)) if msg.contains("Data is empty")));
    }
}
