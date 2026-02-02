use anyhow::Result;
use fips204::ml_dsa_44; // ML-DSA-44 matches shared crate
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

// Constants matches fips204::ml_dsa_44
/// Length of the ML-DSA-44 secret key in bytes
pub const SK_SIZE: usize = 2560;
/// Length of the ML-DSA-44 public key in bytes
pub const PK_SIZE: usize = 1312;
/// Length of the ML-DSA-44 signature in bytes
pub const SIG_SIZE: usize = 2420;

/// A pair of ML-DSA-44 public and private keys
pub struct Keypair {
    /// The public key used for verification
    pub public: ml_dsa_44::PublicKey,
    /// The secret key used for signing
    pub secret: ml_dsa_44::PrivateKey,
}

impl Keypair {
    /// Signs a message using the secret key
    ///
    /// # Panics
    ///
    /// Panics if the signing operation fails.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.secret
            .try_sign(message, b"")
            .expect("Signing failed")
            .to_vec()
    }
}

/// Generates a new ML-DSA-44 keypair
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let (pk, sk) =
        ml_dsa_44::KG::try_keygen().map_err(|e| anyhow::anyhow!("Keygen failed: {e:?}"))?;
    Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec()))
}

/// Reconstructs a `Keypair` from raw bytes
///
/// # Errors
///
/// Returns an error if the key lengths are invalid or if key parsing fails.
///
/// # Panics
///
/// Panics if the internal length check fails after verification.
#[allow(clippy::expect_used)]
pub fn reconstruct_keypair(secret_key: &[u8], public_key: &[u8]) -> Result<Keypair> {
    if secret_key.len() != SK_SIZE {
        return Err(anyhow::anyhow!(
            "Invalid secret key length: expected {SK_SIZE}, got {}",
            secret_key.len()
        ));
    }
    if public_key.len() != PK_SIZE {
        return Err(anyhow::anyhow!(
            "Invalid public key length: expected {PK_SIZE}, got {}",
            public_key.len()
        ));
    }

    let sk_array: [u8; SK_SIZE] = secret_key.try_into().expect("Length checked");
    let pk_array: [u8; PK_SIZE] = public_key.try_into().expect("Length checked");

    let sk = ml_dsa_44::PrivateKey::try_from_bytes(sk_array)
        .map_err(|e| anyhow::anyhow!("Parse SK failed: {e:?}"))?;
    let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_array)
        .map_err(|e| anyhow::anyhow!("Parse PK failed: {e:?}"))?;

    Ok(Keypair {
        public: pk,
        secret: sk,
    })
}

/// Helper to sign a message given a Reconstructed Keypair
#[must_use]
pub fn sign_with_keypair(keys: &Keypair, message: &[u8]) -> Vec<u8> {
    keys.sign(message)
}

/// Sign a message using raw secret key bytes (Requires reconstruction)
///
/// # Errors
///
/// Returns an error as this legacy function is not supported.
pub fn sign_message(_message: &[u8], _secret_key: &[u8]) -> Result<Vec<u8>> {
    Err(anyhow::anyhow!(
        "Legacy signature not supported: strictly requires Keypair reconstruction with PK"
    ))
}

/// Verifies an ML-DSA-44 signature against a public key
///
/// # Errors
///
/// Returns an error if the public key cannot be parsed.
///
/// # Panics
///
/// Panics if the internal length check fails after verification.
#[allow(clippy::expect_used)]
pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    if public_key.len() != PK_SIZE {
        return Ok(false);
    }
    if signature.len() != SIG_SIZE {
        return Ok(false);
    }

    let pk_array: [u8; PK_SIZE] = public_key.try_into().expect("Length checked");
    let sig_array: [u8; SIG_SIZE] = signature.try_into().expect("Length checked");

    let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_array)
        .map_err(|_| anyhow::anyhow!("Invalid PK"))?;

    // Pass sig_array directly based on search result (Signature might be [u8; N])
    Ok(pk.verify(message, &sig_array, b""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn test_signature_flow() {
        let (sk, pk) = generate_keypair().expect("Keygen failed");
        let keys = reconstruct_keypair(&sk, &pk).expect("Reconstruct failed");

        let message = b"WolfDb integrity check";
        let sig = sign_with_keypair(&keys, message);
        let valid = verify_signature(message, &sig, &pk).expect("Verify failed");
        assert!(valid);
    }
}
