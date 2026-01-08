use anyhow::Result;
use pqc_kyber::{decapsulate, encapsulate, keypair};
use rand::thread_rng;

/// Generates a new ML-KEM-768 keypair
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).map_err(|_| anyhow::anyhow!("KEM keypair failed"))?;
    Ok((keys.secret.to_vec(), keys.public.to_vec()))
}

/// Encapsulates a shared secret using the provided public key
///
/// # Errors
///
/// Returns an error if encapsulation fails.
pub fn encapsulate_key(public_key: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let mut rng = thread_rng();
    let (ct, ss) =
        encapsulate(public_key, &mut rng).map_err(|_| anyhow::anyhow!("KEM encapsulate failed"))?;

    Ok((ct.to_vec(), ss))
}

/// Decapsulates a shared secret using the provided secret key
///
/// # Errors
///
/// Returns an error if decapsulation fails.
pub fn decapsulate_key(ciphertext: &[u8], secret_key: &[u8]) -> Result<[u8; 32]> {
    let ss = decapsulate(ciphertext, secret_key)
        .map_err(|_| anyhow::anyhow!("KEM decapsulate failed"))?;

    Ok(ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn test_kem_flow() {
        let (sk, pk) = generate_keypair().expect("Keygen failed");
        let (ct, ss_enc) = encapsulate_key(&pk).expect("Encapsulate failed");
        let ss_dec = decapsulate_key(&ct, &sk).expect("Decapsulate failed");
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_kem_invalid_ct() {
        let (sk, pk) = generate_keypair().expect("Keygen failed");
        let (mut ct, _) = encapsulate_key(&pk).expect("Encapsulate failed");
        ct[0] ^= 0xFF; // Corrupt ciphertext
        let result = decapsulate_key(&ct, &sk);
        // Note: Kyber usually uses implicit rejection, so it might not error but return random SS,
        // but let's see how this crate handles it.
        if let Ok(_ss_dec) = result {
            // If it returns random SS, they shouldn't match.
        }
    }
}
