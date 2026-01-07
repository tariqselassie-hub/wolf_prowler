use anyhow::Result;
pub use pqc_dilithium::Keypair;
use pqc_dilithium::verify;

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let keys = Keypair::generate();
    Ok((keys.expose_secret().to_vec(), keys.public.to_vec()))
}

pub fn reconstruct_keypair(secret_key: &[u8]) -> Result<Keypair> {
    let keys = Keypair::generate();
    if secret_key.len() != keys.expose_secret().len() {
        return Err(anyhow::anyhow!("Invalid secret key length"));
    }
    unsafe {
        let secret_ptr = keys.expose_secret().as_ptr() as *mut u8;
        std::ptr::copy_nonoverlapping(secret_key.as_ptr(), secret_ptr, secret_key.len());
    }
    Ok(keys)
}

pub fn sign_with_keypair(keys: &Keypair, message: &[u8]) -> Vec<u8> {
    keys.sign(message).to_vec()
}

pub fn sign_message(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let keys = reconstruct_keypair(secret_key)?;
    Ok(sign_with_keypair(&keys, message))
}

pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let res = verify(signature, message, public_key);
    Ok(res.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_flow() {
        let (sk, pk) = generate_keypair().expect("Keygen failed");
        let message = b"WolfDb integrity check";
        let sig = sign_message(message, &sk).expect("Sign failed");
        let valid = verify_signature(message, &sig, &pk).expect("Verify failed");
        assert!(valid);
    }

    #[test]
    fn test_invalid_signature() {
        let keys = Keypair::generate();
        let message = b"valid message";
        let mut sig = keys.sign(message);
        sig[0] ^= 0xFF; // Corrupt signature
        let valid = verify_signature(message, &sig, &keys.public).expect("Verify failed");
        assert!(!valid);
    }
}
