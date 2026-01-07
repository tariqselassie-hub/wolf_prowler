use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::Result;
use rand::{RngCore, thread_rng};

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("AES cipher creation failed: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("AES cipher creation failed: {}", e))?;
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = [0u8; 32];
        let data = b"WolfDb secure data";
        let (encrypted, nonce) = encrypt(data, &key).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, &key, &nonce).expect("Decryption failed");
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_aes_wrong_key() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let data = b"WolfDb secure data";
        let (encrypted, nonce) = encrypt(data, &key1).expect("Encryption failed");
        let result = decrypt(&encrypted, &key2, &nonce);
        assert!(result.is_err());
    }
}
