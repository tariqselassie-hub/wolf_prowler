use anyhow::Result;
use cryptoki::context::Pkcs11;
use cryptoki::session::UserType;
use secrecy::Secret;
use std::path::Path;

#[allow(dead_code)]
pub struct HsmProvider {
    pkcs11: Pkcs11,
}

#[allow(dead_code)]
impl HsmProvider {
    pub fn new(library_path: &Path) -> Result<Self> {
        let pkcs11 = Pkcs11::new(library_path)?;
        pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads)?;
        Ok(Self { pkcs11 })
    }

    pub fn wrap_key(&self, _slot_id: u64, pin: &str, plaintext_key: &[u8]) -> Result<Vec<u8>> {
        let slots = self.pkcs11.get_slots_with_token()?;
        let slot = slots
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("No HSM slots found"))?;

        let session = self.pkcs11.open_rw_session(*slot)?;
        let secret_pin = Secret::new(pin.to_string());
        session.login(UserType::User, Some(&secret_pin))?;

        // Mock wrapping for prototype:
        let mut wrapped = vec![b'H', b'W'];
        wrapped.extend_from_slice(plaintext_key);

        session.logout()?;
        Ok(wrapped)
    }

    pub fn unwrap_key(&self, _slot_id: u64, pin: &str, wrapped_key: &[u8]) -> Result<Vec<u8>> {
        let slots = self.pkcs11.get_slots_with_token()?;
        let slot = slots
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("No HSM slots found"))?;

        let session = self.pkcs11.open_rw_session(*slot)?;
        let secret_pin = Secret::new(pin.to_string());
        session.login(UserType::User, Some(&secret_pin))?;

        if !wrapped_key.starts_with(b"HW") {
            return Err(anyhow::anyhow!("Invalid hardware-wrapped key format"));
        }

        let unwrapped = wrapped_key[2..].to_vec();

        session.logout()?;
        Ok(unwrapped)
    }
}

pub struct MockHsm;

impl MockHsm {
    pub fn wrap(password: &str, key: &[u8]) -> Vec<u8> {
        let mut out = vec![b'H', b'W'];
        for (i, b) in key.iter().enumerate() {
            let p_byte = password.as_bytes()[i % password.len()];
            out.push(b ^ p_byte);
        }
        out
    }

    pub fn unwrap(password: &str, wrapped: &[u8]) -> Result<Vec<u8>> {
        if !wrapped.starts_with(b"HW") {
            return Err(anyhow::anyhow!("Not a hardware-wrapped key"));
        }
        let mut out = Vec::new();
        for (i, b) in wrapped[2..].iter().enumerate() {
            let p_byte = password.as_bytes()[i % password.len()];
            out.push(b ^ p_byte);
        }
        Ok(out)
    }
}
