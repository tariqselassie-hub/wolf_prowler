use crate::security::advanced::iam::IAMConfig;
use anyhow::Result;

pub struct IdentityProviderManager;

impl IdentityProviderManager {
    pub fn new(_config: IAMConfig) -> Result<Self> {
        Ok(Self)
    }
}
