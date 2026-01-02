use crate::security::advanced::iam::IAMConfig;
use anyhow::Result;

pub struct SingleSignOnManager;

impl SingleSignOnManager {
    pub fn new(_config: IAMConfig) -> Result<Self> {
        Ok(Self)
    }
}
