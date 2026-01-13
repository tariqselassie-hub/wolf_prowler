use crate::protection::cloud_security::CloudSecurityConfig;
use anyhow::Result;

/// Cloud data protection manager
pub struct CloudDataProtectionManager;

impl CloudDataProtectionManager {
    /// Create new data protection manager
    pub fn new(_config: CloudSecurityConfig) -> Result<Self> {
        Ok(Self)
    }
}
