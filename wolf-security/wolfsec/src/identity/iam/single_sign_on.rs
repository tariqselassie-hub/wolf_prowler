use crate::identity::iam::IAMConfig;
use anyhow::Result;

/// Specialized authority for managing unified cross-domain authentication sessions
pub struct SingleSignOnManager;

impl SingleSignOnManager {
    /// Initializes a new `SingleSignOnManager`.
    ///
    /// # Errors
    /// Returns an error if initialization fails.
    pub fn new(_config: IAMConfig) -> Result<Self> {
        Ok(Self)
    }
}
