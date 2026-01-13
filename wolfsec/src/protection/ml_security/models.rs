use anyhow::Result;

/// Model registry
///
/// Manages registration and retrieval of ML models.
pub struct ModelRegistry;

impl ModelRegistry {
    /// Create new model registry
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}
