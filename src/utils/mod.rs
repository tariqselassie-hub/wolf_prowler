//! Utility modules for Wolf Prowler
//!
//! Shared utilities across the application:
//! - Logging infrastructure
//! - Metrics collection
//! - Configuration management
//! - Common helper functions

pub mod logging;
pub mod metrics_simple;

// Re-exports
pub use logging::Logger;
pub use metrics_simple::{Metrics, MetricsCollector};

/// Configuration manager for Wolf Prowler
pub struct ConfigManager {
    config: crate::core::AppSettings,
}

impl ConfigManager {
    /// Create new config manager with default configuration
    pub fn new() -> Self {
        Self {
            config: crate::core::AppSettings::default(),
        }
    }

    /// Load configuration from file
    pub fn load_from_file<P: AsRef<std::path::Path>>(
        _path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // AppSettings handles loading from settings.toml automatically
        let config = crate::core::AppSettings::new().map_err(|e| e.to_string())?;
        Ok(Self { config })
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<std::path::Path>>(
        &self,
        _path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(&self.config)?;
        std::fs::write("settings.toml", content)?;
        Ok(())
    }

    /// Get configuration reference
    pub fn config(&self) -> &crate::core::AppSettings {
        &self.config
    }

    /// Get mutable configuration reference
    pub fn config_mut(&mut self) -> &mut crate::core::AppSettings {
        &mut self.config
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}
