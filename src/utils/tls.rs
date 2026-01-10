use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;
use tracing::{error, info, warn};

/// Configuration for TLS certificates.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl TlsConfig {
    /// Loads TLS configuration based on environment variables.
    ///
    /// # Behavior
    /// - Checks `WOLF_TLS_CERT` and `WOLF_TLS_KEY`.
    /// - If present, validates existence on disk.
    /// - If missing:
    ///     - **Release Mode**: Returns Error (Enforce Production TLS).
    ///     - **Debug Mode**: Returns `Ok(None)` (Allow self-signed fallback).
    pub fn from_env() -> Result<Option<Self>> {
        let cert_var = env::var("WOLF_TLS_CERT").ok();
        let key_var = env::var("WOLF_TLS_KEY").ok();

        match (cert_var, key_var) {
            (Some(c), Some(k)) => {
                let cert_path = PathBuf::from(c);
                let key_path = PathBuf::from(k);

                if !cert_path.exists() {
                    bail!("Production TLS Certificate not found at: {:?}", cert_path);
                }
                if !key_path.exists() {
                    bail!("Production TLS Key not found at: {:?}", key_path);
                }

                info!("Loaded Production TLS config from environment.");
                Ok(Some(Self { cert_path, key_path }))
            }
            (None, None) => {
                if cfg!(not(debug_assertions)) {
                    error!("CRITICAL: WOLF_TLS_CERT and WOLF_TLS_KEY are missing in production!");
                    bail!("TLS Configuration Required for Production Start. Self-signed certs are disabled.");
                } else {
                    warn!("TLS environment variables missing. Falling back to self-signed generation (DEV ONLY).");
                    Ok(None)
                }
            }
            _ => bail!("Invalid Configuration: Both WOLF_TLS_CERT and WOLF_TLS_KEY must be provided together."),
        }
    }
}
