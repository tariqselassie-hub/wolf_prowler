use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl TlsConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        if let (Ok(cert), Ok(key)) = (
            std::env::var("WOLF_TLS_CERT"),
            std::env::var("WOLF_TLS_KEY"),
        ) {
            Ok(Some(Self {
                cert_path: PathBuf::from(cert),
                key_path: PathBuf::from(key),
            }))
        } else {
            Ok(None)
        }
    }
}
