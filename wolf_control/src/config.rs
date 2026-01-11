use reqwest::tls::Identity;
use reqwest::Certificate;
// Use Wolf Den cert helpers for generating dev self-signed certs
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wolf_den::certs::generate_self_signed_cert;
use wolfsec::network_security::{SecurityManager, MEDIUM_SECURITY};

/// Wrapper for system-wide identity components
#[derive(Default)]
pub struct WolfIdentity {
    pub client: Option<Identity>,
    pub ca: Option<Certificate>,
    pub p2p_keypair: Option<Keypair>,
    pub security_manager: Option<SecurityManager>,
}

impl std::fmt::Debug for WolfIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WolfIdentity")
            .field("client", &self.client.is_some())
            .field("ca", &self.ca.is_some())
            .field("p2p_keypair", &self.p2p_keypair.is_some())
            .field("security_manager", &self.security_manager.is_some())
            .finish()
    }
}

/// Configuration for the Wolf Control TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// API server address (including port).
    pub api_url: String,
    /// Refresh interval for UI polling (seconds).
    pub poll_interval_secs: u64,
    /// Enable verbose logging.
    pub verbose: bool,
    /// UI Theme (dark/light)
    pub theme: String,
    /// Show timestamps in logs
    pub show_timestamps: bool,
    /// Auto-scroll logs
    pub auto_scroll_logs: bool,
    /// Maximum number of connection retries
    pub max_retries: u32,
    /// Accept invalid (self-signed) SSL certificates
    pub accept_invalid_certs: bool,
    /// Admin password for API authentication
    pub admin_password: String,
    /// Path to the client certificate file (PEM)
    pub client_cert: Option<String>,
    /// Path to the client key file (PEM)
    pub client_key: Option<String>,
    /// Path to the CA certificate file (PEM)
    pub ca_cert: Option<String>,
    /// API request timeout in seconds
    pub api_timeout_secs: u64,
    /// Enable API request compression
    pub enable_compression: bool,
    /// API authentication token (if required)
    pub api_token: Option<String>,
    /// Enable API response caching
    pub enable_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_url: "https://localhost:3031".to_string(),
            poll_interval_secs: 2,
            verbose: false,
            theme: "dark".to_string(),
            show_timestamps: true,
            auto_scroll_logs: true,
            max_retries: 3,
            accept_invalid_certs: true,
            admin_password: String::new(), // Empty by default - user must enter password
            client_cert: None,
            client_key: None,
            ca_cert: None,
            api_timeout_secs: 30,
            enable_compression: true,
            api_token: None,
            enable_caching: true,
            cache_ttl_secs: 300, // 5 minutes
        }
    }
}

impl Config {
    /// Load configuration from a TOML file. If the file does not exist or parsing fails,
    /// a default configuration is returned.
    pub fn load_from_path(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => match toml::from_str::<Self>(&content) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("Failed to parse config {}: {}. Using defaults.", path, err);
                    Self::default()
                }
            },
            Err(_) => {
                eprintln!("Config file {} not found. Using defaults.", path);
                Self::default()
            }
        }
    }

    /// Reloads the configuration from the specified path.
    /// If successful, updates the current instance.
    /// If the file cannot be read or parsed, returns an error and leaves the current instance unchanged.
    #[allow(dead_code)]
    pub fn reload(&mut self, path: &str) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;
        let new_config: Config = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;
        *self = new_config;
        Ok(())
    }

    /// Save the current configuration to a TOML file.
    pub fn save_to_path(cfg: &Self, path: &str) -> std::io::Result<()> {
        let toml_str = toml::to_string_pretty(cfg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, toml_str)
    }

    /// Validates the configuration.
    /// Checks that if a client certificate is provided, a client key is also provided.
    pub fn validate(&self) -> Result<(), String> {
        if self.client_cert.is_some() && self.client_key.is_none() {
            return Err("Client certificate is present but client key is missing.".to_string());
        }
        Ok(())
    }

    /// Loads the client identity and CA certificate from the configured file paths.
    /// This is resilient to file-not-found errors; if a configured cert file is not found,
    /// it is treated as if it were not configured. Other file read errors will still fail.
    pub async fn load_certs(&self) -> anyhow::Result<WolfIdentity> {
        // Helper to read a file if it exists, logging a warning if not found.
        let read_file_optional =
            |path: &str, description: &str| -> anyhow::Result<Option<Vec<u8>>> {
                match std::fs::read(path) {
                    Ok(content) => Ok(Some(content)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        eprintln!(
                            "Warning: {} file not found at '{}', ignoring.",
                            description, path
                        );
                        Ok(None)
                    }
                    Err(e) => Err(anyhow::anyhow!(
                        "Failed to read {} from {}: {}",
                        description,
                        path,
                        e
                    )),
                }
            };

        // Load client identity (cert + key)
        let identity =
            if let (Some(cert_path), Some(key_path)) = (&self.client_cert, &self.client_key) {
                let cert_pem = read_file_optional(cert_path, "Client certificate")?;
                let key_pem = read_file_optional(key_path, "Client key")?;

                if let (Some(cert), Some(key)) = (cert_pem, key_pem) {
                    // Combine cert and key into one PEM buffer for reqwest::Identity::from_pem
                    let mut combined = cert;
                    if !combined.ends_with(b"\n") {
                        combined.push(b'\n');
                    }
                    combined.extend_from_slice(&key);

                    match reqwest::Identity::from_pem(&combined) {
                        Ok(id) => Some(id),
                        Err(e) => {
                            eprintln!("Warning: Failed to create client identity from PEMs: {}", e);
                            None
                        }
                    }
                } else {
                    // One or both files were not found. Silently ignore.
                    None
                }
            } else {
                None
            };

        // Load CA certificate. If none provided and `accept_invalid_certs` is true,
        // generate a self-signed cert via `wolf_den::certs` for developer setups.
        let ca_cert = if let Some(ca_path) = &self.ca_cert {
            if let Some(ca_pem) = read_file_optional(ca_path, "CA certificate")? {
                let cert = Certificate::from_pem(&ca_pem).map_err(|e| {
                    anyhow::anyhow!("Failed to create CA certificate from PEM: {}", e)
                })?;
                Some(cert)
            } else {
                None
            }
        } else if self.accept_invalid_certs {
            // Generate a self-signed cert for localhost/127.0.0.1 using Wolf Den.
            match generate_self_signed_cert(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            {
                Ok((cert_pem, _key_pem)) => match Certificate::from_pem(cert_pem.as_bytes()) {
                    Ok(cert) => Some(cert),
                    Err(e) => {
                        eprintln!(
                            "Warning: failed to convert generated cert to Certificate: {}",
                            e
                        );
                        None
                    }
                },
                Err(e) => {
                    eprintln!(
                        "Warning: failed to generate self-signed cert via wolf_den: {}",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        let security_manager = SecurityManager::new("wolf_identity".to_string(), MEDIUM_SECURITY);
        if let Err(e) = security_manager.initialize().await {
            eprintln!("Warning: Failed to initialize SecurityManager: {}", e);
        }

        Ok(WolfIdentity {
            client: identity,
            ca: ca_cert,
            p2p_keypair: Some(Keypair::generate_ed25519()),
            security_manager: Some(security_manager),
        })
    }

    /// Creates an enhanced HTTP client with all configured options and wolf identity
    pub fn create_http_client(
        &self,
        wolf_identity: &WolfIdentity,
    ) -> anyhow::Result<reqwest::Client> {
        let mut client_builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.accept_invalid_certs)
            .timeout(Duration::from_secs(self.api_timeout_secs))
            .user_agent("Wolf-Control/1.0");

        if !self.enable_compression {
            client_builder = client_builder.no_gzip().no_brotli().no_deflate();
        }

        // Add authentication token if provided
        if let Some(token) = &self.api_token {
            client_builder = client_builder.default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", token).parse().unwrap(),
                );
                headers
            });
        }

        // Load TLS identity from wolf_identity if available
        if let Some(identity) = &wolf_identity.client {
            client_builder = client_builder.identity(identity.clone());
        }
        if let Some(ca) = &wolf_identity.ca {
            client_builder = client_builder.add_root_certificate(ca.clone());
        }

        Ok(client_builder.build()?)
    }

    /// Helper to construct the GraphQL API URL based on the base API URL.
    #[allow(dead_code)]
    pub fn graphql_url(&self) -> String {
        format!("{}/graphql", self.api_url.trim_end_matches('/'))
    }
}
