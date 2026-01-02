//! Logging infrastructure for Wolf Prowler

use anyhow::Result;
use std::path::PathBuf;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Logger configuration
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Log level
    pub level: String,
    /// Enable file logging
    pub file_logging: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Enable JSON format
    pub json_format: bool,
    /// Enable console colors
    pub console_colors: bool,
}

/// Wolf Prowler logger
pub struct Logger {
    config: LoggerConfig,
}

impl Logger {
    /// Create a new logger
    pub fn new(config: LoggerConfig) -> Self {
        Self { config }
    }

    /// Initialize the logging system
    pub fn init(&self) -> Result<()> {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&self.config.level));

        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .with_ansi(self.config.console_colors);

        let json_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true)
            .with_ansi(false);

        let file_layer = if let Some(log_file) = &self.config.log_file {
            if self.config.file_logging {
                let file_appender = tracing_appender::rolling::daily(
                    log_file
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new(".")),
                    log_file
                        .file_name()
                        .unwrap_or_else(|| std::ffi::OsStr::new("wolf_prowler.log")),
                );

                Some(
                    tracing_subscriber::fmt::layer()
                        .with_writer(file_appender)
                        .with_ansi(false)
                        .json()
                        .boxed(),
                )
            } else {
                None
            }
        } else {
            None
        };

        let subscriber = tracing_subscriber::registry().with(env_filter.clone());

        if self.config.json_format {
            subscriber.with(json_layer).init();
        } else {
            subscriber.with(fmt_layer).init();
        }

        if let Some(layer) = file_layer {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(layer)
                .init();
        }

        info!("🐺 Wolf Prowler logging initialized");
        info!("Log level: {}", self.config.level);
        info!("File logging: {}", self.config.file_logging);
        info!("JSON format: {}", self.config.json_format);

        Ok(())
    }

    /// Log a startup message
    pub fn log_startup(&self, version: &str, port: u16) {
        info!("🚀 Wolf Prowler v{} starting up", version);
        info!("📡 Network port: {}", port);
        info!("🌐 Dashboard: http://localhost:8080");
    }

    /// Log a peer connection
    pub fn log_peer_connected(&self, peer_id: &str) {
        info!("🔗 Peer connected: {}", peer_id);
    }

    /// Log a peer disconnection
    pub fn log_peer_disconnected(&self, peer_id: &str) {
        info!("❌ Peer disconnected: {}", peer_id);
    }

    /// Log a security event
    pub fn log_security_event(&self, event_type: &str, severity: &str, description: &str) {
        match severity {
            "critical" => error!("🚨 [{}] {}", event_type, description),
            "high" => error!("⚠️ [{}] {}", event_type, description),
            "medium" => warn!("⚡ [{}] {}", event_type, description),
            "low" => info!("ℹ️ [{}] {}", event_type, description),
            _ => debug!("📝 [{}] {}", event_type, description),
        }
    }

    /// Log a pack coordination event
    pub fn log_pack_coordination(&self, action: &str, pack_id: &str) {
        info!("🐺 Pack coordination: {} [{}]", action, pack_id);
    }

    /// Log a howl communication
    pub fn log_howl(&self, frequency: f32, pattern: &str, source: &str) {
        info!("📢 Howl: {:.1}Hz - {} from {}", frequency, pattern, source);
    }

    /// Log a territory event
    pub fn log_territory(&self, action: &str, territory_id: &str) {
        info!("🏠 Territory {}: {}", action, territory_id);
    }

    /// Log a hunt event
    pub fn log_hunt(&self, action: &str, hunt_id: &str, target: &str) {
        info!("🎯 Hunt {}: {} targeting {}", action, hunt_id, target);
    }

    /// Log a discovery event
    pub fn log_discovery(&self, method: &str, peers_found: usize) {
        info!("🔍 Discovery ({}): {} peers found", method, peers_found);
    }

    /// Log a cryptographic operation
    pub fn log_crypto(&self, operation: &str, success: bool) {
        if success {
            debug!("🔐 {}: success", operation);
        } else {
            error!("🔐 {}: failed", operation);
        }
    }

    /// Log a network event
    pub fn log_network(&self, event_type: &str, details: &str) {
        info!("🌐 {}: {}", event_type, details);
    }

    /// Log a dashboard event
    pub fn log_dashboard(&self, event: &str) {
        info!("📊 Dashboard: {}", event);
    }

    /// Log a metrics update
    pub fn log_metrics(&self, metrics: &str) {
        debug!("📈 Metrics: {}", metrics);
    }

    /// Log an error with context
    pub fn log_error(&self, context: &str, error: &anyhow::Error) {
        error!("❌ {}: {}", context, error);
    }

    /// Log a warning
    pub fn log_warning(&self, message: &str) {
        warn!("⚠️ {}", message);
    }

    /// Log debug information
    pub fn log_debug(&self, message: &str) {
        debug!("🐛 {}", message);
    }

    /// Log trace information
    pub fn log_trace(&self, message: &str) {
        trace!("🔍 {}", message);
    }
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_logging: false,
            log_file: None,
            json_format: false,
            console_colors: true,
        }
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new(LoggerConfig::default())
    }
}

/// Macro for logging security events
#[macro_export]
macro_rules! log_security {
    ($level:expr, $event_type:expr, $description:expr) => {
        match $level {
            "critical" => error!("🚨 [{}] {}", $event_type, $description),
            "high" => error!("⚠️ [{}] {}", $event_type, $description),
            "medium" => warn!("⚡ [{}] {}", $event_type, $description),
            "low" => info!("ℹ️ [{}] {}", $event_type, $description),
            _ => debug!("📝 [{}] {}", $event_type, $description),
        }
    };
}

/// Macro for logging pack events
#[macro_export]
macro_rules! log_pack {
    ($action:expr, $pack_id:expr) => {
        info!("🐺 Pack coordination: {} [{}]", $action, $pack_id);
    };
}

/// Macro for logging howl events
#[macro_export]
macro_rules! log_howl {
    ($frequency:expr, $pattern:expr, $source:expr) => {
        info!(
            "📢 Howl: {:.1}Hz - {} from {}",
            $frequency, $pattern, $source
        );
    };
}

/// Initialize logging with default configuration
pub fn init_logging() -> Result<()> {
    let logger = Logger::default();
    logger.init()?;
    Ok(())
}

/// Initialize logging with custom configuration
pub fn init_logging_with_config(config: LoggerConfig) -> Result<()> {
    let logger = Logger::new(config);
    logger.init()?;
    Ok(())
}
