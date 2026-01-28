//! Unified logging infrastructure for Wolf Prowler
//!
//! This crate provides a centralized way to initialize and manage logging
//! across all Wolf Prowler components, ensuring consistency and proper bridging
//! between `log` and `tracing` crates.

use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::info;
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Logger configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggerConfig {
    /// Log level (e.g., "info", "debug", "trace")
    pub level: String,
    /// Enable file logging
    pub file_logging: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Enable JSON format for console
    pub json_format: bool,
    /// Enable console colors (ignored if json_format is true)
    pub console_colors: bool,
    /// Whether to include line numbers and files
    pub show_location: bool,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_logging: false,
            log_file: None,
            json_format: false,
            console_colors: true,
            show_location: true,
        }
    }
}

/// Initialize the logging system
pub fn init_logging(config: LoggerConfig) -> Result<()> {
    // 1. Initialize LogTracer to bridge 'log' crate to 'tracing'
    // This allows crates using 'info!' from 'log' to show up in our tracing subscriber
    LogTracer::init().ok();

    // 2. Build EnvFilter
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    // 3. Prepare Console Layer
    let console_layer = if config.json_format {
        let layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(config.show_location)
            .with_line_number(config.show_location)
            .with_ansi(false);
        Some(layer.boxed())
    } else {
        let layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(config.show_location)
            .with_line_number(config.show_location)
            .with_ansi(config.console_colors);
        Some(layer.boxed())
    };

    // 4. Prepare File Layer
    let file_layer = if config.file_logging {
        if let Some(log_file) = &config.log_file {
            let file_name = log_file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("wolf_prowler.log");

            let directory = log_file.parent().unwrap_or_else(|| Path::new("."));

            // Ensure directory exists
            std::fs::create_dir_all(directory)?;

            let file_appender = tracing_appender::rolling::daily(directory, file_name);

            let layer = tracing_subscriber::fmt::layer()
                .with_writer(file_appender)
                .with_ansi(false)
                .json() // Always use JSON for file logs for easier parsing
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true);

            Some(layer.boxed())
        } else {
            None
        }
    } else {
        None
    };

    // 5. Build and install the subscriber
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer);

    subscriber.init();

    info!("🐺 Wolf Log initialized");
    info!("Level: {}", config.level);
    if config.file_logging {
        if let Some(path) = &config.log_file {
            info!("File logging enabled: {:?}", path);
        }
    }

    Ok(())
}

/// Helper for quick initialization with default settings
pub fn init_vibrant() -> Result<()> {
    init_logging(LoggerConfig {
        level: "info,wolfsec=info,wolf_prowler=info,wolf_net=info".to_string(),
        console_colors: true,
        show_location: true,
        ..Default::default()
    })
}

/// Helper for production initialization
pub fn init_production(log_dir: impl AsRef<Path>) -> Result<()> {
    let log_path = log_dir.as_ref().join("wolf_system.log");
    init_logging(LoggerConfig {
        level: "info".to_string(),
        file_logging: true,
        log_file: Some(log_path),
        json_format: true, // JSON for easier centralized logging (cloud)
        console_colors: false,
        show_location: true,
    })
}
