//! Sentinel daemon entry point.
//!
//! This crate provides the daemon for the TersecPot system.

use sentinel::start_sentinel;
use tracing_subscriber;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    tracing::info!("TersecPot Sentinel starting...");
    start_sentinel().await
}
