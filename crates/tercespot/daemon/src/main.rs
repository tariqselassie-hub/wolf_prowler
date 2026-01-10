//! Sentinel daemon entry point.
//!
//! This crate provides the daemon for the TersecPot system.

use sentinel::start_sentinel;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    start_sentinel().await
}
