//! `WolfDb` - Hybrid PQC Database Command Line Interface and Web Server.
//!
//! This binary provides both an interactive REPL for database management
//! and a REST API server for remote interactions.

use anyhow::Result;
use clap::Parser;
use wolf_db::engine::QueryEngine;
use wolf_db::storage::WolfDbStorage;

/// Command-line arguments for `WolfDb`
#[derive(Parser)]
#[command(name = "wolfdb")]
#[command(about = "WolfDb - Hybrid PQC Database with CLI and Web Interface")]
struct Cli {
    /// Operating mode: 'cli' for REPL or 'web' for web server
    #[arg(long, default_value = "cli")]
    mode: String,

    /// Path to the `WolfDb` database directory
    #[arg(long, default_value = "wolf.db")]
    db: String,

    /// Web server host address (web mode only)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Web server port (web mode only)
    #[arg(long, default_value_t = 3000)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Cli::parse();
    let db_path = args.db;

    match args.mode.as_str() {
        "cli" => {
            // CLI REPL mode
            let storage = WolfDbStorage::open(&db_path)?;
            let mut engine = QueryEngine::new(storage);
            engine.run_repl().await?;
        }
        "web" => {
            // Web server mode
            use wolf_db::api::{create_router, AppState};

            let storage = WolfDbStorage::open(&db_path)?;
            let state = AppState::new(storage);
            let app = create_router(state);

            let addr = format!("{}:{}", args.host, args.port);
            tracing::info!("🐺 WolfDb Web Server starting on http://{}", addr);
            tracing::info!("📊 Navigate to http://{} to access the dashboard", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
        _ => {
            tracing::info!("Invalid mode: {}. Use 'cli' or 'web'", args.mode);
            std::process::exit(1);
        }
    }

    Ok(())
}
