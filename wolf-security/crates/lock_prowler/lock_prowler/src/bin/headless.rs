//! Headless Lock Prowler Binary
//!
//! Runs the Lock Prowler in automated "hunter" mode.
use lock_prowler::headless::{HeadlessConfig, HeadlessWolfProwler};
use lock_prowler::storage::WolfStore;
use std::env;
use tokio::signal;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🐺 Starting Headless Wolf Prowler...");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let config = parse_args(&args)?;

    // Initialize database
    let db_path = env::var("WOLF_DB_PATH").unwrap_or_else(|_| "./wolf_data".to_string());
    println!("📁 Using database path: {}", db_path);

    let store = WolfStore::new(&db_path)
        .await
        .map_err(|e| format!("Failed to initialize database: {}", e))?;

    // Initialize headless prowler
    let prowler = HeadlessWolfProwler::new(config.clone(), store);

    if config.enable_wolfpack {
        println!("🐺 WolfPack integration enabled (managed internally)");
    }

    // Start the service
    println!("🚀 Starting headless service...");
    prowler.start().await?;

    // Handle shutdown signal
    // In test mode, we might want to simulate a shutdown or have a different monitoring loop.
    // The `shutdown_rx` is not mutable as it's only consumed once by `tokio::select!`.
    let shutdown_rx = signal::ctrl_c();
    tokio::select! {
        _ = async {
            loop {
                let status = prowler.get_status().await;
                println!("📊 Status: Running={}, Progress={:.1}%, Discovered={}, Imported={}",
                    status.is_running, status.progress, status.discovered_secrets, status.imported_secrets);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        } => {},
        _ = shutdown_rx => {
            println!("\n🛑 Received shutdown signal...");
        }
    }

    // Stop the service
    println!("🛑 Stopping headless service...");
    prowler.stop().await?;

    println!("✅ Headless Wolf Prowler stopped gracefully");
    Ok(())
}

fn parse_args(args: &[String]) -> Result<HeadlessConfig, String> {
    let mut config = HeadlessConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--path" | "-p" => {
                if i + 1 < args.len() {
                    config.scan_paths = vec![args[i + 1].clone()];
                    i += 2;
                } else {
                    return Err("Missing path argument for --path".to_string());
                }
            }
            "--interval" | "-i" => {
                if i + 1 < args.len() {
                    config.scan_interval =
                        args[i + 1].parse().map_err(|_| "Invalid interval value")?;
                    i += 2;
                } else {
                    return Err("Missing interval argument for --interval".to_string());
                }
            }
            "--no-auto-import" => {
                config.auto_import = false;
                i += 1;
            }
            "--no-wolfpack" => {
                config.enable_wolfpack = false;
                i += 1;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]));
            }
        }
    }

    Ok(config)
}

fn print_help() {
    println!("Headless Wolf Prowler");
    println!();
    println!("Usage: headless [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -p, --path PATH        Target path to scan (default: ~)");
    println!("  -i, --interval SECONDS Scan interval in seconds (default: 300)");
    println!("  --no-auto-import       Disable automatic secret import");
    println!("  --no-wolfpack          Disable WolfPack integration");
    println!("  -h, --help             Show this help message");
    println!();
    println!("Environment Variables:");
    println!("  WOLF_DB_PATH           Path to Wolf database (default: ./wolf_data)");
    println!();
    println!("Examples:");
    println!("  headless --path /home/user --interval 600");
    println!("  headless --path /var/log --no-auto-import");
    println!("  headless --no-wolfpack");
}
