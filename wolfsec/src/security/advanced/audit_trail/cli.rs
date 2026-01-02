use crate::security::advanced::audit_trail::AuditTrailSystem;
use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;

/// CLI commands for the Audit Trail System
#[derive(Debug, Subcommand)]
pub enum AuditCliCommand {
    /// Validate the integrity of an exported audit chain JSON file
    ValidateChain {
        /// Path to the exported JSON file
        #[arg(short, long)]
        path: PathBuf,
    },
}

impl AuditCliCommand {
    /// Execute the CLI command
    pub async fn execute(&self, system: &AuditTrailSystem) -> Result<()> {
        match self {
            AuditCliCommand::ValidateChain { path } => {
                println!("🔍 Starting audit chain validation for: {:?}", path);
                match system.validate_chain_file(path).await {
                    Ok(true) => println!("✅ SUCCESS: Audit chain integrity verified."),
                    Ok(false) => {
                        println!("❌ FAILURE: Audit chain integrity compromised or invalid.")
                    }
                    Err(e) => {
                        println!("⚠️ ERROR: Failed to validate chain: {}", e);
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }
}
