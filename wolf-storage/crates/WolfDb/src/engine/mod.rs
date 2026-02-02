use crate::storage::model::Record;
use crate::storage::WolfDbStorage;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use comfy_table::Table;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "wolfdb")]
#[command(about = "WolfDb Hybrid PQC Database REPL", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display database security and engine status
    Status,
    /// List all record IDs in the database
    List {
        /// Maximum number of records to list
        #[arg(short, default_value_t = 50)]
        limit: usize,
    },
    /// Insert an encrypted record (relational + vector)
    Insert {
        /// Unique identifier for the record
        id: String,
        /// Relational data in JSON format, e.g., '{"key":"value"}'
        data: String,
        /// Optional vector in JSON format, e.g., '[0.1, 0.2]'
        #[arg(short, long)]
        vector: Option<String>,
    },
    /// Retrieve and decrypt a record by ID
    Get {
        /// Unique identifier for the record
        id: String,
    },
    /// Perform a hybrid similarity search
    Search {
        /// Query vector in JSON format, e.g., '[0.1, 0.2]'
        vector: String,
        /// Number of results to return
        #[arg(short, default_value_t = 5)]
        k: usize,
    },
    /// Recover database keys from a backup blob
    Recover {
        /// The base64 encoded recovery blob
        blob: String,
    },
    /// Import data from a `SQLite` database file
    ImportSqlite {
        /// Path to the `SQLite` file
        path: String,
    },
    /// Rebuild vector index from underlying encrypted storage
    Rebuild {
        /// Table name (defaults to 'default')
        #[arg(short, long, default_value = "default")]
        table: String,
    },
    /// Delete a record by ID
    Delete {
        /// Unique identifier for the record
        id: String,
        /// Table name (defaults to 'default')
        #[arg(short, long, default_value = "default")]
        table: String,
    },
    /// Display storage statistics
    Stats,
    /// Exit the REPL
    Exit,
}

/// Core query engine for the `WolfDb` REPL
pub struct QueryEngine {
    storage: WolfDbStorage,
}

impl QueryEngine {
    /// Creates a new `QueryEngine` instance
    #[must_use]
    pub const fn new(storage: WolfDbStorage) -> Self {
        Self { storage }
    }

    /// Starts the interactive REPL session
    ///
    /// # Errors
    ///
    /// Returns an error if the REPL session cannot be initialized, historical commands cannot be loaded,
    /// or if database operations fail.
    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::too_many_lines)]
    pub async fn run_repl(&mut self) -> Result<()> {
        tracing::info!(
            "{}",
            "----------------------------------------".bright_blue()
        );
        tracing::info!(
            "{}",
            "      WOLFDB HYBRID PQC DATABASE       "
                .bright_white()
                .bold()
        );
        tracing::info!(
            "{}",
            "----------------------------------------".bright_blue()
        );
        tracing::info!("Type 'help' or any command. Use 'exit' to quit.\n");

        let mut rl = DefaultEditor::new()?;
        let history_path = "wolfdb_history.txt";
        let _ = rl.load_history(history_path);

        // Security check
        if self.storage.is_initialized() {
            let password = dialoguer::Password::new()
                .with_prompt("Master Password")
                .interact()?;

            // Check if HSM is enabled before asking for PIN
            let keystore_path = "wolf.db/keystore.json"; // Assuming default path
            let mut hsm_pin = None;
            let pin_str;

            if std::path::Path::new(keystore_path).exists() {
                let ks = crate::crypto::keystore::Keystore::load(keystore_path)?;
                if ks.hsm_enabled {
                    pin_str = dialoguer::Password::new()
                        .with_prompt("HSM Security PIN")
                        .interact()?;
                    hsm_pin = Some(pin_str.as_str());
                }
            }

            self.storage
                .unlock(&password, hsm_pin)
                .context("Failed to unlock database. Invalid password?")?;
            tracing::info!(
                "{}",
                "✔ Database unlocked. PQC session active.".bright_green()
            );
        } else {
            tracing::info!(
                "{}",
                "Welcome! Please set a master password for your PQC database.".bright_blue()
            );
            let password = dialoguer::Password::new()
                .with_prompt("Set Master Password")
                .with_confirmation("Confirm Password", "Passwords do not match!")
                .interact()?;

            let use_hsm: bool = dialoguer::Confirm::new()
                .with_prompt("Enable USB HSM / Hardware Security? (Prototype)")
                .default(false)
                .interact()?;

            let mut hsm_pin = None;
            let hsm_pin_str;
            if use_hsm {
                hsm_pin_str = dialoguer::Password::new()
                    .with_prompt("Set HSM Security PIN")
                    .interact()?;
                hsm_pin = Some(hsm_pin_str.as_str());
            }

            self.storage.initialize_keystore(&password, hsm_pin)?;
            tracing::info!(
                "{}",
                "✔ Keystore initialized with PQ-KEM (Kyber768) and PQ-DSA (Dilithium)."
                    .bright_green()
            );

            // Phase 3: Email Backup
            tracing::info!("\n{}", "--- SECURE BACKUP SETUP ---".bright_blue().bold());
            let do_backup: bool = dialoguer::Confirm::new()
                .with_prompt("Enable Cloud/Email Backup?")
                .default(true)
                .interact()?;

            if do_backup {
                let email: String = dialoguer::Input::new()
                    .with_prompt("Recovery Email Address")
                    .interact_text()?;

                let recovery_pass = dialoguer::Password::new()
                    .with_prompt("Recovery Security Password (different from Master)")
                    .with_confirmation("Confirm Recovery Password", "Passwords do not match!")
                    .interact()?;

                tracing::info!("Generating encrypted recovery blob...");
                let blob = self.storage.generate_recovery_backup(&recovery_pass)?;

                crate::backup::email::EmailBackup::send_recovery_key(&email, &blob, None).await?;
                tracing::info!("{}", "✔ Secure recovery backup completed.".bright_green());
            }
        }

        loop {
            let readline = rl.readline("wolfdb> ".bright_green().bold().to_string().as_str());
            match readline {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    let _ = rl.add_history_entry(line);

                    if line == "exit" || line == "quit" {
                        self.save()?;
                        break;
                    }

                    // Prepend a dummy program name for clap to parse correctly
                    let args = format!("wolfdb {line}");
                    let parts = shlex::split(&args).context("Failed to parse command input")?;

                    match Cli::try_parse_from(parts) {
                        Ok(cli) => {
                            if let Err(e) = self.execute(cli.command).await {
                                tracing::error!("{} {e}", "Error:".bright_red().bold());
                            }
                        }
                        Err(e) => {
                            tracing::error!("{e}");
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    tracing::info!(
                        "\n{}",
                        "(!) Interrupted. Cleaning up session...".bright_yellow()
                    );
                    let _ = self.save();
                    break;
                }
                Err(ReadlineError::Eof) => {
                    tracing::info!("{}", "(!) Session ended.".bright_yellow());
                    let _ = self.save();
                    break;
                }
                Err(err) => {
                    tracing::error!("{} {err:?}", "Error:".bright_red());
                    break;
                }
            }
        }

        rl.save_history(history_path)?;
        self.save()?;
        Ok(())
    }

    /// Executes specified command
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::cognitive_complexity)]
    async fn execute(&mut self, cmd: Commands) -> Result<()> {
        match cmd {
            Commands::Status => {
                let status = if self.storage.get_active_sk().is_some() {
                    "ACTIVE".bright_green()
                } else {
                    "LOCKED".bright_red()
                };
                tracing::info!("Security Status: {status}");
                tracing::info!(
                    "Key Type: {}",
                    "ML-KEM (Kyber768) + ML-DSA (Dilithium)".bright_white()
                );

                if let Ok(info) = self.storage.get_info() {
                    tracing::info!("\n{}", "--- DATABASE METRICS ---".bright_blue().bold());
                    let mut table = Table::new();
                    table.set_header(vec!["Metric", "Value"]);
                    if let Some(obj) = info.as_object() {
                        for (k, v) in obj {
                            table.add_row(vec![k, &v.to_string()]);
                        }
                    }
                    tracing::info!("{table}");
                }
            }
            Commands::List { limit } => {
                let keys = self.storage.list_keys("default".to_string()).await?; // Assuming 'default' table for now
                if keys.is_empty() {
                    tracing::info!("{}", "No records found.".bright_yellow());
                } else {
                    tracing::info!(
                        "\n{}",
                        format!("--- LISTING RECORDS (Limit: {limit}) ---")
                            .bright_blue()
                            .bold()
                    );
                    let mut table = Table::new();
                    table.set_header(vec!["#", "Record ID"]);

                    for (i, key) in keys.iter().take(limit).enumerate() {
                        table.add_row(vec![i.saturating_add(1).to_string(), key.clone()]);
                    }
                    tracing::info!("{table}");

                    if keys.len() > limit {
                        tracing::info!(
                            "{}",
                            format!("... and {} more records.", keys.len().saturating_sub(limit))
                                .dimmed()
                        );
                    }
                }
            }
            Commands::Insert { id, data, vector } => {
                let pk = self
                    .storage
                    .get_active_pk()
                    .context("No KEM public key active. Unlock required.")?
                    .to_vec();

                let data_map: HashMap<String, String> =
                    serde_json::from_str(&data).context("Invalid relational data JSON")?;

                let vector_data: Option<Vec<f32>> = if let Some(v_str) = vector {
                    Some(serde_json::from_str(&v_str).context("Invalid vector JSON")?)
                } else {
                    None
                };

                let record = Record {
                    id: id.clone(),
                    data: data_map,
                    vector: vector_data,
                };
                self.storage
                    .insert_record("default".to_string(), record, pk)
                    .await?;
                tracing::info!(
                    "{} Record '{}' encrypted and persisted.",
                    "✔".bright_green(),
                    id.bright_white().bold()
                );
            }
            Commands::Get { id } => {
                let sk = self
                    .storage
                    .get_active_sk()
                    .context("No KEM secret key active. Unlock required.")?
                    .to_vec();
                if let Some(record) = self
                    .storage
                    .get_record("default".to_string(), id.clone(), sk)
                    .await?
                {
                    Self::print_record(&record);
                } else {
                    tracing::info!("{} Record '{id}' not found.", "✘".bright_yellow());
                }
            }
            Commands::Search { vector, k } => {
                let sk = self
                    .storage
                    .get_active_sk()
                    .context("No KEM secret key active. Unlock required.")?
                    .to_vec();
                let query_vec: Vec<f32> =
                    serde_json::from_str(&vector).context("Invalid query vector JSON")?;

                let results = self
                    .storage
                    .search_similar_records("default".to_string(), query_vec, k, sk)
                    .await?;

                if results.is_empty() {
                    tracing::info!("{}", "No similar records found.".bright_yellow());
                } else {
                    Self::print_results(results);
                }
            }
            Commands::Recover { blob } => {
                let recovery_pass = dialoguer::Password::new()
                    .with_prompt("Recovery Security Password")
                    .interact()?;

                let new_master_pass = dialoguer::Password::new()
                    .with_prompt("Set New Master Password")
                    .with_confirmation("Confirm Password", "Passwords do not match!")
                    .interact()?;

                self.storage
                    .recover_from_backup(&blob, &recovery_pass, &new_master_pass)?;
                tracing::info!(
                    "{}",
                    "✔ Database keys recovered and re-initialized.".bright_green()
                );
            }
            Commands::ImportSqlite { path } => {
                tracing::info!("{}", format!("Importing from SQLite: {path}").bright_blue());

                let pk = self
                    .storage
                    .get_active_pk()
                    .context("No KEM public key active. Unlock required.")?
                    .to_vec();

                let records_map = crate::import::sqlite::SqliteImporter::import_from_path(&path)?;
                let mut total_records: usize = 0;

                for (table_name, records) in records_map {
                    tracing::info!("  Processing table: {}", table_name.bright_white());
                    let count = records.len();
                    self.storage
                        .insert_batch_records(table_name, records, pk.clone())
                        .await?;
                    tracing::info!("    -> Imported {count} records");
                    total_records = total_records.saturating_add(count);
                }

                tracing::info!(
                    "{} Import complete. Total records: {total_records}",
                    "✔".bright_green()
                );
            }
            Commands::Rebuild { table } => {
                let sk = self
                    .storage
                    .get_active_sk()
                    .context("No KEM secret key active. Unlock required.")?
                    .to_vec();
                tracing::info!(
                    "{} Rebuilding vector index for '{}'...",
                    "ℹ".bright_blue(),
                    table
                );
                self.storage.rebuild_vector_index(table.clone(), sk).await?;
                tracing::info!(
                    "{} Vector index for '{}' rebuild complete.",
                    "✔".bright_green(),
                    table
                );
            }
            Commands::Delete { id, table } => {
                if self.storage.delete_record(table.clone(), id.clone()).await? {
                    tracing::info!(
                        "{} Record '{}' deleted from '{}'.",
                        "✔".bright_green(),
                        id.bright_white().bold(),
                        table
                    );
                } else {
                    tracing::info!("{} Record '{id}' not found in '{table}'.", "✘".bright_yellow());
                }
            }
            Commands::Stats => {
                tracing::info!("\n{}", "--- STORAGE STATISTICS ---".bright_blue().bold());
                if let Ok(info) = self.storage.get_info() {
                    let mut table = Table::new();
                    table.set_header(vec!["Metric", "Value"]);
                    if let Some(obj) = info.as_object() {
                        for (k, v) in obj {
                            table.add_row(vec![k, &v.to_string()]);
                        }
                    }
                    tracing::info!("{table}");
                }
            }
            Commands::Exit => {
                // Handled in loop
            }
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        self.storage.save().map_err(|e| anyhow::anyhow!(e))?;
        tracing::info!(
            "{}",
            "✔ Database persistence complete.".bright_green().dimmed()
        );
        Ok(())
    }

    fn print_record(record: &Record) {
        let mut table = Table::new();
        table.set_header(vec!["Field", "Value"]);
        table.add_row(vec!["ID", &record.id]);

        let meta_str = serde_json::to_string_pretty(&record.data).unwrap_or_default();
        table.add_row(vec!["Relational Data", &meta_str]);

        if let Some(v) = &record.vector {
            table.add_row(vec!["Vector Data", &format!("{v:?}")]);
        }

        tracing::info!("\n{table}");
    }

    fn print_results(results: Vec<(Record, f32)>) {
        let mut table = Table::new();
        table.set_header(vec!["Rank", "Distance", "Record ID", "Metadata"]);

        for (i, (rec, dist)) in results.into_iter().enumerate() {
            let meta_str = serde_json::to_string(&rec.data).unwrap_or_default();
            table.add_row(vec![
                i.saturating_add(1).to_string(),
                format!("{dist:.4}"),
                rec.id,
                meta_str,
            ]);
        }

        tracing::info!("\n{table}");
    }
}
