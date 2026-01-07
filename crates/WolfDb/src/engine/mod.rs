use crate::storage::WolfDbStorage;
use crate::storage::model::Record;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use comfy_table::Table;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::collections::HashMap;
use base64::Engine as _;

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
    /// Import data from a SQLite database file
    ImportSqlite {
        /// Path to the SQLite file
        path: String,
    },
    /// Exit the REPL
    Exit,
}

pub struct QueryEngine {
    storage: WolfDbStorage,
}

impl QueryEngine {
    pub fn new(storage: WolfDbStorage) -> Self {
        Self { storage }
    }

    pub async fn run_repl(&mut self) -> Result<()> {
        println!(
            "{}",
            "----------------------------------------".bright_blue()
        );
        println!(
            "{}",
            "      WOLFDB HYBRID PQC DATABASE       "
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "----------------------------------------".bright_blue()
        );
        println!("Type 'help' or any command. Use 'exit' to quit.\n");

        let mut rl = DefaultEditor::new()?;
        let history_path = "wolfdb_history.txt";
        let _ = rl.load_history(history_path);

        // Security check
        if !self.storage.is_initialized() {
            println!(
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
            println!(
                "{}",
                "✔ Keystore initialized with PQ-KEM (Kyber768) and PQ-DSA (Dilithium)."
                    .bright_green()
            );

            // Phase 3: Email Backup
            println!("\n{}", "--- SECURE BACKUP SETUP ---".bright_blue().bold());
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

                println!("Generating encrypted recovery blob...");
                let blob = self.storage.generate_recovery_backup(&recovery_pass)?;

                crate::backup::email::EmailBackup::send_recovery_key(&email, &blob, None).await?;
                println!("{}", "✔ Secure recovery backup completed.".bright_green());
            }
        } else {
            let password = dialoguer::Password::new()
                .with_prompt("Master Password")
                .interact()?;

            // Check if HSM is enabled before asking for PIN
            let keystore_path = format!("wolf.db/keystore.json"); // Assuming default path
            let mut hsm_pin = None;
            let pin_str;

            if std::path::Path::new(&keystore_path).exists() {
                let ks = crate::crypto::keystore::Keystore::load(&keystore_path)?;
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
            println!(
                "{}",
                "✔ Database unlocked. PQC session active.".bright_green()
            );
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
                    let args = format!("wolfdb {}", line);
                    let parts = shlex::split(&args).context("Failed to parse command input")?;

                    match Cli::try_parse_from(parts) {
                        Ok(cli) => {
                            if let Err(e) = self.execute(cli.command) {
                                println!("{} {}", "Error:".bright_red().bold(), e);
                            }
                        }
                        Err(e) => {
                            println!("{}", e);
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!(
                        "\n{}",
                        "(!) Interrupted. Cleaning up session...".bright_yellow()
                    );
                    let _ = self.save();
                    break;
                }
                Err(ReadlineError::Eof) => {
                    println!("{}", "(!) Session ended.".bright_yellow());
                    let _ = self.save();
                    break;
                }
                Err(err) => {
                    println!("{} {:?}", "Error:".bright_red(), err);
                    break;
                }
            }
        }

        rl.save_history(history_path)?;
        self.save()?;
        Ok(())
    }

    fn execute(&mut self, cmd: Commands) -> Result<()> {
        match cmd {
            Commands::Status => {
                let status = if self.storage.get_active_sk().is_some() {
                    "ACTIVE".bright_green()
                } else {
                    "LOCKED".bright_red()
                };
                println!("Security Status: {}", status);
                println!(
                    "Key Type: {}",
                    "ML-KEM (Kyber768) + ML-DSA (Dilithium)".bright_white()
                );

                if let Ok(info) = self.storage.get_info() {
                    println!("\n{}", "--- DATABASE METRICS ---".bright_blue().bold());
                    let mut table = Table::new();
                    table.set_header(vec!["Metric", "Value"]);
                    if let Some(obj) = info.as_object() {
                        for (k, v) in obj {
                            table.add_row(vec![k, &v.to_string()]);
                        }
                    }
                    println!("{}", table);
                }
            }
            Commands::List { limit } => {
                let keys = self.storage.list_keys("default")?; // Assuming 'default' table for now
                if keys.is_empty() {
                     println!("{}", "No records found.".bright_yellow());
                } else {
                    println!("\n{}", format!("--- LISTING RECORDS (Limit: {}) ---", limit).bright_blue().bold());
                    let mut table = Table::new();
                    table.set_header(vec!["#", "Record ID"]);
                    
                    for (i, key) in keys.iter().take(limit).enumerate() {
                        table.add_row(vec![(i + 1).to_string(), key.clone()]);
                    }
                    println!("{}", table);
                    
                    if keys.len() > limit {
                        println!("{}", format!("... and {} more records.", keys.len() - limit).dimmed());
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
                self.storage.insert_record("default", &record, &pk)?;
                println!(
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
                if let Some(record) = self.storage.get_record("default", &id, &sk)? {
                    self.print_record(&record);
                } else {
                    println!("{} Record '{}' not found.", "✘".bright_yellow(), id);
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
                    .search_similar_records("default", &query_vec, k, &sk)?;

                if results.is_empty() {
                    println!("{}", "No similar records found.".bright_yellow());
                } else {
                    self.print_results(results);
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
                println!(
                    "{}",
                    "✔ Database keys recovered and re-initialized.".bright_green()
                );
            }
            Commands::ImportSqlite { path } => {
                println!("{}", format!("Importing from SQLite: {}", path).bright_blue());
                
                let conn = rusqlite::Connection::open(&path)
                    .context("Failed to open SQLite database")?;

                // Get list of tables
                let mut stmt = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
                let tables: Vec<String> = stmt.query_map([], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;

                let pk = self.storage.get_active_pk()
                    .context("No KEM public key active. Unlock required.")?
                    .to_vec();

                let mut total_records = 0;

                for table_name in tables {
                    println!("  Processing table: {}", table_name.bright_white());
                    
                    let mut stmt = conn.prepare(&format!("SELECT * FROM \"{}\"", table_name))?;
                    let column_names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
                    let column_count = column_names.len();

                    let rows = stmt.query_map([], |row| {
                        let mut data_map = HashMap::new();
                        let mut id = None;

                        for i in 0..column_count {
                            let col_name = &column_names[i];
                            let val_ref = row.get_ref(i)?;
                            
                            let val_str = match val_ref {
                                rusqlite::types::ValueRef::Null => "null".to_string(),
                                rusqlite::types::ValueRef::Integer(i) => i.to_string(),
                                rusqlite::types::ValueRef::Real(r) => r.to_string(),
                                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).to_string(),
                                rusqlite::types::ValueRef::Blob(b) => base64::engine::general_purpose::STANDARD.encode(b),
                            };

                            if (col_name == "id" || col_name == "uuid") && id.is_none() {
                                id = Some(val_str.clone());
                            }
                            
                            data_map.insert(col_name.clone(), val_str);
                        }

                        Ok((id, data_map))
                    })?;

                    let mut batch = Vec::new();
                    for row_res in rows {
                        let (id_opt, data): (Option<String>, HashMap<String, String>) = row_res?;
                        let id = id_opt.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                        
                        batch.push(Record {
                            id,
                            data,
                            vector: None, // No vector data in generic import
                        });
                    }

                    let count = batch.len();
                    self.storage.insert_batch_records(&table_name, batch, &pk)?;
                    println!("    -> Imported {} records", count);
                    total_records += count;
                }

                println!(
                    "{} Import complete. Total records: {}",
                    "✔".bright_green(),
                    total_records
                );
            }
            Commands::Exit => {
                // Handled in loop
            }
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        self.storage.save()?;
        println!(
            "{}",
            "✔ Database persistence complete.".bright_green().dimmed()
        );
        Ok(())
    }

    fn print_record(&self, record: &Record) {
        let mut table = Table::new();
        table.set_header(vec!["Field", "Value"]);
        table.add_row(vec!["ID", &record.id]);

        let meta_str = serde_json::to_string_pretty(&record.data).unwrap_or_default();
        table.add_row(vec!["Relational Data", &meta_str]);

        if let Some(v) = &record.vector {
            table.add_row(vec!["Vector Data", &format!("{:?}", v)]);
        }

        println!("\n{}", table);
    }

    fn print_results(&self, results: Vec<(Record, f32)>) {
        let mut table = Table::new();
        table.set_header(vec!["Rank", "Distance", "Record ID", "Metadata"]);

        for (i, (rec, dist)) in results.into_iter().enumerate() {
            let meta_str = serde_json::to_string(&rec.data).unwrap_or_default();
            table.add_row(vec![
                (i + 1).to_string(),
                format!("{:.4}", dist),
                rec.id,
                meta_str,
            ]);
        }

        println!("\n{}", table);
    }
}
