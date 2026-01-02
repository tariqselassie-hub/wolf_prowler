use super::SecurityEvent;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{debug, info};

/// Event storage for historical analysis
pub struct EventStorage {
    /// In-memory event buffer
    events: Vec<SecurityEvent>,
    /// Maximum buffer size
    max_buffer_size: usize,
    /// Storage directory
    storage_path: String,
    /// Event retention days
    retention_days: i64,
    /// Optional database pool for persistent storage
    db_pool: Option<sqlx::PgPool>,
}

impl EventStorage {
    /// Create new event storage
    pub fn new(storage_path: String, retention_days: i64) -> Result<Self> {
        // Create storage directory if it doesn't exist
        fs::create_dir_all(&storage_path)?;

        Ok(Self {
            events: Vec::new(),
            max_buffer_size: 10000,
            storage_path,
            retention_days,
            db_pool: None,
        })
    }

    /// Create event storage with database integration
    pub fn with_database(
        storage_path: String,
        retention_days: i64,
        db_pool: sqlx::PgPool,
    ) -> Result<Self> {
        // Create storage directory if it doesn't exist
        fs::create_dir_all(&storage_path)?;

        Ok(Self {
            events: Vec::new(),
            max_buffer_size: 10000,
            storage_path,
            retention_days,
            db_pool: Some(db_pool),
        })
    }

    /// Store a security event
    pub async fn store_event(&mut self, event: SecurityEvent) -> Result<()> {
        debug!("💾 Storing event: {}", event.event_id);

        // Store in database if available
        if let Some(pool) = &self.db_pool {
            // Extract peer_id from affected assets if available
            let peer_id = event
                .affected_assets
                .first()
                .map(|asset| asset.asset_id.clone());

            // Direct SQL insertion using runtime query to avoid macro issues
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO security_events (
                    event_id, timestamp, event_type, severity, source,
                    peer_id, description, details, resolved
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(event.event_id)
            .bind(event.timestamp)
            .bind(format!("{:?}", event.event_type))
            .bind(format!("{:?}", event.severity))
            .bind(event.source.source_id.clone())
            .bind(peer_id)
            .bind(event.description.clone())
            .bind(serde_json::to_value(&event.details).unwrap_or_else(|_| serde_json::json!({})))
            .bind(false)
            .execute(pool)
            .await
            {
                // Log error but don't fail the whole storage operation (fallback to disk)
                tracing::error!("Failed to store event in database: {}", e);
            } else {
                debug!("Event stored in database successfully");
            }
        }

        // Add to in-memory buffer for fast access
        self.events.push(event.clone());

        // Trim buffer if needed
        if self.events.len() > self.max_buffer_size {
            self.events.remove(0);
        }

        // Still persist to disk as backup
        self.persist_event(&event).await?;

        Ok(())
    }

    /// Query events by time range
    pub fn query_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<SecurityEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Query events by severity
    pub fn query_by_severity(&self, severity: super::EventSeverity) -> Vec<SecurityEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == severity)
            .cloned()
            .collect()
    }

    /// Query events by event type
    pub fn query_by_type(&self, event_type_pattern: &str) -> Vec<SecurityEvent> {
        self.events
            .iter()
            .filter(|e| format!("{:?}", e.event_type).contains(event_type_pattern))
            .cloned()
            .collect()
    }

    /// Get recent events
    pub fn get_recent_events(&self, count: usize) -> Vec<SecurityEvent> {
        let start_index = if self.events.len() > count {
            self.events.len() - count
        } else {
            0
        };

        self.events[start_index..].to_vec()
    }

    /// Persist event to disk
    async fn persist_event(&self, event: &SecurityEvent) -> Result<()> {
        // Create daily event file
        let date_str = event.timestamp.format("%Y-%m-%d").to_string();
        let file_path = Path::new(&self.storage_path).join(format!("events_{}.jsonl", date_str));

        // Append event as JSON line
        let json = serde_json::to_string(event)?;
        let mut content = if file_path.exists() {
            fs::read_to_string(&file_path)?
        } else {
            String::new()
        };

        content.push_str(&json);
        content.push('\n');

        fs::write(file_path, content).context("Failed to persist event")?;

        Ok(())
    }

    /// Load events from disk for a specific date
    pub async fn load_events_for_date(
        &mut self,
        date: DateTime<Utc>,
    ) -> Result<Vec<SecurityEvent>> {
        let date_str = date.format("%Y-%m-%d").to_string();
        let file_path = Path::new(&self.storage_path).join(format!("events_{}.jsonl", date_str));

        if !file_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(file_path)?;
        let mut events = Vec::new();

        for line in content.lines() {
            if !line.is_empty() {
                match serde_json::from_str::<SecurityEvent>(line) {
                    Ok(event) => events.push(event),
                    Err(e) => {
                        debug!("⚠️ Failed to parse event: {}", e);
                    }
                }
            }
        }

        info!("📂 Loaded {} events from {}", events.len(), date_str);
        Ok(events)
    }

    /// Clean up old events
    pub async fn cleanup_old_events(&self) -> Result<()> {
        let cutoff_date = Utc::now() - chrono::Duration::days(self.retention_days);
        let cutoff_str = cutoff_date.format("%Y-%m-%d").to_string();

        info!("🧹 Cleaning up events older than {}", cutoff_str);

        let storage_dir = Path::new(&self.storage_path);
        if !storage_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(storage_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(filename) = path.file_name() {
                if let Some(filename_str) = filename.to_str() {
                    if filename_str.starts_with("events_") && filename_str.ends_with(".jsonl") {
                        // Extract date from filename
                        let date_part = filename_str
                            .trim_start_matches("events_")
                            .trim_end_matches(".jsonl");

                        if date_part < cutoff_str.as_str() {
                            fs::remove_file(&path)?;
                            info!("🗑️ Removed old event file: {:?}", filename);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get storage statistics
    pub fn get_statistics(&self) -> StorageStatistics {
        let total_events = self.events.len();

        let mut events_by_severity = HashMap::new();
        for event in &self.events {
            *events_by_severity
                .entry(format!("{:?}", event.severity))
                .or_insert(0) += 1;
        }

        let oldest_event = self.events.first().map(|e| e.timestamp);
        let newest_event = self.events.last().map(|e| e.timestamp);

        StorageStatistics {
            total_events,
            events_by_severity,
            oldest_event,
            newest_event,
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStatistics {
    pub total_events: usize,
    pub events_by_severity: HashMap<String, usize>,
    pub oldest_event: Option<DateTime<Utc>>,
    pub newest_event: Option<DateTime<Utc>>,
}
