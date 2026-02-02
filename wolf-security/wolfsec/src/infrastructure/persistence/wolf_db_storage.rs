use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use wolf_db::storage::model::Record;
pub use wolf_db::storage::WolfDbStorage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source: String,
    pub metadata: HashMap<String, String>,
}

pub struct WolfDbThreatRepository {
    storage: Arc<WolfDbStorage>,
}

impl WolfDbThreatRepository {
    pub fn new(storage: Arc<WolfDbStorage>) -> Self {
        Self { storage }
    }

    pub async fn save_alert(&self, alert: &SecurityAlert) -> Result<()> {
        let pk = self
            .storage
            .get_active_pk()
            .context("Database locked. Unlock first.")?;
        let pk_vec = pk.to_vec();

        let mut data = HashMap::new();
        data.insert("timestamp".to_string(), alert.timestamp.to_rfc3339());
        data.insert("severity".to_string(), alert.severity.clone());
        data.insert("title".to_string(), alert.title.clone());
        data.insert("description".to_string(), alert.description.clone());
        data.insert("source".to_string(), alert.source.clone());

        // Store metadata with prefix
        for (k, v) in &alert.metadata {
            data.insert(format!("meta:{}", k), v.clone());
        }

        let record = Record {
            id: alert.id.clone(),
            data,
            vector: None,
        };

        self.storage
            .insert_record("alerts".to_string(), record, pk_vec)
            .await?;

        Ok(())
    }

    pub async fn get_recent_alerts(&self, limit: usize) -> Result<Vec<SecurityAlert>> {
        let sk = self
            .storage
            .get_active_sk()
            .context("Database locked. Unlock first.")?;
        let sk_vec = sk.to_vec();

        let keys = self.storage.list_keys("alerts".to_string()).await?;
        let mut alerts = Vec::new();

        for key in keys {
            if let Some(record) = self
                .storage
                .get_record("alerts".to_string(), key, sk_vec.clone())
                .await?
            {
                if let Ok(alert) = Self::record_to_alert(record) {
                    alerts.push(alert);
                }
            }
        }

        alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(alerts.into_iter().take(limit).collect())
    }

    fn record_to_alert(record: Record) -> Result<SecurityAlert> {
        let timestamp_str = record.data.get("timestamp").context("Missing timestamp")?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
            .context("Invalid timestamp format")?
            .with_timezone(&chrono::Utc);

        let mut metadata = HashMap::new();
        for (k, v) in &record.data {
            if let Some(key) = k.strip_prefix("meta:") {
                metadata.insert(key.to_string(), v.clone());
            }
        }

        Ok(SecurityAlert {
            id: record.id,
            timestamp,
            severity: record.data.get("severity").cloned().unwrap_or_default(),
            title: record.data.get("title").cloned().unwrap_or_default(),
            description: record.data.get("description").cloned().unwrap_or_default(),
            source: record.data.get("source").cloned().unwrap_or_default(),
            metadata,
        })
    }
}
