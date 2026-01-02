// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/infrastructure/persistence/postgres_monitoring_repository.rs
use crate::domain::entities::{monitoring::SecurityEvent, AlertCategory, AlertSeverity};
use crate::domain::error::DomainError;
use crate::domain::repositories::MonitoringRepository;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use uuid::Uuid;

pub struct PostgresMonitoringRepository {
    pool: PgPool,
}

impl PostgresMonitoringRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MonitoringRepository for PostgresMonitoringRepository {
    async fn save_event(&self, event: &SecurityEvent) -> Result<(), DomainError> {
        let details_json = serde_json::to_value(&event.details)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        let severity_str = serde_json::to_string(&event.severity)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?
            .trim_matches('"')
            .to_string();
        let category_str = serde_json::to_string(&event.category)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?
            .trim_matches('"')
            .to_string();

        let event_type = format!("{}: {}", category_str, event.title);

        sqlx::query(
            r#"
            INSERT INTO security_events (id, timestamp, event_type, severity, message, source, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
                timestamp = $2, event_type = $3, severity = $4, message = $5, source = $6, metadata = $7
            "#,
        )
        .bind(event.id)
        .bind(event.timestamp)
        .bind(event_type)
        .bind(severity_str)
        .bind(&event.description)
        .bind(&event.source)
        .bind(details_json)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        Ok(())
    }

    async fn find_event_by_id(&self, id: &Uuid) -> Result<Option<SecurityEvent>, DomainError> {
        let row = sqlx::query("SELECT id, timestamp, event_type, severity, message, source, metadata FROM security_events WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        if let Some(row) = row {
            let details: HashMap<String, String> =
                serde_json::from_value(row.try_get("metadata")?)?;
            let severity_str: String = row.try_get("severity")?;
            let event_type_str: String = row.try_get("event_type")?;
            let (category_str, title) = event_type_str
                .split_once(": ")
                .unwrap_or((&event_type_str, ""));

            let severity: AlertSeverity =
                serde_json::from_value(serde_json::Value::String(severity_str))
                    .map_err(|e| DomainError::Unexpected(format!("Invalid severity: {}", e)))?;
            let category: AlertCategory =
                serde_json::from_value(serde_json::Value::String(category_str.to_string()))
                    .map_err(|e| DomainError::Unexpected(format!("Invalid category: {}", e)))?;

            Ok(Some(SecurityEvent {
                id: row.try_get("id")?,
                timestamp: row.try_get("timestamp")?,
                category,
                severity,
                title: title.to_string(),
                description: row.try_get("message")?,
                source: row.try_get("source")?,
                details,
            }))
        } else {
            Ok(None)
        }
    }
}
