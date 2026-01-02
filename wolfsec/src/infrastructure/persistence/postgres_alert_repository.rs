// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/infrastructure/persistence/postgres_alert_repository.rs
use crate::domain::entities::{Alert, AlertCategory, AlertSeverity, AlertStatus};
use crate::domain::error::DomainError;
use crate::domain::repositories::AlertRepository;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use uuid::Uuid;

pub struct PostgresAlertRepository {
    pool: PgPool,
}

impl PostgresAlertRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AlertRepository for PostgresAlertRepository {
    async fn save(&self, alert: &Alert) -> Result<(), DomainError> {
        let details_json = serde_json::to_value(&alert.details)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        // Serialize enums to strings for database storage
        let severity_str = serde_json::to_string(&alert.severity)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?
            .trim_matches('"')
            .to_string();
        let category_str = serde_json::to_string(&alert.category)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?
            .trim_matches('"')
            .to_string();
        let status_str = serde_json::to_string(&alert.status)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?
            .trim_matches('"')
            .to_string();

        sqlx::query(
            r#"
            INSERT INTO alerts (id, timestamp, severity, category, title, description, source, status, details, acknowledged_by, resolved_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                timestamp = $2,
                severity = $3,
                category = $4,
                title = $5,
                description = $6,
                source = $7,
                status = $8,
                details = $9,
                acknowledged_by = $10,
                resolved_by = $11
            "#,
        )
        .bind(alert.id)
        .bind(alert.timestamp)
        .bind(severity_str)
        .bind(category_str)
        .bind(&alert.title)
        .bind(&alert.description)
        .bind(&alert.source)
        .bind(status_str)
        .bind(details_json)
        .bind(&alert.acknowledged_by)
        .bind(&alert.resolved_by)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        Ok(())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Alert>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, timestamp, severity, category, title, description, source, status, details, acknowledged_by, resolved_by
            FROM alerts
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        if let Some(row) = row {
            let details: HashMap<String, String> = serde_json::from_value(row.try_get("details")?)?;

            let severity_str: String = row.try_get("severity")?; // Corrected typo here
            let category_str: String = row.try_get("category")?;
            let status_str: String = row.try_get("status")?;

            let severity: AlertSeverity =
                serde_json::from_value(serde_json::Value::String(severity_str))
                    .map_err(|e| DomainError::Unexpected(format!("Invalid severity: {}", e)))?;

            let category: AlertCategory =
                serde_json::from_value(serde_json::Value::String(category_str))
                    .map_err(|e| DomainError::Unexpected(format!("Invalid category: {}", e)))?;

            let status: AlertStatus = serde_json::from_value(serde_json::Value::String(status_str))
                .map_err(|e| DomainError::Unexpected(format!("Invalid status: {}", e)))?;

            Ok(Some(Alert {
                id: row.try_get("id")?,
                timestamp: row.try_get("timestamp")?,
                severity,
                category,
                title: row.try_get("title")?,
                description: row.try_get("description")?,
                source: row.try_get("source")?,
                status,
                details,
                acknowledged_by: row.try_get("acknowledged_by")?,
                resolved_by: row.try_get("resolved_by")?,
            }))
        } else {
            Ok(None)
        }
    }
}
