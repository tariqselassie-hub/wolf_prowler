// /home/t4riq/Desktop/Rust/wolf_prowler/wolfsec/src/infrastructure/persistence/postgres_threat_repository.rs
use crate::domain::entities::{Threat, ThreatSeverity, ThreatType};
use crate::domain::error::DomainError;
use crate::domain::repositories::ThreatRepository;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use uuid::Uuid;

pub struct PostgresThreatRepository {
    pool: PgPool,
}

impl PostgresThreatRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ThreatRepository for PostgresThreatRepository {
    async fn save(&self, threat: &Threat) -> Result<(), DomainError> {
        let mitigation_steps_json = serde_json::to_value(&threat.mitigation_steps)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
        let related_events_json = serde_json::to_value(&threat.related_events)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;
        let metadata_json = serde_json::to_value(&threat.metadata)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        let threat_type_str = serde_json::to_string(&threat.threat_type)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?
            .trim_matches('"')
            .to_string();
        let severity_str = serde_json::to_string(&threat.severity)
            .map_err(|e| DomainError::Unexpected(e.to_string()))?
            .trim_matches('"')
            .to_string();

        sqlx::query(
            r#"
            INSERT INTO threats (
                id, threat_type, severity, description, source_peer, target_asset,
                detected_at, confidence, mitigation_steps, related_events, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                threat_type = $2, severity = $3, description = $4, source_peer = $5,
                target_asset = $6, detected_at = $7, confidence = $8,
                mitigation_steps = $9, related_events = $10, metadata = $11
            "#,
        )
        .bind(threat.id)
        .bind(threat_type_str)
        .bind(severity_str)
        .bind(&threat.description)
        .bind(&threat.source_peer)
        .bind(&threat.target_asset)
        .bind(threat.detected_at)
        .bind(threat.confidence)
        .bind(mitigation_steps_json)
        .bind(related_events_json)
        .bind(metadata_json)
        .execute(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        Ok(())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Threat>, DomainError> {
        let row = sqlx::query(
            r#"
            SELECT id, threat_type, severity, description, source_peer, target_asset,
                   detected_at, confidence, mitigation_steps, related_events, metadata
            FROM threats
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::Unexpected(e.to_string()))?;

        if let Some(row) = row {
            let threat_type_str: String = row.try_get("threat_type")?;
            let severity_str: String = row.try_get("severity")?;

            let threat_type: ThreatType =
                serde_json::from_value(serde_json::Value::String(threat_type_str))
                    .map_err(|e| DomainError::Unexpected(format!("Invalid threat_type: {}", e)))?;
            let severity: ThreatSeverity =
                serde_json::from_value(serde_json::Value::String(severity_str))
                    .map_err(|e| DomainError::Unexpected(format!("Invalid severity: {}", e)))?;

            let mitigation_steps: Vec<String> =
                serde_json::from_value(row.try_get("mitigation_steps")?)?;
            let related_events: Vec<Uuid> = serde_json::from_value(row.try_get("related_events")?)?;
            let metadata: HashMap<String, String> =
                serde_json::from_value(row.try_get("metadata")?)?;

            Ok(Some(Threat {
                id: row.try_get("id")?,
                threat_type,
                severity,
                description: row.try_get("description")?,
                source_peer: row.try_get("source_peer")?,
                target_asset: row.try_get("target_asset")?,
                detected_at: row.try_get("detected_at")?,
                confidence: row.try_get("confidence")?,
                mitigation_steps,
                related_events,
                metadata,
            }))
        } else {
            Ok(None)
        }
    }
}
