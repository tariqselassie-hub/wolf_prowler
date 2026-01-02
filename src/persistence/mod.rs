//! Database persistence layer for Wolf Prowler
//!
//! Provides PostgreSQL persistence for all Wolf Prowler data including:
//! - Peer information and metrics
//! - Security events and alerts
//! - Audit logs
//! - Configuration
//! - Wolf Pack hierarchy

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tracing::{debug, info};
use uuid::Uuid;

pub mod models;
pub use models::*;

/// Database connection pool manager
#[derive(Clone)]
pub struct PersistenceManager {
    pool: PgPool,
}

impl PersistenceManager {
    /// Create a new persistence manager with connection pool
    pub async fn new(database_url: &str) -> Result<Self> {
        info!(
            "Connecting to database: {}",
            database_url.split('@').last().unwrap_or("***")
        );

        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .idle_timeout(std::time::Duration::from_secs(600))
            .max_lifetime(std::time::Duration::from_secs(1800))
            .connect(database_url)
            .await
            .context("Failed to connect to database")?;

        info!("Database connection pool established");

        // Run migrations
        Self::run_migrations(&pool).await?;

        Ok(Self { pool })
    }

    /// Run database migrations
    async fn run_migrations(pool: &PgPool) -> Result<()> {
        info!("Running database migrations...");

        sqlx::migrate!("./migrations")
            .run(pool)
            .await
            .context("Failed to run database migrations")?;

        info!("Database migrations applied successfully");
        Ok(())
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Health check - verify database connectivity
    pub async fn health_check(&self) -> Result<bool> {
        let result: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&self.pool).await?;
        Ok(result == 1)
    }

    /// Resolve an org_key to an org_id
    pub async fn resolve_org_key(&self, org_key: &str) -> Result<Option<Uuid>> {
        let org_id =
            sqlx::query_scalar::<_, Uuid>("SELECT org_id FROM organizations WHERE org_key = $1")
                .bind(org_key)
                .fetch_optional(&self.pool)
                .await?;

        Ok(org_id)
    }

    // ========================================================================
    // ORGANIZATION OPERATIONS
    // ========================================================================

    /// Create a new organization
    pub async fn create_organization(
        &self,
        name: &str,
        email: Option<&str>,
        org_key: &str,
    ) -> Result<Uuid> {
        let org_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO organizations (org_id, name, admin_email, org_key, status)
            VALUES ($1, $2, $3, $4, 'active')
            "#,
        )
        .bind(org_id)
        .bind(name)
        .bind(email)
        .bind(org_key)
        .execute(&self.pool)
        .await?;

        Ok(org_id)
    }

    /// Get organization by ID
    pub async fn get_organization(&self, org_id: Uuid) -> Result<Option<DbOrganization>> {
        let org = sqlx::query_as::<_, DbOrganization>(
            "SELECT org_id, name, org_key, admin_email, status, created_at, updated_at FROM organizations WHERE org_id = $1"
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(org)
    }

    /// Get organization by its API key
    pub async fn get_organization_by_key(&self, org_key: &str) -> Result<Option<DbOrganization>> {
        let org = sqlx::query_as::<_, DbOrganization>(
            "SELECT org_id, name, org_key, admin_email, status, created_at, updated_at FROM organizations WHERE org_key = $1"
        )
        .bind(org_key)
        .fetch_optional(&self.pool)
        .await?;

        Ok(org)
    }

    /// List all organizations
    pub async fn list_organizations(&self) -> Result<Vec<DbOrganization>> {
        let orgs = sqlx::query_as::<_, DbOrganization>(
            "SELECT org_id, name, org_key, admin_email, status, created_at, updated_at FROM organizations ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(orgs)
    }

    /// Update organization status
    pub async fn update_organization_status(&self, org_id: Uuid, status: &str) -> Result<()> {
        sqlx::query(
            "UPDATE organizations SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE org_id = $2"
        )
        .bind(status)
        .bind(org_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ========================================================================
    // PEER OPERATIONS
    // ========================================================================

    /// Save or update peer information
    pub async fn save_peer(&self, peer: &DbPeer) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO peers (
                org_id, peer_id, service_type, system_type, version, status, 
                trust_score, protocol_version, agent_version, capabilities, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (peer_id) DO UPDATE SET
                org_id = EXCLUDED.org_id,
                status = EXCLUDED.status,
                trust_score = EXCLUDED.trust_score,
                last_seen = CURRENT_TIMESTAMP,
                protocol_version = EXCLUDED.protocol_version,
                agent_version = EXCLUDED.agent_version,
                capabilities = EXCLUDED.capabilities,
                metadata = EXCLUDED.metadata,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(&peer.org_id)
        .bind(&peer.peer_id)
        .bind(&peer.service_type)
        .bind(&peer.system_type)
        .bind(&peer.version)
        .bind(&peer.status)
        .bind(&peer.trust_score)
        .bind(&peer.protocol_version)
        .bind(&peer.agent_version)
        .bind(&peer.capabilities)
        .bind(&peer.metadata)
        .execute(&self.pool)
        .await
        .context("Failed to save peer")?;

        debug!("Saved peer: {}", peer.peer_id);
        Ok(())
    }

    /// Save multiple peers in a batch
    pub async fn save_peers_batch(&self, peers: &[DbPeer]) -> Result<()> {
        if peers.is_empty() {
            return Ok(());
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        for peer in peers {
            sqlx::query(
                r#"
                INSERT INTO peers (
                    org_id, peer_id, service_type, system_type, version, status, 
                    trust_score, protocol_version, agent_version, capabilities, metadata
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (peer_id) DO UPDATE SET
                    org_id = EXCLUDED.org_id,
                    status = EXCLUDED.status,
                    trust_score = EXCLUDED.trust_score,
                    last_seen = CURRENT_TIMESTAMP,
                    protocol_version = EXCLUDED.protocol_version,
                    agent_version = EXCLUDED.agent_version,
                    capabilities = EXCLUDED.capabilities,
                    metadata = EXCLUDED.metadata,
                    updated_at = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&peer.org_id)
            .bind(&peer.peer_id)
            .bind(&peer.service_type)
            .bind(&peer.system_type)
            .bind(&peer.version)
            .bind(&peer.status)
            .bind(&peer.trust_score)
            .bind(&peer.protocol_version)
            .bind(&peer.agent_version)
            .bind(&peer.capabilities)
            .bind(&peer.metadata)
            .execute(&mut *tx)
            .await
            .context("Failed to save peer in batch")?;
        }

        tx.commit().await.context("Failed to commit transaction")?;
        debug!("Batch saved {} peers", peers.len());
        Ok(())
    }

    pub async fn get_all_peers(&self, org_id: Uuid) -> Result<Vec<DbPeer>> {
        let peers = sqlx::query_as::<_, DbPeer>(
            r#"
            SELECT org_id, peer_id, service_type, system_type, version, status, 
                   trust_score, first_seen, last_seen, protocol_version, agent_version, 
                   capabilities, metadata, created_at, updated_at
            FROM peers
            WHERE org_id = $1
            ORDER BY last_seen DESC
            "#,
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(peers)
    }

    /// Get peer by ID
    pub async fn get_peer(&self, _org_id: Uuid, peer_id: &str) -> Result<Option<DbPeer>> {
        let peer = sqlx::query_as::<_, DbPeer>(
            r#"
            SELECT org_id, peer_id, service_type, system_type, version, status,
                   trust_score, first_seen, last_seen, protocol_version, agent_version,
                   capabilities, metadata, created_at, updated_at
            FROM peers
            WHERE peer_id = $1
            "#,
        )
        .bind(peer_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(peer)
    }

    pub async fn get_active_peers(&self, org_id: Uuid) -> Result<Vec<DbPeer>> {
        let peers = sqlx::query_as::<_, DbPeer>(
            r#"
            SELECT org_id, peer_id, service_type, system_type, version, status,
                   trust_score, first_seen, last_seen, protocol_version,
                   agent_version, capabilities, metadata, created_at, updated_at
            FROM peers
            WHERE org_id = $1 AND status = 'online'
            ORDER BY last_seen DESC
            "#,
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(peers)
    }

    /// Save peer metrics
    pub async fn save_peer_metrics(&self, metrics: &DbPeerMetrics) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO peer_metrics (
                org_id, peer_id, latency_ms, messages_sent, messages_received,
                bytes_sent, bytes_received, requests_sent, requests_received,
                requests_success, requests_failed, health_score, uptime_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(metrics.org_id)
        .bind(metrics.peer_id.clone())
        .bind(metrics.latency_ms)
        .bind(metrics.messages_sent)
        .bind(metrics.messages_received)
        .bind(metrics.bytes_sent)
        .bind(metrics.bytes_received)
        .bind(metrics.requests_sent)
        .bind(metrics.requests_received)
        .bind(metrics.requests_success)
        .bind(metrics.requests_failed)
        .bind(metrics.health_score)
        .bind(metrics.uptime_ms)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Save multiple peer metrics in a batch
    pub async fn save_peer_metrics_batch(&self, metrics_list: &[DbPeerMetrics]) -> Result<()> {
        if metrics_list.is_empty() {
            return Ok(());
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        for metrics in metrics_list {
            sqlx::query(
                r#"
                INSERT INTO peer_metrics (
                    peer_id, latency_ms, messages_sent, messages_received,
                    bytes_sent, bytes_received, requests_sent, requests_received,
                    requests_success, requests_failed, health_score, uptime_ms
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                "#,
            )
            .bind(metrics.peer_id.clone())
            .bind(metrics.latency_ms)
            .bind(metrics.messages_sent)
            .bind(metrics.messages_received)
            .bind(metrics.bytes_sent)
            .bind(metrics.bytes_received)
            .bind(metrics.requests_sent)
            .bind(metrics.requests_received)
            .bind(metrics.requests_success)
            .bind(metrics.requests_failed)
            .bind(metrics.health_score)
            .bind(metrics.uptime_ms)
            .execute(&mut *tx)
            .await
            .context("Failed to save peer metrics in batch")?;
        }

        tx.commit().await.context("Failed to commit transaction")?;
        debug!("Batch saved {} peer metrics", metrics_list.len());
        Ok(())
    }

    // ========================================================================
    // SECURITY OPERATIONS
    // ========================================================================

    /// Save security event
    pub async fn save_security_event(&self, event: &DbSecurityEvent) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_events (
                org_id, event_type, severity, source, peer_id, description, details
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(event.org_id)
        .bind(event.event_type.clone())
        .bind(event.severity.clone())
        .bind(event.source.clone())
        .bind(event.peer_id.clone())
        .bind(event.description.clone())
        .bind(event.details.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Save security alert
    pub async fn save_security_alert(&self, alert: &DbSecurityAlert) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_alerts (
                org_id, severity, status, title, message, category, source, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(alert.org_id)
        .bind(alert.severity.clone())
        .bind(alert.status.clone())
        .bind(alert.title.clone())
        .bind(alert.message.clone())
        .bind(alert.category.clone())
        .bind(alert.source.clone())
        .bind(alert.metadata.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get recent security alerts scoped by org_id
    pub async fn get_recent_alerts(
        &self,
        org_id: Uuid,
        limit: i64,
    ) -> Result<Vec<DbSecurityAlert>> {
        let alerts = sqlx::query_as::<_, DbSecurityAlert>(
            r#"
            SELECT id, org_id, alert_id, timestamp, severity, status, title, message,
                   category, source, escalation_level, acknowledged_by,
                   acknowledged_at, resolved_by, resolved_at, metadata
            FROM security_alerts
            WHERE org_id = $1
            ORDER BY timestamp DESC
            LIMIT $2
            "#,
        )
        .bind(org_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(alerts)
    }

    /// Get active alerts by severity
    pub async fn get_alerts_by_severity(&self, severity: &str) -> Result<Vec<DbSecurityAlert>> {
        let alerts = sqlx::query_as::<_, DbSecurityAlert>(
            r#"
            SELECT id, org_id, alert_id, timestamp, severity, status, title, message,
                   category, source, escalation_level, acknowledged_by,
                   acknowledged_at, resolved_by, resolved_at, metadata
            FROM security_alerts
            WHERE severity = $1 AND status = 'active'
            ORDER BY timestamp DESC
            "#,
        )
        .bind(severity)
        .fetch_all(&self.pool)
        .await?;

        Ok(alerts)
    }

    // ========================================================================
    // AUDIT OPERATIONS
    // ========================================================================

    /// Save audit log entry
    pub async fn save_audit_log(&self, log: &DbAuditLog) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                org_id, action, actor, resource, resource_type, result, details, ip_address, user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(log.org_id)
        .bind(log.action.clone())
        .bind(log.actor.clone())
        .bind(log.resource.clone())
        .bind(log.resource_type.clone())
        .bind(log.result.clone())
        .bind(log.details.clone())
        .bind(log.ip_address.clone())
        .bind(log.user_agent.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get audit logs for a specific actor
    pub async fn get_audit_logs_by_actor(
        &self,
        actor: &str,
        limit: i64,
    ) -> Result<Vec<DbAuditLog>> {
        let logs = sqlx::query_as::<_, DbAuditLog>(
            r#"
            SELECT id, org_id, timestamp, action, actor, resource, resource_type,
                   result, details, ip_address, user_agent
            FROM audit_logs
            WHERE actor = $1
            ORDER BY timestamp DESC
            LIMIT $2
            "#,
        )
        .bind(actor)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    // ========================================================================
    // SIEM OPERATIONS
    // ========================================================================

    /// Store SIEM security event
    pub async fn store_siem_event(
        &self,
        event: &wolfsec::security::advanced::siem::SecurityEvent,
    ) -> Result<()> {
        let db_event = DbSecurityEvent::from_siem_event(event);

        sqlx::query(
            r#"
            INSERT INTO security_events (
                org_id, event_id, timestamp, event_type, severity, source,
                peer_id, description, details, resolved
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(db_event.org_id)
        .bind(db_event.event_id)
        .bind(db_event.timestamp)
        .bind(db_event.event_type.clone())
        .bind(db_event.severity.clone())
        .bind(db_event.source.clone())
        .bind(db_event.peer_id.clone())
        .bind(db_event.description.clone())
        .bind(db_event.details.clone())
        .bind(db_event.resolved)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Query SIEM events with filters
    pub async fn query_siem_events(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        severity: Option<&str>,
        event_type: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DbSecurityEvent>> {
        let events = if let (Some(sev), Some(evt)) = (severity, event_type) {
            sqlx::query_as::<_, DbSecurityEvent>(
                r#"
                SELECT id, org_id, event_id, timestamp, event_type, severity, source,
                       peer_id, description, details, resolved, resolved_at, resolved_by
                FROM security_events
                WHERE timestamp >= $1 AND timestamp <= $2
                  AND severity = $3 AND event_type LIKE $4
                ORDER BY timestamp DESC
                LIMIT $5
                "#,
            )
            .bind(start)
            .bind(end)
            .bind(sev)
            .bind(format!("%{}%", evt))
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else if let Some(sev) = severity {
            sqlx::query_as::<_, DbSecurityEvent>(
                r#"
                SELECT id, org_id, event_id, timestamp, event_type, severity, source,
                       peer_id, description, details, resolved, resolved_at, resolved_by
                FROM security_events
                WHERE timestamp >= $1 AND timestamp <= $2 AND severity = $3
                ORDER BY timestamp DESC
                LIMIT $4
                "#,
            )
            .bind(start)
            .bind(end)
            .bind(sev)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else if let Some(evt) = event_type {
            sqlx::query_as::<_, DbSecurityEvent>(
                r#"
                SELECT id, org_id, event_id, timestamp, event_type, severity, source,
                       peer_id, description, details, resolved, resolved_at, resolved_by
                FROM security_events
                WHERE timestamp >= $1 AND timestamp <= $2 AND event_type LIKE $3
                ORDER BY timestamp DESC
                LIMIT $4
                "#,
            )
            .bind(start)
            .bind(end)
            .bind(format!("%{}%", evt))
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, DbSecurityEvent>(
                r#"
                SELECT id, org_id, event_id, timestamp, event_type, severity, source,
                       peer_id, description, details, resolved, resolved_at, resolved_by
                FROM security_events
                WHERE timestamp >= $1 AND timestamp <= $2
                ORDER BY timestamp DESC
                LIMIT $3
                "#,
            )
            .bind(start)
            .bind(end)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(events)
    }

    /// Get recent SIEM events
    pub async fn get_recent_siem_events(&self, limit: i64) -> Result<Vec<DbSecurityEvent>> {
        let events = sqlx::query_as::<_, DbSecurityEvent>(
            r#"
            SELECT id, org_id, event_id, timestamp, event_type, severity, source,
                   peer_id, description, details, resolved, resolved_at, resolved_by
            FROM security_events
            ORDER BY timestamp DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    /// Mark SIEM event as resolved
    pub async fn resolve_siem_event(&self, event_id: uuid::Uuid, resolved_by: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE security_events
            SET resolved = true,
                resolved_at = CURRENT_TIMESTAMP,
                resolved_by = $2
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .bind(resolved_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ========================================================================
    // CONFIGURATION OPERATIONS
    // ========================================================================

    /// Get configuration value
    pub async fn get_config(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let value = sqlx::query_scalar(
            r#"
            SELECT value FROM config WHERE key = $1
            "#,
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;

        Ok(value)
    }

    /// Set configuration value
    pub async fn set_config(
        &self,
        key: &str,
        value: serde_json::Value,
        updated_by: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO config (key, value, updated_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                updated_by = EXCLUDED.updated_by,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(updated_by)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ========================================================================
    // WOLF PACK OPERATIONS
    // ========================================================================

    /// Save or update pack member
    pub async fn save_pack_member(&self, member: &DbPackMember) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO pack_members (org_id, peer_id, rank, pack_name, contributions)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (peer_id) DO UPDATE SET
                org_id = EXCLUDED.org_id,
                rank = EXCLUDED.rank,
                pack_name = EXCLUDED.pack_name,
                last_active = CURRENT_TIMESTAMP,
                contributions = EXCLUDED.contributions
            "#,
        )
        .bind(member.org_id)
        .bind(member.peer_id.clone())
        .bind(member.rank.clone())
        .bind(member.pack_name.clone())
        .bind(member.contributions.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all pack members
    pub async fn get_pack_members(&self, pack_name: &str) -> Result<Vec<DbPackMember>> {
        let members = sqlx::query_as::<_, DbPackMember>(
            r#"
            SELECT org_id, peer_id, rank, pack_name, joined_at, last_active, contributions
            FROM pack_members
            WHERE pack_name = $1
            ORDER BY 
                CASE rank
                    WHEN 'alpha' THEN 1
                    WHEN 'beta' THEN 2
                    WHEN 'delta' THEN 3
                    WHEN 'scout' THEN 4
                    WHEN 'hunter' THEN 5
                    WHEN 'guardian' THEN 6
                    WHEN 'omega' THEN 7
                    ELSE 8
                END
            "#,
        )
        .bind(pack_name)
        .fetch_all(&self.pool)
        .await?;

        Ok(members)
    }

    // ========================================================================
    // SYSTEM LOGS
    // ========================================================================

    /// Save system log
    pub async fn save_system_log(&self, log: &DbSystemLog) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO system_logs (org_id, level, message, source, metadata)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(log.org_id)
        .bind(log.level.clone())
        .bind(log.message.clone())
        .bind(log.source.clone())
        .bind(log.metadata.clone())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get recent system logs
    pub async fn get_recent_logs(&self, limit: i64) -> Result<Vec<DbSystemLog>> {
        let logs = sqlx::query_as::<_, DbSystemLog>(
            r#"
            SELECT id, org_id, timestamp, level, message, source, metadata
            FROM system_logs
            ORDER BY timestamp DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    // ========================================================================
    // CLEANUP OPERATIONS
    // ========================================================================

    /// Clean up old data based on retention policies
    pub async fn cleanup_old_data(&self, _days: i32) -> Result<u64> {
        let mut total_deleted = 0u64;

        // Clean old peer metrics (keep last 30 days)
        let result = sqlx::query(
            "DELETE FROM peer_metrics WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '30 days'",
        )
        .execute(&self.pool)
        .await?;
        total_deleted += result.rows_affected();

        // Clean resolved security events (keep last 90 days)
        let result = sqlx::query(
            "DELETE FROM security_events WHERE resolved = true AND timestamp < CURRENT_TIMESTAMP - INTERVAL '90 days'"
        )
        .execute(&self.pool)
        .await?;
        total_deleted += result.rows_affected();

        // Clean old system logs (keep last 7 days)
        let result = sqlx::query(
            "DELETE FROM system_logs WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '7 days'",
        )
        .execute(&self.pool)
        .await?;
        total_deleted += result.rows_affected();

        info!("Cleaned up {} old records", total_deleted);
        Ok(total_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires database connection
    async fn test_database_connection() {
        let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler".to_string()
        });

        let pm = PersistenceManager::new(&db_url).await.unwrap();
        assert!(pm.health_check().await.unwrap());
    }
}
