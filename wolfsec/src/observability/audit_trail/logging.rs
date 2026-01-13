use crate::observability::audit_trail::{AuditConfig, AuditEvent, AuditQuery};
use anyhow::Result;

pub struct AuditLogger;

impl AuditLogger {
    pub fn new(_config: AuditConfig) -> Result<Self> {
        Ok(Self)
    }

    pub async fn log_event(&self, _event: AuditEvent) -> Result<()> {
        Ok(())
    }

    pub async fn query_events(&self, _query: AuditQuery) -> Result<Vec<AuditEvent>> {
        Ok(Vec::new())
    }
}
