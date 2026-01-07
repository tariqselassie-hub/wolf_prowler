use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Authentication
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub password: String,
    pub hsm_pin: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UnlockRequest {
    pub password: String,
    pub hsm_pin: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub session_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub locked: bool,
    pub initialized: bool,
}

// ============================================================================
// Records
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RecordRequest {
    pub id: String,
    pub data: HashMap<String, String>,
    pub vector: Option<Vec<f32>>,
    /// Partition type: "relational", "vector", or "hybrid" (default)
    pub partition: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BatchRecordRequest {
    pub table: String,
    pub records: Vec<RecordRequest>,
    /// Partition type: "relational", "vector", or "hybrid" (default)
    pub partition: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RecordResponse {
    pub id: String,
    pub data: HashMap<String, String>,
    pub vector: Option<Vec<f32>>,
}

#[derive(Debug, Serialize)]
pub struct RecordListResponse {
    pub records: Vec<RecordResponse>,
    pub total: usize,
    pub page: usize,
    pub limit: usize,
}

// ============================================================================
// Queries
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct MetadataQueryRequest {
    pub table: String,
    pub field: String,
    pub value: String,
    /// Partition type: "relational", "vector", or "hybrid" (default)
    pub partition: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HybridSearchRequest {
    pub table: String,
    pub vector: Vec<f32>,
    pub k: usize,
    pub filter_field: String,
    pub filter_value: String,
    /// Partition type: must support vectors ("vector" or "hybrid")
    pub partition: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub record: RecordResponse,
    pub similarity: f32,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
}

// ============================================================================
// Vector Operations
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct VectorSearchRequest {
    pub vector: Vec<f32>,
    pub k: usize,
    pub table: Option<String>,
    /// Partition type: must support vectors ("vector" or "hybrid")
    pub partition: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VectorStatsResponse {
    pub count: usize,
    pub index_size: usize,
    pub deleted: usize,
}

// ============================================================================
// Tables
// ============================================================================

#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub record_count: usize,
}

#[derive(Debug, Serialize)]
pub struct TablesResponse {
    pub tables: Vec<TableInfo>,
}

// ============================================================================
// Security
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct BackupRequest {
    pub recovery_password: String,
}

#[derive(Debug, Serialize)]
pub struct BackupResponse {
    pub blob: String,
}

#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
    pub blob: String,
    pub recovery_password: String,
    pub new_master_password: String,
}

#[derive(Debug, Serialize)]
pub struct KeystoreInfo {
    pub kem_algorithm: String,
    pub dsa_algorithm: String,
    pub hsm_enabled: bool,
}

// ============================================================================
// Administration
// ============================================================================

#[derive(Debug, Serialize)]
pub struct DatabaseStats {
    pub tables: Vec<TableInfo>,
    pub total_records: usize,
    pub vector_stats: VectorStatsResponse,
    pub pqc_status: String,
}

#[derive(Debug, Deserialize)]
pub struct ImportSqliteRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct ImportResponse {
    pub tables_imported: usize,
    pub records_imported: usize,
}

// ============================================================================
// Error Response
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub details: Option<String>,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: None,
        }
    }

    pub fn with_details(error: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: Some(details.into()),
        }
    }
}
