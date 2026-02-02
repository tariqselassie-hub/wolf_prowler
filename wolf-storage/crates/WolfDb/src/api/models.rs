use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Authentication
// ============================================================================

/// Request to initialize the database keystore
#[derive(Debug, Deserialize)]
pub struct InitRequest {
    /// Password to encrypt the master key
    pub password: String,
    /// Optional HSM PIN if an HSM is used for wrapping the master key
    pub hsm_pin: Option<String>,
}

/// Request to unlock the database
#[derive(Debug, Deserialize)]
pub struct UnlockRequest {
    /// Password to decrypt the master key
    pub password: String,
    /// Optional HSM PIN if an HSM is used for wrapping the master key
    pub hsm_pin: Option<String>,
}

/// Response containing authentication details after successful login or initialization
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    /// Session token for subsequent requests
    pub session_token: String,
    /// Unix timestamp when the session token expires
    pub expires_at: i64,
}

/// Response containing the current database status
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    /// Whether the database is currently locked (keys not in memory)
    pub locked: bool,
    /// Whether the database has been initialized with a master key
    pub initialized: bool,
}

// ============================================================================
// Records
// ============================================================================

/// Request to insert a single record
#[derive(Debug, Deserialize)]
pub struct RecordRequest {
    /// Unique identifier for the record
    pub id: String,
    /// Key-value pairs for relational/metadata fields
    pub data: HashMap<String, String>,
    /// Optional vector embedding for similarity search
    pub vector: Option<Vec<f32>>,
    /// Partition type: "relational", "vector", or "hybrid" (default)
    pub partition: Option<String>,
}

/// Request to insert multiple records into a table
#[derive(Debug, Deserialize)]
pub struct BatchRecordRequest {
    /// Target table name
    pub table: String,
    /// List of records to insert
    pub records: Vec<RecordRequest>,
    /// Partition type: "relational", "vector", or "hybrid" (default)
    pub partition: Option<String>,
}

/// Response containing a single record's data
#[derive(Debug, Serialize)]
pub struct RecordResponse {
    /// Unique identifier for the record
    pub id: String,
    /// Key-value pairs for relational/metadata fields
    pub data: HashMap<String, String>,
    /// Optional vector embedding
    pub vector: Option<Vec<f32>>,
}

/// Response containing a paginated list of records
#[derive(Debug, Serialize)]
pub struct RecordListResponse {
    /// List of records in the current page
    pub records: Vec<RecordResponse>,
    /// Total number of records across all pages
    pub total: usize,
    /// Current page index
    pub page: usize,
    /// Maximum number of records per page
    pub limit: usize,
}

// ============================================================================
// Queries
// ============================================================================

/// Request to query records by exact metadata match
#[derive(Debug, Deserialize)]
pub struct MetadataQueryRequest {
    /// Table to search in
    pub table: String,
    /// Metadata field name to match
    pub field: String,
    /// Value to match exactly
    pub value: String,
    /// Partition type: "relational", "vector", or "hybrid" (default)
    pub partition: Option<String>,
}

/// Request to perform a hybrid search (vector + metadata filter)
#[derive(Debug, Deserialize)]
pub struct HybridSearchRequest {
    /// Table to search in
    pub table: String,
    /// Query vector for similarity search
    pub vector: Vec<f32>,
    /// Number of nearest neighbors to return
    pub k: usize,
    /// Metadata field for filtering
    pub filter_field: String,
    /// Exact value for metadata filtering
    pub filter_value: String,
    /// Partition type: must support vectors ("vector" or "hybrid")
    pub partition: Option<String>,
}

/// Single result from a search operation
#[derive(Debug, Serialize)]
pub struct SearchResult {
    /// The record that matched the search
    pub record: RecordResponse,
    /// Calculated similarity score (e.g., cosine similarity)
    pub similarity: f32,
}

/// Response containing search results
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    /// List of matching results with scores
    pub results: Vec<SearchResult>,
}

// ============================================================================
// Vector Operations
// ============================================================================

/// Request to perform a pure vector similarity search
#[derive(Debug, Deserialize)]
pub struct VectorSearchRequest {
    /// Query vector
    pub vector: Vec<f32>,
    /// Number of nearest neighbors to return
    pub k: usize,
    /// Optional target table
    pub table: Option<String>,
    /// Partition type: must support vectors ("vector" or "hybrid")
    pub partition: Option<String>,
}

/// Statistics for vector storage
#[derive(Debug, Serialize)]
pub struct VectorStatsResponse {
    /// Total number of vectors stored
    pub count: usize,
    /// Estimated size of the vector index in bytes
    pub index_size: usize,
    /// Number of deleted (but not yet compacted) vectors
    pub deleted: usize,
}

// ============================================================================
// Tables
// ============================================================================

/// Summary information about a database table
#[derive(Debug, Serialize)]
pub struct TableInfo {
    /// Name of the table
    pub name: String,
    /// Approximate number of records in the table
    pub record_count: usize,
}

/// Response containing a list of all tables
#[derive(Debug, Serialize)]
pub struct TablesResponse {
    /// List of table information
    pub tables: Vec<TableInfo>,
}

// ============================================================================
// Security
// ============================================================================

/// Request to generate a database backup
#[derive(Debug, Deserialize)]
pub struct BackupRequest {
    /// Password used to encrypt the backup blob
    pub recovery_password: String,
}

/// Response containing the encrypted backup blob
#[derive(Debug, Serialize)]
pub struct BackupResponse {
    /// Base64-encoded encrypted backup blob
    pub blob: String,
}

/// Request to restore the database from a backup
#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
    /// Base64-encoded encrypted backup blob
    pub blob: String,
    /// Password used to decrypt the backup blob
    pub recovery_password: String,
    /// New master password to set after recovery
    pub new_master_password: String,
}

/// Information about the current cryptographic configuration
#[derive(Debug, Serialize)]
pub struct KeystoreInfo {
    /// KEM algorithm name (e.g., Kyber768)
    pub kem_algorithm: String,
    /// Digital Signature algorithm name (e.g., Dilithium2)
    pub dsa_algorithm: String,
    /// Whether a hardware security module is enabled
    pub hsm_enabled: bool,
}

// ============================================================================
// Administration
// ============================================================================

/// Global statistics for the database
#[derive(Debug, Serialize)]
pub struct DatabaseStats {
    /// Summary of all tables
    pub tables: Vec<TableInfo>,
    /// Total record count across all tables
    pub total_records: usize,
    /// Vector-specific statistics
    pub vector_stats: VectorStatsResponse,
    /// Current status of PQC integrity checks
    pub pqc_status: String,
}

/// Request to import data from an external `SQLite` database file
#[derive(Debug, Deserialize)]
pub struct ImportSqliteRequest {
    /// Path to the `SQLite` .db file on the server
    pub path: String,
}

/// Response summarizing the result of a data import
#[derive(Debug, Serialize)]
pub struct ImportResponse {
    /// Number of tables successfully imported
    pub tables_imported: usize,
    /// Total number of records successfully imported
    pub records_imported: usize,
}

// ============================================================================
// Error Response
// ============================================================================

/// Generic error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// High-level error message
    pub error: String,
    /// Optional detailed error information
    pub details: Option<String>,
}

impl ErrorResponse {
    /// Creates a new error response with a message
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: None,
        }
    }

    /// Creates a new error response with a message and detailed information
    pub fn with_details(error: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: Some(details.into()),
        }
    }
}
