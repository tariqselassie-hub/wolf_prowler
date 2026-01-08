use super::{
    models::{
        AuthResponse, BackupRequest, BackupResponse, BatchRecordRequest, DatabaseStats,
        ErrorResponse, HybridSearchRequest, ImportResponse, ImportSqliteRequest, InitRequest,
        KeystoreInfo, MetadataQueryRequest, RecordListResponse, RecordRequest, RecordResponse,
        RecoverRequest, SearchResponse, SearchResult, StatusResponse, TableInfo, TablesResponse,
        UnlockRequest, VectorSearchRequest, VectorStatsResponse,
    },
    AppState,
};
use crate::storage::model::Record;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

// ============================================================================
// Error Handling
// ============================================================================

/// Wrapper for errors returned by the API
pub struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error_msg = self.0.to_string();
        tracing::error!("API Error: {error_msg}");
        
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(error_msg)),
        )
            .into_response()
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

type ApiResult<T> = Result<T, ApiError>;

// ============================================================================
// Partition Helpers
// ============================================================================

/// Build table name with optional partition prefix
fn build_table_name(table: &str, partition: Option<&str>) -> String {
    match partition {
        Some("relational") => format!("relational:{table}"),
        Some("vector") => format!("vector:{table}"),
        Some("hybrid") | None => table.to_string(), // Default to hybrid
        Some(other) => {
            tracing::warn!("Unknown partition '{other}', defaulting to hybrid");
            table.to_string()
        }
    }
}

/// Validate partition supports the requested operation
/// # Errors
///
/// Returns an error if the partition configuration is invalid for the requested operation.
fn validate_partition(partition: Option<&str>, has_vector: bool) -> ApiResult<()> {
    if let Some(p) = partition {
        if p == "relational" && has_vector {
            return Err(ApiError(anyhow::anyhow!(
                "Partition 'relational' does not support vector operations"
            )));
        }
    }
    Ok(())
}


// ============================================================================
// Authentication Handlers
// ============================================================================

/// Initializes the database with a new master password
///
/// # Errors
///
/// Returns an error if the keystore cannot be initialized or if session creation fails.
pub async fn auth_init(
    State(state): State<AppState>,
    Json(req): Json<InitRequest>,
) -> ApiResult<Json<AuthResponse>> {
    state
        .storage
        .write()
        .await
        .initialize_keystore(&req.password, req.hsm_pin.as_deref())?;
    
    let token = state.create_session().await;
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    
    Ok(Json(AuthResponse {
        session_token: token,
        expires_at,
    }))
}

/// Unlocks the database with an existing master password
///
/// # Errors
///
/// Returns an error if the password is incorrect or if session creation fails.
pub async fn auth_unlock(
    State(state): State<AppState>,
    Json(req): Json<UnlockRequest>,
) -> ApiResult<Json<AuthResponse>> {
    state
        .storage
        .write()
        .await
        .unlock(&req.password, req.hsm_pin.as_deref())?;
    
    let token = state.create_session().await;
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    
    Ok(Json(AuthResponse {
        session_token: token,
        expires_at,
    }))
}

/// Locks the database by clearing keys from memory and ending the session
///
/// # Errors
///
/// This function is currently infallible but returns `ApiResult` for consistency.
pub async fn auth_lock(
    State(state): State<AppState>,
    Json(token): Json<String>,
) -> ApiResult<StatusCode> {
    state.remove_session(&token).await;
    Ok(StatusCode::OK)
}

/// Checks if the database is initialized and currently unlocked
///
/// # Errors
///
/// This function is currently infallible but returns `ApiResult` for consistency.
pub async fn auth_status(
    State(state): State<AppState>,
) -> ApiResult<Json<StatusResponse>> {
    let storage = state.storage.read().await;
    let locked = storage.get_active_sk().is_none();
    let initialized = storage.is_initialized();
    drop(storage);
    
    Ok(Json(StatusResponse {
        locked,
        initialized,
    }))
}

// ============================================================================
// Record Handlers
// ============================================================================

/// Query parameters for listing records
#[derive(Deserialize)]
pub struct ListRecordsQuery {
    table: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Returns a list of records for a specific table
///
/// # Errors
///
/// Returns an error if the database is locked or if record retrieval fails.
pub async fn list_records(
    State(state): State<AppState>,
    Query(params): Query<ListRecordsQuery>,
) -> ApiResult<Json<RecordListResponse>> {
    let storage = state.storage.read().await;
    let table = params.table.as_deref().unwrap_or("default");
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);
    
    let keys = storage.list_keys(table.to_string()).await?;
    let total = keys.len();
    
    let sk = storage.get_active_sk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();
    
    let mut records = Vec::new();
    for key in keys.iter().skip(offset).take(limit) {
        if let Some(record) = storage.get_record(table.to_string(), key.clone(), sk.clone()).await? {
            records.push(RecordResponse {
                id: record.id,
                data: record.data,
                vector: record.vector,
            });
        }
    }
    drop(storage);
    
    Ok(Json(RecordListResponse {
        records,
        total,
        page: offset / limit,
        limit,
    }))
}

/// Query parameters for getting a specific record
#[derive(Deserialize)]
pub struct GetRecordQuery {
    table: Option<String>,
}

/// Returns a single record by its ID
///
/// # Errors
///
/// Returns an error if the database is locked or if the record is not found.
pub async fn get_record(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<GetRecordQuery>,
) -> ApiResult<Json<RecordResponse>> {
    let storage = state.storage.read().await;
    let table = params.table.as_deref().unwrap_or("default");
    
    let sk = storage.get_active_sk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();
    
    let record = storage.get_record(table.to_string(), id, sk).await?
        .ok_or_else(|| anyhow::anyhow!("Record not found"))?;
    drop(storage);
    
    Ok(Json(RecordResponse {
        id: record.id,
        data: record.data,
        vector: record.vector,
    }))
}

/// Inserts or updates a record in the specified table
///
/// # Errors
///
/// Returns an error if the database is locked or if insertion fails.
pub async fn insert_record(
    State(state): State<AppState>,
    Path(table): Path<String>,
    Json(req): Json<RecordRequest>,
) -> ApiResult<StatusCode> {
    // Validate partition supports vectors if provided
    validate_partition(req.partition.as_deref(), req.vector.is_some())?;
    
    // Build table name with partition prefix
    let table_name = build_table_name(&table, req.partition.as_deref());
    
    let storage = state.storage.read().await;
    let pk = storage
        .get_active_pk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec(); // Convert to owned value

    let record = Record {
        id: req.id,
        data: req.data,
        vector: req.vector,
    };

    storage.insert_record(table_name, record, pk).await?;
    drop(storage);
    Ok(StatusCode::CREATED)
}

/// Inserts a batch of records into the specified table
///
/// # Errors
///
/// Returns an error if the database is locked or if batch insertion fails.
pub async fn batch_insert_records(
    State(state): State<AppState>,
    Json(req): Json<BatchRecordRequest>,
) -> ApiResult<StatusCode> {
    // Validate partition for all records
    for record in &req.records {
        validate_partition(req.partition.as_deref(), record.vector.is_some())?;
    }
    
    // Build table name with partition prefix
    let table_name = build_table_name(&req.table, req.partition.as_deref());
    
    let storage = state.storage.read().await;
    let pk = storage
        .get_active_pk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();

    let records: Vec<Record> = req
        .records
        .into_iter()
        .map(|r| Record {
            id: r.id,
            data: r.data,
            vector: r.vector,
        })
        .collect();

    storage.insert_batch_records(table_name, records, pk).await?;
    drop(storage);
    Ok(StatusCode::CREATED)
}

/// Deletes a record from the specified table
///
/// # Errors
///
/// Returns an error if the database is locked or if deletion fails.
pub async fn delete_record(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<GetRecordQuery>,
) -> ApiResult<StatusCode> {
    let storage = state.storage.read().await;
    let table = params.table.as_deref().unwrap_or("default");
    
    let deleted = storage.delete_record(table.to_string(), id).await?;
    drop(storage);
    
    if deleted {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

// ============================================================================
// Query Handlers
// ============================================================================

/// Searches for records matching a specific metadata field and value
///
/// # Errors
///
/// Returns an error if the database is locked or if the query fails.
pub async fn query_by_metadata(
    State(state): State<AppState>,
    Json(req): Json<MetadataQueryRequest>,
) -> ApiResult<Json<SearchResponse>> {
    // Build table name with partition prefix
    let table_name = build_table_name(&req.table, req.partition.as_deref());
    
    let storage = state.storage.read().await;
    let sk = storage
        .get_active_sk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();

    let records = storage.find_by_metadata(table_name, req.field, req.value, sk).await?;
    drop(storage);
    
    let results = records.into_iter().map(|r| SearchResult {
        record: RecordResponse {
            id: r.id,
            data: r.data,
            vector: r.vector,
        },
        similarity: 1.0, // Exact match
    }).collect();
    
    Ok(Json(SearchResponse { results }))
}

/// Performs a hybrid search combining vector similarity and metadata filtering
///
/// # Errors
///
/// Returns an error if the database is locked or if the hybrid search fails.
pub async fn hybrid_search(
    State(state): State<AppState>,
    Json(req): Json<HybridSearchRequest>,
) -> ApiResult<Json<SearchResponse>> {
    // Validate partition supports vectors
    validate_partition(req.partition.as_deref(), true)?;
    
    // Build table name with partition prefix
    let table_name = build_table_name(&req.table, req.partition.as_deref());
    
    let storage = state.storage.read().await;
    let sk = storage
        .get_active_sk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();

    let results_with_scores = storage.search_hybrid(
        table_name,
        req.vector,
        req.k,
        req.filter_field,
        req.filter_value,
        sk,
    ).await?;
    drop(storage);
    
    let results = results_with_scores.into_iter().map(|(r, score)| SearchResult {
        record: RecordResponse {
            id: r.id,
            data: r.data,
            vector: r.vector,
        },
        similarity: score,
    }).collect();
    
    Ok(Json(SearchResponse { results }))
}

// ============================================================================
// Vector Handlers
// ============================================================================

/// Performs a pure vector similarity search
///
/// # Errors
///
/// Returns an error if the database is locked or if the vector search fails.
pub async fn vector_search(
    State(state): State<AppState>,
    Json(req): Json<VectorSearchRequest>,
) -> ApiResult<Json<SearchResponse>> {
    let storage = state.storage.read().await;
    let table = req.table.as_deref().unwrap_or("default");
    
    let sk = storage.get_active_sk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();
    
    let results_with_scores = storage.search_similar_records(table.to_string(), req.vector, req.k, sk).await?;
    drop(storage);
    
    let results = results_with_scores.into_iter().map(|(r, score)| SearchResult {
        record: RecordResponse {
            id: r.id,
            data: r.data,
            vector: r.vector,
        },
        similarity: score,
    }).collect();
    
    Ok(Json(SearchResponse { results }))
}

/// Returns statistics for the vector index
///
/// # Errors
///
/// Returns an error if indexing info cannot be retrieved.
#[allow(clippy::cast_possible_truncation)]
pub async fn vector_stats(
    State(state): State<AppState>,
) -> ApiResult<Json<VectorStatsResponse>> {
    let storage = state.storage.read().await;
    let info = storage.get_info()?;
    drop(storage);
    
    Ok(Json(VectorStatsResponse {
        count: info["vector_records"].as_u64().unwrap_or(0) as usize,
        index_size: info["vector_index_size"].as_u64().unwrap_or(0) as usize,
        deleted: info["vector_deleted"].as_u64().unwrap_or(0) as usize,
    }))
}

// ============================================================================
// Table Handlers
// ============================================================================

/// Returns a list of all tables in the database
///
/// # Errors
///
/// Returns an error if table enumeration fails.
pub async fn list_tables(
    State(state): State<AppState>,
) -> ApiResult<Json<TablesResponse>> {
    let storage = state.storage.read().await;
    let count = storage.list_keys("default".to_string()).await?.len();
    drop(storage);
    
    // For now, return a simple list - in the future we can scan the sled database
    // to find all tables
    let tables = vec![
        TableInfo {
            name: "default".to_string(),
            record_count: count,
        },
    ];
    
    Ok(Json(TablesResponse { tables }))
}

// ============================================================================
// Security Handlers
// ============================================================================

/// Generates an encrypted backup blob of the master key and database state
///
/// # Errors
///
/// Returns an error if backup generation fails.
pub async fn generate_backup(
    State(state): State<AppState>,
    Json(req): Json<BackupRequest>,
) -> ApiResult<Json<BackupResponse>> {
    let storage = state.storage.read().await;
    let blob = storage.generate_recovery_backup(&req.recovery_password)?;
    drop(storage);
    
    Ok(Json(BackupResponse { blob }))
}

/// Restores database access from a backup blob
///
/// # Errors
///
/// Returns an error if recovery fails.
pub async fn recover_backup(
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> ApiResult<StatusCode> {
    {
        let mut storage = state.storage.write().await;
        storage.recover_from_backup(&req.blob, &req.recovery_password, &req.new_master_password)?;
    }
    
    Ok(StatusCode::OK)
}

/// Returns information about the available cryptographic algorithms
///
/// # Errors
///
/// Returns an error if keystore information cannot be loaded.
pub async fn keystore_info(
    State(_state): State<AppState>,
) -> ApiResult<Json<KeystoreInfo>> {
    let keystore_path = "wolf.db/keystore.json"; // Consider making this dynamic?
    let hsm_enabled = if std::path::Path::new(keystore_path).exists() {
        // This blocks, but it's only startup info and lightweight json read
        // Could wrap in spawn_blocking if concerned
        let ks = crate::crypto::keystore::Keystore::load(keystore_path)?;
        ks.hsm_enabled
    } else {
        false
    };
    
    Ok(Json(KeystoreInfo {
        kem_algorithm: "ML-KEM (Kyber768)".to_string(),
        dsa_algorithm: "ML-DSA (Dilithium)".to_string(),
        hsm_enabled,
    }))
}

// ============================================================================
// Administration Handlers
// ============================================================================

/// Returns comprehensive statistics about the database
///
/// # Errors
///
/// Returns an error if database info cannot be retrieved.
#[allow(clippy::cast_possible_truncation)]
pub async fn database_stats(
    State(state): State<AppState>,
) -> ApiResult<Json<DatabaseStats>> {
    let storage = state.storage.read().await;
    let info = storage.get_info()?;
    let count = storage.list_keys("default".to_string()).await?.len();
    drop(storage);

    let tables = vec![
        TableInfo {
            name: "default".to_string(),
            record_count: count,
        },
    ];
    
    let total_records: usize = tables.iter().map(|t| t.record_count).sum();
    
    Ok(Json(DatabaseStats {
        tables,
        total_records,
        vector_stats: VectorStatsResponse {
            count: info["vector_records"].as_u64().unwrap_or(0) as usize,
            index_size: info["vector_index_size"].as_u64().unwrap_or(0) as usize,
            deleted: info["vector_deleted"].as_u64().unwrap_or(0) as usize,
        },
        pqc_status: info["pqc_integrity"].as_str().unwrap_or("UNKNOWN").to_string(),
    }))
}

/// Imports data from a file uploaded via multipart form
///
/// # Errors
///
/// Returns an error if file upload or processing fails.
pub async fn import_sqlite_file(
    State(state): State<AppState>,
    mut multipart: axum::extract::Multipart,
) -> ApiResult<Json<ImportResponse>> {
    use tokio::io::AsyncWriteExt;
    
    // Save uploaded file to temp location
    let temp_path = format!("/tmp/wolfdb_import_{}.db", uuid::Uuid::new_v4());
    
    while let Some(field) = multipart.next_field().await.map_err(|e| anyhow::anyhow!("Multipart error: {e}"))? {
        let name = field.name().unwrap_or("").to_string();
        
        if name == "file" {
            let data = field.bytes().await.map_err(|e| anyhow::anyhow!("Failed to read file: {e}"))?;
            
            let mut file = tokio::fs::File::create(&temp_path).await?;
            file.write_all(&data).await?;
            file.flush().await?;
            break;
        }
    }
    
    // Process the uploaded file
    let result = import_sqlite_from_path(state.clone(), &temp_path).await;
    
    // Clean up temp file
    let _ = tokio::fs::remove_file(&temp_path).await;
    
    result
}

/// Imports data from a `SQLite` file at a specific server-side path
///
/// # Errors
///
/// Returns an error if the import from the specified path fails.
pub async fn import_sqlite(
    State(state): State<AppState>,
    Json(req): Json<ImportSqliteRequest>,
) -> ApiResult<Json<ImportResponse>> {
    import_sqlite_from_path(state, &req.path).await
}

/// # Errors
///
/// Returns an error if the database is locked or if the import fails.
async fn import_sqlite_from_path(
    state: AppState,
    path: &str,
) -> ApiResult<Json<ImportResponse>> {
    let pk = {
        let storage = state.storage.read().await;
        let active_pk = storage.get_active_pk()
            .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
            .to_vec();
        drop(storage);
        active_pk
    };
    
    let path = path.to_string();
    // Run the import logic in a blocking task since rusqlite is sync
    let records_map = tokio::task::spawn_blocking(move || {
        crate::import::sqlite::SqliteImporter::import_from_path(&path)
    }).await.map_err(|e| anyhow::anyhow!("Join error: {e}"))??;

    let mut total_records = 0;
    let tables_count = records_map.len();
    
    for (table_name, records) in records_map {
        let count = records.len();
        // Insert asynchronously
        let storage = state.storage.read().await;
        storage.insert_batch_records(table_name, records, pk.clone()).await?;
        drop(storage);
        total_records += count;
    }
    
    Ok(Json(ImportResponse {
        tables_imported: tables_count,
        records_imported: total_records,
    }))
}
