use super::{models::*, AppState};
use crate::storage::model::Record;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::HashMap;

// ============================================================================
// Error Handling
// ============================================================================

pub struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error_msg = self.0.to_string();
        tracing::error!("API Error: {}", error_msg);
        
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
        Some("relational") => format!("relational:{}", table),
        Some("vector") => format!("vector:{}", table),
        Some("hybrid") | None => table.to_string(), // Default to hybrid
        Some(other) => {
            tracing::warn!("Unknown partition '{}', defaulting to hybrid", other);
            table.to_string()
        }
    }
}

/// Validate partition supports the requested operation
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

pub async fn auth_init(
    State(state): State<AppState>,
    Json(req): Json<InitRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let mut storage = state.storage.write().await;
    
    storage.initialize_keystore(&req.password, req.hsm_pin.as_deref())?;
    
    let token = state.create_session().await;
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    
    Ok(Json(AuthResponse {
        session_token: token,
        expires_at,
    }))
}

pub async fn auth_unlock(
    State(state): State<AppState>,
    Json(req): Json<UnlockRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let mut storage = state.storage.write().await;
    
    storage.unlock(&req.password, req.hsm_pin.as_deref())?;
    
    let token = state.create_session().await;
    let expires_at = chrono::Utc::now().timestamp() + 3600;
    
    Ok(Json(AuthResponse {
        session_token: token,
        expires_at,
    }))
}

pub async fn auth_lock(
    State(state): State<AppState>,
    Json(token): Json<String>,
) -> ApiResult<StatusCode> {
    state.remove_session(&token).await;
    Ok(StatusCode::OK)
}

pub async fn auth_status(
    State(state): State<AppState>,
) -> ApiResult<Json<StatusResponse>> {
    let storage = state.storage.read().await;
    
    Ok(Json(StatusResponse {
        locked: storage.get_active_sk().is_none(),
        initialized: storage.is_initialized(),
    }))
}

// ============================================================================
// Record Handlers
// ============================================================================

#[derive(Deserialize)]
pub struct ListRecordsQuery {
    table: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

pub async fn list_records(
    State(state): State<AppState>,
    Query(params): Query<ListRecordsQuery>,
) -> ApiResult<Json<RecordListResponse>> {
    let storage = state.storage.read().await;
    let table = params.table.as_deref().unwrap_or("default");
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);
    
    let keys = storage.list_keys(table)?;
    let total = keys.len();
    
    let sk = storage.get_active_sk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();
    
    let mut records = Vec::new();
    for key in keys.iter().skip(offset).take(limit) {
        if let Some(record) = storage.get_record(table, key, &sk)? {
            records.push(RecordResponse {
                id: record.id,
                data: record.data,
                vector: record.vector,
            });
        }
    }
    
    Ok(Json(RecordListResponse {
        records,
        total,
        page: offset / limit,
        limit,
    }))
}

#[derive(Deserialize)]
pub struct GetRecordQuery {
    table: Option<String>,
}

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
    
    let record = storage.get_record(table, &id, &sk)?
        .ok_or_else(|| anyhow::anyhow!("Record not found"))?;
    
    Ok(Json(RecordResponse {
        id: record.id,
        data: record.data,
        vector: record.vector,
    }))
}

pub async fn insert_record(
    State(state): State<AppState>,
    Path(table): Path<String>,
    Json(req): Json<RecordRequest>,
) -> ApiResult<StatusCode> {
    // Validate partition supports vectors if provided
    validate_partition(req.partition.as_deref(), req.vector.is_some())?;
    
    // Build table name with partition prefix
    let table_name = build_table_name(&table, req.partition.as_deref());
    
    let mut storage = state.storage.write().await;
    let pk = storage
        .get_active_pk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec(); // Convert to owned value

    let record = Record {
        id: req.id,
        data: req.data,
        vector: req.vector,
    };

    storage.insert_record(&table_name, &record, &pk)?;
    Ok(StatusCode::CREATED)
}

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
    
    let mut storage = state.storage.write().await;
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

    storage.insert_batch_records(&table_name, records, &pk)?;
    Ok(StatusCode::CREATED)
}

pub async fn delete_record(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<GetRecordQuery>,
) -> ApiResult<StatusCode> {
    let mut storage = state.storage.write().await;
    let table = params.table.as_deref().unwrap_or("default");
    
    let deleted = storage.delete_record(table, &id)?;
    
    if deleted {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

// ============================================================================
// Query Handlers
// ============================================================================

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

    let records = storage.find_by_metadata(&table_name, &req.field, &req.value, &sk)?;
    
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
        &table_name,
        &req.vector,
        req.k,
        &req.filter_field,
        &req.filter_value,
        &sk,
    )?;
    
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

pub async fn vector_search(
    State(state): State<AppState>,
    Json(req): Json<VectorSearchRequest>,
) -> ApiResult<Json<SearchResponse>> {
    let storage = state.storage.read().await;
    let table = req.table.as_deref().unwrap_or("default");
    
    let sk = storage.get_active_sk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();
    
    let results_with_scores = storage.search_similar_records(table, &req.vector, req.k, &sk)?;
    
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

pub async fn vector_stats(
    State(state): State<AppState>,
) -> ApiResult<Json<VectorStatsResponse>> {
    let storage = state.storage.read().await;
    let info = storage.get_info()?;
    
    Ok(Json(VectorStatsResponse {
        count: info["vector_records"].as_u64().unwrap_or(0) as usize,
        index_size: info["vector_index_size"].as_u64().unwrap_or(0) as usize,
        deleted: info["vector_deleted"].as_u64().unwrap_or(0) as usize,
    }))
}

// ============================================================================
// Table Handlers
// ============================================================================

pub async fn list_tables(
    State(state): State<AppState>,
) -> ApiResult<Json<TablesResponse>> {
    let storage = state.storage.read().await;
    
    // For now, return a simple list - in the future we can scan the sled database
    // to find all tables
    let tables = vec![
        TableInfo {
            name: "default".to_string(),
            record_count: storage.list_keys("default")?.len(),
        },
    ];
    
    Ok(Json(TablesResponse { tables }))
}

// ============================================================================
// Security Handlers
// ============================================================================

pub async fn generate_backup(
    State(state): State<AppState>,
    Json(req): Json<BackupRequest>,
) -> ApiResult<Json<BackupResponse>> {
    let storage = state.storage.read().await;
    
    let blob = storage.generate_recovery_backup(&req.recovery_password)?;
    
    Ok(Json(BackupResponse { blob }))
}

pub async fn recover_backup(
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> ApiResult<StatusCode> {
    let mut storage = state.storage.write().await;
    
    storage.recover_from_backup(&req.blob, &req.recovery_password, &req.new_master_password)?;
    
    Ok(StatusCode::OK)
}

pub async fn keystore_info(
    State(state): State<AppState>,
) -> ApiResult<Json<KeystoreInfo>> {
    let _storage = state.storage.read().await;
    
    let keystore_path = "wolf.db/keystore.json";
    let hsm_enabled = if std::path::Path::new(keystore_path).exists() {
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

pub async fn database_stats(
    State(state): State<AppState>,
) -> ApiResult<Json<DatabaseStats>> {
    let storage = state.storage.read().await;
    let info = storage.get_info()?;
    
    let tables = vec![
        TableInfo {
            name: "default".to_string(),
            record_count: storage.list_keys("default")?.len(),
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

pub async fn import_sqlite_file(
    State(state): State<AppState>,
    mut multipart: axum::extract::Multipart,
) -> ApiResult<Json<ImportResponse>> {
    use tokio::io::AsyncWriteExt;
    
    // Save uploaded file to temp location
    let temp_path = format!("/tmp/wolfdb_import_{}.db", uuid::Uuid::new_v4());
    
    while let Some(field) = multipart.next_field().await.map_err(|e| anyhow::anyhow!("Multipart error: {}", e))? {
        let name = field.name().unwrap_or("").to_string();
        
        if name == "file" {
            let data = field.bytes().await.map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;
            
            let mut file = tokio::fs::File::create(&temp_path).await?;
            file.write_all(&data).await?;
            file.flush().await?;
            break;
        }
    }
    
    // Process the uploaded file
    let result = import_sqlite_from_path(state, &temp_path).await;
    
    // Clean up temp file
    let _ = tokio::fs::remove_file(&temp_path).await;
    
    result
}

pub async fn import_sqlite(
    State(state): State<AppState>,
    Json(req): Json<ImportSqliteRequest>,
) -> ApiResult<Json<ImportResponse>> {
    import_sqlite_from_path(state, &req.path).await
}

async fn import_sqlite_from_path(
    state: AppState,
    path: &str,
) -> ApiResult<Json<ImportResponse>> {
    let mut storage = state.storage.write().await;
    
    let pk = storage.get_active_pk()
        .ok_or_else(|| anyhow::anyhow!("Database is locked"))?
        .to_vec();
    
    let conn = rusqlite::Connection::open(path)?;
    
    let mut stmt = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
    let tables: Vec<String> = stmt.query_map([], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    
    let mut total_records = 0;
    
    for table_name in &tables {
        let mut stmt = conn.prepare(&format!("SELECT * FROM \"{}\"", table_name))?;
        let column_names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
        let column_count = column_names.len();
        
        let rows = stmt.query_map([], |row| {
            let mut data_map = HashMap::new();
            let mut id = None;
            
            for i in 0..column_count {
                let col_name = &column_names[i];
                let val_ref = row.get_ref(i)?;
                
                let val_str = match val_ref {
                    rusqlite::types::ValueRef::Null => "null".to_string(),
                    rusqlite::types::ValueRef::Integer(i) => i.to_string(),
                    rusqlite::types::ValueRef::Real(r) => r.to_string(),
                    rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).to_string(),
                    rusqlite::types::ValueRef::Blob(b) => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b),
                };
                
                if (col_name == "id" || col_name == "uuid") && id.is_none() {
                    id = Some(val_str.clone());
                }
                
                data_map.insert(col_name.clone(), val_str);
            }
            
            Ok((id, data_map))
        })?;
        
        let mut batch = Vec::new();
        for row_res in rows {
            let (id_opt, data): (Option<String>, HashMap<String, String>) = row_res?;
            let id = id_opt.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            
            batch.push(Record {
                id,
                data,
                vector: None,
            });
        }
        
        let count = batch.len();
        storage.insert_batch_records(table_name, batch, &pk)?;
        total_records += count;
    }
    
    Ok(Json(ImportResponse {
        tables_imported: tables.len(),
        records_imported: total_records,
    }))
}
