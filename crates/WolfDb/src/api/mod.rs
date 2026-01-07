use crate::storage::WolfDbStorage;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

pub mod handlers;
pub mod models;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<RwLock<WolfDbStorage>>,
    pub sessions: Arc<RwLock<HashMap<String, SessionData>>>,
}

#[derive(Clone)]
pub struct SessionData {
    pub token: String,
    pub expires_at: i64,
}

impl AppState {
    pub fn new(storage: WolfDbStorage) -> Self {
        Self {
            storage: Arc::new(RwLock::new(storage)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new session token
    pub async fn create_session(&self) -> String {
        use rand::Rng;
        let token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let expires_at = chrono::Utc::now().timestamp() + 3600; // 1 hour

        let mut sessions = self.sessions.write().await;
        sessions.insert(
            token.clone(),
            SessionData {
                token: token.clone(),
                expires_at,
            },
        );

        token
    }

    /// Validate a session token
    pub async fn validate_session(&self, token: &str) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(token) {
            let now = chrono::Utc::now().timestamp();
            session.expires_at > now
        } else {
            false
        }
    }

    /// Remove a session
    pub async fn remove_session(&self, token: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(token);
    }
}

use axum::{
    routing::{get, post, delete},
    Router,
};
use tower_http::cors::{CorsLayer, Any};
use tower::ServiceBuilder;
use axum::extract::DefaultBodyLimit;

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Serve dashboard at root
        .route("/", get(|| async {
            axum::response::Html(include_str!("../../dashboard.html"))
        }))
        
        // Authentication
        .route("/api/auth/init", post(handlers::auth_init))
        .route("/api/auth/unlock", post(handlers::auth_unlock))
        .route("/api/auth/lock", post(handlers::auth_lock))
        .route("/api/auth/status", get(handlers::auth_status))
        
        // Records
        .route("/api/records", get(handlers::list_records))
        .route("/api/records", post(handlers::insert_record))
        .route("/api/records/batch", post(handlers::batch_insert_records))
        .route("/api/records/:id", get(handlers::get_record))
        .route("/api/records/:id", delete(handlers::delete_record))
        
        // Queries
        .route("/api/query/metadata", post(handlers::query_by_metadata))
        .route("/api/query/hybrid", post(handlers::hybrid_search))
        
        // Vector operations
        .route("/api/vector/search", post(handlers::vector_search))
        .route("/api/vector/stats", get(handlers::vector_stats))
        
        // Tables
        .route("/api/tables", get(handlers::list_tables))
        
        // Security
        .route("/api/security/backup", post(handlers::generate_backup))
        .route("/api/security/recover", post(handlers::recover_backup))
        .route("/api/security/keystore", get(handlers::keystore_info))
        
        // Administration
        .route("/api/admin/stats", get(handlers::database_stats))
        .route("/api/admin/import/sqlite", post(handlers::import_sqlite))
        .route("/api/admin/import/sqlite/upload", post(handlers::import_sqlite_file))
        
        .layer(
            ServiceBuilder::new()
                .layer(cors)
                .layer(DefaultBodyLimit::max(200 * 1024 * 1024)) // 200MB limit
        )
        .with_state(state)
}
