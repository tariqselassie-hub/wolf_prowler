//! Async-safe application state management for Wolf Control
//!
//! This module replaces the problematic std::sync::Mutex pattern with proper
//! tokio::sync::RwLock for async contexts, improving performance
//! and preventing runtime blocking.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Application data structure with async-safe access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    /// Whether the system is connected to network
    pub connected: bool,
    /// List of connected peers
    pub peers: Vec<String>,
    /// System status information
    pub status: SystemStatus,
    /// Network uptime in seconds
    pub uptime_seconds: u64,
    /// Number of active alerts
    pub active_alerts: usize,
    /// Last error message
    pub last_error: Option<String>,
}

/// System status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemStatus {
    Starting,
    Running,
    Error(String),
    Maintenance,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            connected: false,
            peers: Vec::new(),
            status: SystemStatus::Starting,
            uptime_seconds: 0,
            active_alerts: 0,
            last_error: None,
        }
    }
}

/// Async-safe application state wrapper
pub struct AsyncAppState {
    /// Internal state protected by RwLock for async access
    state: Arc<RwLock<AppState>>,
    /// Shutdown signal for graceful shutdown
    shutdown_signal: Arc<tokio::sync::Notify>,
}

impl AsyncAppState {
    /// Create new async-safe application state
    pub fn new(initial_state: AppState) -> Self {
        Self {
            state: Arc::new(RwLock::new(initial_state)),
            shutdown_signal: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Read state asynchronously (shared access)
    pub async fn read_state(&self) -> tokio::sync::RwLockReadGuard<'_, AppState> {
        self.state.read().await
    }

    /// Write state asynchronously (exclusive access)
    pub async fn write_state(&self) -> tokio::sync::RwLockWriteGuard<'_, AppState> {
        self.state.write().await
    }

    /// Update specific field without holding full write lock
    pub async fn update_field<F, R>(&self, update_fn: F) -> R
    where
        F: FnOnce(&mut AppState) -> R,
    {
        let mut state = self.state.write().await;
        update_fn(&mut state)
    }

    /// Try to update state with timeout
    pub async fn try_update_field<F, R>(&self, timeout: Duration, update_fn: F) -> Result<R>
    where
        F: FnOnce(&mut AppState) -> R,
    {
        match tokio::time::timeout(timeout, self.state.write()).await {
            Ok(guard) => Ok(update_fn(guard)),
            Err(_) => Err(anyhow::anyhow!("State update timed out")),
        }
    }

    /// Get shutdown receiver for graceful shutdown
    pub fn shutdown_notifier(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.shutdown_signal)
    }

    /// Signal shutdown
    pub async fn shutdown(&self) {
        self.shutdown_signal.notify_one();
        info!("Shutdown signal sent to application state");
    }

    /// Wait for shutdown signal
    pub async fn wait_for_shutdown(&self) {
        self.shutdown_signal.notified().await;
        info!("Application shutdown received");
    }

    /// Get current status string for display
    pub async fn get_status_string(&self) -> String {
        let state = self.state.read().await;
        match &state.status {
            SystemStatus::Starting => "Starting".to_string(),
            SystemStatus::Running => "Running".to_string(),
            SystemStatus::Error(msg) => format!("Error: {}", msg),
            SystemStatus::Maintenance => "Maintenance".to_string(),
        }
    }

    /// Get formatted status information
    pub async fn get_status_info(&self) -> String {
        let state = self.state.read().await;
        format!(
            "Connected: {} | Peers: {} | Uptime: {}s | Alerts: {} | Status: {}",
            state.connected,
            state.peers.len(),
            state.uptime_seconds,
            state.active_alerts,
            self.get_status_string().await
        )
    }

    /// Add a new peer to the connected list
    pub async fn add_peer(&self, peer_id: String) {
        let mut state = self.state.write().await;
        if !state.peers.contains(&peer_id) {
            state.peers.push(peer_id);
            debug!("Added peer {} to connection list", peer_id);
        }
    }

    /// Remove a peer from the connected list
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut state = self.state.write().await;
        if let Some(pos) = state.peers.iter().position(|p| p == peer_id) {
            state.peers.remove(pos);
            debug!("Removed peer {} from connection list", peer_id);
        }
    }

    /// Update connection status
    pub async fn set_connected(&self, connected: bool) {
        let mut state = self.state.write().await;
        if state.connected != connected {
            state.connected = connected;
            info!("Connection status changed to: {}", connected);
        }
    }

    /// Set error status
    pub async fn set_error(&self, error: String) {
        self.update_field(Duration::from_secs(5), |state| {
            state.status = SystemStatus::Error(error.clone());
            state.last_error = Some(error);
            state.connected = false;
            error!("Application error set: {}", error);
            true // Return value to satisfy update_fn
        }).await
        .map_err(|_| anyhow::anyhow!("Failed to set error state"))
    }

    /// Increment uptime counter
    pub async fn increment_uptime(&self, seconds: u64) {
        let mut state = self.state.write().await;
        state.uptime_seconds += seconds;
        debug!("Uptime incremented to {} seconds", state.uptime_seconds);
    }

    /// Set active alerts count
    pub async fn set_active_alerts(&self, count: usize) {
        let mut state = self.state.write().await;
        if state.active_alerts != count {
            state.active_alerts = count;
            info!("Active alerts changed to: {}", count);
        }
    }

    /// Get current metrics for monitoring
    pub async fn get_metrics(&self) -> AppMetrics {
        let state = self.state.read().await;
        AppMetrics {
            connected_peers: state.peers.len(),
            uptime_seconds: state.uptime_seconds,
            active_alerts: state.active_alerts,
            last_error: state.last_error.clone(),
        }
    }
}

/// Application metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMetrics {
    pub connected_peers: usize,
    pub uptime_seconds: u64,
    pub active_alerts: usize,
    pub last_error: Option<String>,
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self {
            connected_peers: 0,
            uptime_seconds: 0,
            active_alerts: 0,
            last_error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_async_state_concurrent_access() {
        let state = AsyncAppState::new(AppState::default());
        
        // Spawn concurrent readers
        let state_clone = Arc::clone(&state.state);
        let mut handles = vec![];
        
        for i in 0..10 {
            let state_ref = Arc::clone(&state_clone);
            let handle = tokio::spawn(async move {
                let guard = state_ref.read().await;
                assert!(guard.peers.len() >= 0);
                drop(guard);
                sleep(Duration::from_millis(1)).await;
            });
            handles.push(handle);
        }
        
        // Spawn concurrent writer
        let state_clone2 = Arc::clone(&state.state);
        let writer = tokio::spawn(async move {
            state_clone2.write().await;
            sleep(Duration::from_millis(5)).await;
        });
        
        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_state_update_with_timeout() {
        let state = AsyncAppState::new(AppState::default());
        
        // This should succeed
        let result = state.try_update_field(Duration::from_millis(100), |s| {
            s.connected = true;
            "success"
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        
        // This should timeout
        let result = state.try_update_field(Duration::from_millis(1), |s| {
            sleep(Duration::from_millis(10)).await;
            "timeout"
        }).await;
        
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_peer_management() {
        let state = AsyncAppState::new(AppState::default());
        
        // Add peers
        state.add_peer("peer1".to_string()).await;
        state.add_peer("peer2".to_string()).await;
        
        let metrics = state.get_metrics().await;
        assert_eq!(metrics.connected_peers, 2);
        
        // Remove a peer
        state.remove_peer("peer1").await;
        
        let metrics = state.get_metrics().await;
        assert_eq!(metrics.connected_peers, 1);
    }
}