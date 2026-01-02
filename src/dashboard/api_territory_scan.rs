use crate::dashboard::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use wolf_net::scanner::{NetworkDevice, NetworkInterface, NetworkScanner, ScannerConfig};

/// Cached scan results
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

lazy_static::lazy_static! {
    static ref SCAN_CACHE: Arc<RwLock<Option<(Vec<NetworkDevice>, Instant)>>> = Arc::new(RwLock::new(None));
}

const CACHE_DURATION: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub total_devices: usize,
    pub devices: Vec<NetworkDevice>,
    pub scan_time_ms: u64,
    pub cached: bool,
}

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub interface: Option<String>,
    pub force: Option<bool>,
}

/// API: List available network interfaces
pub async fn api_list_interfaces() -> Result<Json<Vec<NetworkInterface>>, axum::http::StatusCode> {
    match NetworkScanner::list_interfaces().await {
        Ok(interfaces) => Ok(Json(interfaces)),
        Err(e) => {
            tracing::error!("Failed to list interfaces: {}", e);
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// API: Scan local network for devices (POST)
pub async fn api_territory_scan(
    State(_state): State<AppState>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, axum::http::StatusCode> {
    // Check cache first (ignore if force is true)
    if !payload.force.unwrap_or(false) && payload.interface.is_none() {
        let cache = SCAN_CACHE.read().await;
        if let Some((devices, timestamp)) = cache.as_ref() {
            if timestamp.elapsed() < CACHE_DURATION {
                tracing::info!(
                    "📦 Returning cached scan results ({} devices)",
                    devices.len()
                );
                return Ok(Json(ScanResponse {
                    total_devices: devices.len(),
                    devices: devices.clone(),
                    scan_time_ms: 0,
                    cached: true,
                }));
            }
        }
    }

    // Perform new scan
    tracing::info!(
        "🔍 Starting new network scan (Interface: {:?})...",
        payload.interface
    );
    let start = Instant::now();

    // Prepare configuration
    let mut scanner_config = ScannerConfig::default();

    if let Some(ref iface_name) = payload.interface {
        scanner_config.interface = Some(iface_name.clone());

        // Try to find the subnet for this interface
        match NetworkScanner::list_interfaces().await {
            Ok(interfaces) => {
                if let Some(iface) = interfaces.into_iter().find(|i| &i.name == iface_name) {
                    scanner_config.subnet = iface.subnet;
                    tracing::info!(
                        "🎯 Focused scan on interface {} subnet {}",
                        iface_name,
                        scanner_config.subnet
                    );
                } else {
                    tracing::warn!(
                        "Specified interface '{}' not found. Using default subnet.",
                        iface_name
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Failed to list interfaces: {}. Using default subnet.", e);
            }
        }
    }

    // Initialize scanner
    let scanner = if payload.interface.is_some() {
        // If specific interface requested, use our constructed config
        NetworkScanner::new(scanner_config)
    } else {
        // If no interface, try to auto-detect the best default (e.g. via default route)
        NetworkScanner::new_auto().await.unwrap_or_else(|e| {
            tracing::warn!(
                "Failed to auto-detect network config: {}. Falling back to default.",
                e
            );
            NetworkScanner::new(scanner_config)
        })
    };

    let devices = match scanner.scan_network().await {
        Ok(devices) => devices,
        Err(e) => {
            tracing::error!("Network scan failed: {}", e);
            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let scan_time = start.elapsed().as_millis() as u64;

    // Update cache
    {
        let mut cache = SCAN_CACHE.write().await;
        *cache = Some((devices.clone(), Instant::now()));
    }

    tracing::info!(
        "✅ Network scan complete: {} devices in {}ms",
        devices.len(),
        scan_time
    );

    Ok(Json(ScanResponse {
        total_devices: devices.len(),
        devices,
        scan_time_ms: scan_time,
        cached: false,
    }))
}
