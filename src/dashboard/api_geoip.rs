use crate::dashboard::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use wolf_net::geo::{GeoIPConfig, GeoIPService, GeoLocation};

lazy_static::lazy_static! {
    static ref GEOIP_SERVICE: GeoIPService = GeoIPService::new(GeoIPConfig::default());
}

#[derive(Debug, Serialize)]
pub struct GeoIPResponse {
    pub ip: String,
    pub location: Option<GeoLocation>,
    pub cached: bool,
}

#[derive(Debug, Deserialize)]
pub struct GeoIPRequest {
    pub ip: String,
}

/// API: Resolve IP address to geographic location
pub async fn api_geoip_resolve(
    State(_state): State<AppState>,
    Json(req): Json<GeoIPRequest>,
) -> Result<Json<GeoIPResponse>, axum::http::StatusCode> {
    // Parse IP address
    let ip: IpAddr = req
        .ip
        .parse()
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    // Check if it's a private IP (skip GeoIP for private IPs)
    if is_private_ip(&ip) {
        return Ok(Json(GeoIPResponse {
            ip: req.ip,
            location: None,
            cached: false,
        }));
    }

    // Resolve location
    match GEOIP_SERVICE.resolve(&ip).await {
        Ok(location) => {
            Ok(Json(GeoIPResponse {
                ip: req.ip,
                location: Some(location),
                cached: false, // TODO: Track if from cache
            }))
        }
        Err(e) => {
            tracing::error!("GeoIP resolution failed for {}: {}", req.ip, e);
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// API: Get cache statistics
pub async fn api_geoip_stats(
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let (total, expired) = GEOIP_SERVICE.cache_stats().await;

    Ok(Json(serde_json::json!({
        "cache_total": total,
        "cache_expired": expired,
        "cache_active": total - expired
    })))
}

/// Check if IP is private/local
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unique_local(),
    }
}
