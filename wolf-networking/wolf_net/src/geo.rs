//! GeoIP Service Module
//!
//! Provides geographic location resolution for IP addresses using external GeoIP APIs.
//! Includes caching to minimize API calls and respect rate limits.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Geographic location data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// IP address of the target.
    pub ip: String,
    /// Two‑letter country code (e.g., "US").
    pub country: String,
    /// Full country name.
    pub country_code: String,
    /// Region identifier (e.g., state or province).
    pub region: String,
    /// Human‑readable region name.
    pub region_name: String,
    /// City name.
    pub city: String,
    /// Postal/ZIP code.
    pub zip: String,
    /// Latitude coordinate.
    pub lat: f64,
    /// Longitude coordinate.
    pub lon: f64,
    /// Timezone identifier (e.g., "America/New_York").
    pub timezone: String,
    /// ISP name.
    pub isp: String,
    /// Organization name.
    pub org: String,
    /// Autonomous system identifier.
    pub r#as: String,
}

/// Cached geo location with timestamp
#[derive(Debug, Clone)]
struct CachedGeoLocation {
    location: GeoLocation,
    cached_at: Instant,
}

/// GeoIP service configuration
#[derive(Debug, Clone)]
pub struct GeoIPConfig {
    /// Base URL of the GeoIP API.
    pub api_url: String,
    /// How long cached entries are considered fresh.
    pub cache_duration: Duration,
    /// HTTP request timeout for API calls.
    pub timeout: Duration,
}

impl Default for GeoIPConfig {
    fn default() -> Self {
        Self {
            api_url: "http://ip-api.com/json".to_string(),
            cache_duration: Duration::from_secs(86400), // 24 hours
            timeout: Duration::from_secs(5),
        }
    }
}

/// GeoIP service for resolving IP addresses to geographic locations
pub struct GeoIPService {
    config: GeoIPConfig,
    cache: Arc<RwLock<HashMap<String, CachedGeoLocation>>>,
    client: reqwest::Client,
}

impl GeoIPService {
    /// Create a new GeoIP service
    pub fn new(config: GeoIPConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            client,
        }
    }

    /// Resolve an IP address to a geographic location
    pub async fn resolve(&self, ip: &IpAddr) -> anyhow::Result<GeoLocation> {
        let ip_str = ip.to_string();

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&ip_str) {
                if cached.cached_at.elapsed() < self.config.cache_duration {
                    tracing::debug!("📍 GeoIP cache hit for {}", ip_str);
                    return Ok(cached.location.clone());
                }
            }
        }

        // Fetch from API
        tracing::info!("🌍 Resolving GeoIP for {}", ip_str);
        let location = self.fetch_from_api(&ip_str).await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                ip_str.clone(),
                CachedGeoLocation {
                    location: location.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        Ok(location)
    }

    /// Fetch location data from the API
    async fn fetch_from_api(&self, ip: &str) -> anyhow::Result<GeoLocation> {
        let url = format!("{}/{ip}", self.config.api_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch GeoIP data: {e}"))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "GeoIP API returned error: {}",
                response.status()
            ));
        }

        let location: GeoLocation = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse GeoIP response: {e}"))?;

        Ok(location)
    }

    /// Resolve multiple IPs concurrently
    pub async fn resolve_batch(&self, ips: &[IpAddr]) -> Vec<Option<GeoLocation>> {
        let mut tasks = Vec::new();

        for ip in ips {
            let service = self.clone();
            let ip = *ip;
            tasks.push(tokio::spawn(async move { service.resolve(&ip).await.ok() }));
        }

        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.ok().flatten());
        }

        results
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let total = cache.len();
        let expired = cache
            .values()
            .filter(|c| c.cached_at.elapsed() >= self.config.cache_duration)
            .count();

        let res = (total, expired);
        drop(cache);
        res
    }

    /// Clear expired cache entries
    pub async fn clear_expired_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.retain(|_, v| v.cached_at.elapsed() < self.config.cache_duration);
    }

    /// Clear all cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

// Implement Clone manually since reqwest::Client is Clone
impl Clone for GeoIPService {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cache: Arc::clone(&self.cache),
            client: self.client.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_geoip_resolution() {
        let service = GeoIPService::new(GeoIPConfig::default());
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)); // Google DNS

        // This test requires internet connection
        if let Ok(location) = service.resolve(&ip).await {
            assert_eq!(location.ip, "8.8.8.8");
            assert!(!location.country.is_empty());
        }
    }

    #[tokio::test]
    async fn test_cache() {
        let service = GeoIPService::new(GeoIPConfig::default());
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)); // Cloudflare DNS

        // First call - should fetch from API
        // Checks result to handle network failure gracefully (e.g. offline)
        match service.resolve(&ip).await {
            Ok(_) => {
                // Second call - should use cache
                let _ = service.resolve(&ip).await;
                let (total, _) = service.cache_stats().await;
                assert_eq!(total, 1);
            }
            Err(e) => {
                tracing::info!("Skipping test_cache due to network error: {}", e);
            }
        }
    }
}
