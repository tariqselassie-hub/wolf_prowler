// External feeds module
pub mod cache;
pub mod cve_search;
pub mod nvd;
pub mod virustotal;

use serde::{Deserialize, Serialize};

/// External feeds configuration struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalFeedsConfig {
    /// Optional NVD API key
    pub nvd_api_key: Option<String>,
    /// Optional CVE Search base URL
    pub cve_search_url: Option<String>,
    /// Optional VirusTotal API key
    pub virustotal_api_key: Option<String>,
    /// Optional HTTP Proxy URL for outbound requests
    pub proxy_url: Option<String>,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for ExternalFeedsConfig {
    fn default() -> Self {
        Self {
            nvd_api_key: None,
            cve_search_url: None,
            virustotal_api_key: None,
            proxy_url: None,
            cache_ttl_secs: 3600,
        }
    }
}

/// A unified record of threat intelligence from an external source.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatFeedItem {
    /// Unique identifier for the threat (e.g., CVE-ID or file hash).
    pub id: String,
    /// Short, descriptive title of the threat.
    pub title: String,
    /// Optional detailed account of the threat behavior and impact.
    pub description: Option<String>,
    /// Optional classification of the threat risk level.
    pub severity: Option<String>,
    /// Name of the providing intelligence feed (e.g., "NVD", "VirusTotal").
    pub source: String,
    /// The complete, unmodified technical data from the source.
    pub raw: serde_json::Value,
}

/// Fetch and enrich threat data
pub async fn enrich_threat(
    item: &mut ThreatFeedItem,
    config: &ExternalFeedsConfig,
) -> anyhow::Result<()> {
    // Simple heuristic: if the ID looks like a CVE identifier, use NVD;
    // if it looks like a SHA256 hash (64 hex chars), use VirusTotal;
    // otherwise, attempt a generic CVE search.
    if item.id.starts_with("CVE-") {
        // Try NVD first
        if let Some(feed) = nvd::fetch_nvd(&item.id, config).await? {
            item.title = feed.title;
            item.description = feed.description;
            item.severity = feed.severity;
            item.source = "NVD".to_string();
            item.raw = feed.raw;
            return Ok(());
        }
    }
    // Check for a SHA256 hash (64 hex characters)
    let is_hash = item.id.len() == 64 && item.id.chars().all(|c| c.is_ascii_hexdigit());
    if is_hash {
        if let Some(feed) = virustotal::lookup_hash(&item.id, config).await?
        {
            item.title = feed.title;
            item.description = feed.description;
            item.severity = feed.severity;
            item.source = "VirusTotal".to_string();
            item.raw = feed.raw;
            return Ok(());
        }
    }
    // Fallback to CVE search using the ID as a query string
    let results: Vec<ThreatFeedItem> =
        cve_search::search_cve(&item.id, config).await?;
    if let Some(first) = results.into_iter().next() {
        item.title = first.title;
        item.description = first.description;
        item.severity = first.severity;
        item.source = first.source;
        item.raw = first.raw;
    }
    Ok(())
}
