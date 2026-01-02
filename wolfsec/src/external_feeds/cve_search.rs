// Search CVE data from CVE Search API
use super::{ExternalFeedsConfig, ThreatFeedItem};
use anyhow::Result;
use reqwest::Client;

pub async fn search_cve(query: &str, config: &ExternalFeedsConfig) -> Result<Vec<ThreatFeedItem>> {
    let base_url = match &config.cve_search_url {
        Some(url) => url.clone(),
        None => return Ok(vec![]),
    };
    let client = Client::new();
    let url = format!("{}/search?query={}", base_url, query);
    let resp = client
        .get(&url)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    // Simplified: assume resp contains an array of items under "results"
    let mut items = Vec::new();
    if let Some(arr) = resp["results"].as_array() {
        for entry in arr {
            let id = entry["id"].as_str().unwrap_or("").to_string();
            let title = entry["summary"].as_str().unwrap_or("").to_string();
            items.push(ThreatFeedItem {
                id: id.clone(),
                title,
                description: None,
                severity: None,
                source: "CVE-Search".to_string(),
                raw: entry.clone(),
            });
        }
    }
    Ok(items)
}
