// Fetch CVE data from NVD API
use super::{ExternalFeedsConfig, ThreatFeedItem};
use anyhow::Result;
use reqwest::Client;
use serde_json::Value;

/// Fetches detailed CVE information from the National Vulnerability Database (NVD).
pub async fn fetch_nvd(
    cve_id: &str,
    config: &ExternalFeedsConfig,
) -> Result<Option<ThreatFeedItem>> {
    // Return None if API key not provided
    let api_key = match &config.nvd_api_key {
        Some(k) => k.clone(),
        None => return Ok(None),
    };

    let client = Client::new();
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cve/{}?apiKey={}",
        cve_id, api_key
    );

    let resp: Value = client.get(&url).send().await?.json().await?;

    // Simplified parsing
    Ok(Some(ThreatFeedItem {
        id: cve_id.to_string(),
        title: resp["result"]["CVE_Items"][0]["cve"]["description"]["description_data"][0]["value"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        description: None,
        severity: None,
        source: "NVD".to_string(),
        raw: resp,
    }))
}
