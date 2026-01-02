// Fetch malware data from VirusTotal API
use super::{ExternalFeedsConfig, ThreatFeedItem};
use anyhow::Result;
use reqwest::Client;

pub async fn lookup_hash(
    hash: &str,
    config: &ExternalFeedsConfig,
) -> Result<Option<ThreatFeedItem>> {
    let api_key = match &config.virustotal_api_key {
        Some(k) => k.clone(),
        None => return Ok(None),
    };
    let client = Client::new();
    let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
    let resp = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    Ok(Some(ThreatFeedItem {
        id: hash.to_string(),
        title: resp["data"]["attributes"]["meaningful_name"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        description: None,
        severity: None,
        source: "VirusTotal".to_string(),
        raw: resp,
    }))
}
