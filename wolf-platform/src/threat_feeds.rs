use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

/// In-memory database for housing threat intelligence
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ThreatDatabase {
    pub malicious_ips: HashSet<String>,
    pub known_cves: HashMap<String, CveRecord>,
    pub last_updated: Option<DateTime<Utc>>,
    pub config: ThreatFeedConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatFeedConfig {
    pub ip_feed_url: String,
    pub cve_feed_url: String,
}

impl Default for ThreatFeedConfig {
    fn default() -> Self {
        Self {
            ip_feed_url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
                .to_string(),
            cve_feed_url: "https://cve.circl.lu/api/last".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub description: String,
    pub severity: f32, // CVSS score
    pub published: DateTime<Utc>,
    pub status: String,
}

/// Manager to handle background updates from external sources
pub struct ThreatFeedManager {
    db: Arc<RwLock<ThreatDatabase>>,
}

impl ThreatFeedManager {
    pub fn new(db: Arc<RwLock<ThreatDatabase>>) -> Self {
        Self { db }
    }

    /// Start the background task to update feeds periodically
    pub async fn start_background_updates(&self) {
        let db = self.db.clone();
        tokio::spawn(async move {
            // Update immediately on start
            if let Err(e) = Self::update_feeds(db.clone()).await {
                error!("❌ Failed to perform initial threat feed update: {}", e);
            }

            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600 * 4)); // Every 4 hours

            loop {
                interval.tick().await;
                info!("🔄 Starting scheduled threat feed update...");

                if let Err(e) = Self::update_feeds(db.clone()).await {
                    error!("❌ Failed to update threat feeds: {}", e);
                } else {
                    info!("✅ Threat feeds updated successfully");
                }
            }
        });
    }

    /// Logic to fetch from APIs and update the database
    pub async fn update_feeds(db: Arc<RwLock<ThreatDatabase>>) -> Result<()> {
        let (ip_url, cve_url) = {
            let db_read = db.read().await;
            (
                db_read.config.ip_feed_url.clone(),
                db_read.config.cve_feed_url.clone(),
            )
        };

        let mut new_ips = HashSet::new();
        let mut new_cves = HashMap::new();

        // 1. Fetch Malicious IPs (Emerging Threats)
        info!("📥 Fetching malicious IPs from {}...", ip_url);
        match reqwest::get(&ip_url).await {
            Ok(resp) => match resp.text().await {
                Ok(text) => {
                    for line in text.lines() {
                        let ip = line.trim();
                        if !ip.is_empty() && ip.contains('.') {
                            new_ips.insert(ip.to_string());
                        }
                    }
                    info!("✅ Fetched {} malicious IPs", new_ips.len());
                }
                Err(e) => error!("❌ Failed to read IP feed text: {}", e),
            },
            Err(e) => error!("❌ Failed to connect to IP feed: {}", e),
        }

        // 2. Fetch Recent CVEs (CIRCL.lu)
        info!("📥 Fetching recent CVEs from {}...", cve_url);
        match reqwest::get(&cve_url).await {
            Ok(resp) => match resp.json::<Vec<serde_json::Value>>().await {
                Ok(cves) => {
                    for cve_data in cves {
                        if let Some(id) = cve_data.get("id").and_then(|v| v.as_str()) {
                            let summary = cve_data
                                .get("summary")
                                .and_then(|v| v.as_str())
                                .unwrap_or("No description available")
                                .to_string();

                            let cvss = cve_data
                                .get("cvss")
                                .and_then(|v| v.as_f64())
                                .or_else(|| {
                                    cve_data
                                        .get("cvss")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| s.parse::<f64>().ok())
                                })
                                .unwrap_or(0.0) as f32;

                            let published = cve_data
                                .get("Published")
                                .and_then(|v| v.as_str())
                                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                                .map(|dt| dt.with_timezone(&Utc))
                                .unwrap_or_else(Utc::now);

                            let record = CveRecord {
                                id: id.to_string(),
                                description: summary,
                                severity: cvss,
                                published,
                                status: "Published".to_string(),
                            };
                            new_cves.insert(id.to_string(), record);
                        }
                    }
                    info!("✅ Fetched {} recent CVEs", new_cves.len());
                }
                Err(e) => error!("❌ Failed to parse CVE JSON: {}", e),
            },
            Err(e) => error!("❌ Failed to connect to CVE feed: {}", e),
        }

        let mut write_guard = db.write().await;
        if !new_ips.is_empty() {
            write_guard.malicious_ips.extend(new_ips);
        }
        if !new_cves.is_empty() {
            write_guard.known_cves.extend(new_cves);
        }
        write_guard.last_updated = Some(Utc::now());

        Ok(())
    }

    /// Validate that the configured feed URLs are reachable
    pub async fn validate_feeds(db: Arc<RwLock<ThreatDatabase>>) -> HashMap<String, String> {
        let (ip_url, cve_url) = {
            let db_read = db.read().await;
            (
                db_read.config.ip_feed_url.clone(),
                db_read.config.cve_feed_url.clone(),
            )
        };

        let mut results = HashMap::new();

        // Check IP Feed
        let ip_status = match reqwest::get(&ip_url).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    "reachable".to_string()
                } else {
                    format!("error: {}", resp.status())
                }
            }
            Err(e) => format!("unreachable: {}", e),
        };
        results.insert("ip_feed".to_string(), ip_status);

        // Check CVE Feed
        let cve_status = match reqwest::get(&cve_url).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    "reachable".to_string()
                } else {
                    format!("error: {}", resp.status())
                }
            }
            Err(e) => format!("unreachable: {}", e),
        };
        results.insert("cve_feed".to_string(), cve_status);

        results
    }
}
