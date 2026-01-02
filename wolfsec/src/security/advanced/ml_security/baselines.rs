use crate::security::advanced::ml_security::{BehavioralDataPoint, RiskLevel};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Historic baseline for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerProfile {
    pub peer_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub statistics: HashMap<String, BaselineMetric>,
    pub risk_history: Vec<(DateTime<Utc>, RiskLevel)>,
    pub total_interactions: u64,
}

/// Aggregated metric for behavioral baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetric {
    pub count: u64,
    pub mean: f64,
    pub m2: f64, // Used for Welford's online variance algorithm
    pub min: f64,
    pub max: f64,
}

impl BaselineMetric {
    pub fn new(value: f64) -> Self {
        Self {
            count: 1,
            mean: value,
            m2: 0.0,
            min: value,
            max: value,
        }
    }

    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
    }

    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
}

impl PeerProfile {
    pub fn new(peer_id: String) -> Self {
        Self {
            peer_id,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            statistics: HashMap::new(),
            risk_history: Vec::new(),
            total_interactions: 0,
        }
    }

    pub fn update(&mut self, data: &BehavioralDataPoint) {
        self.last_seen = data.timestamp;
        self.total_interactions += 1;

        for (key, &value) in &data.features {
            self.statistics
                .entry(key.clone())
                .and_modify(|m| m.update(value))
                .or_insert_with(|| BaselineMetric::new(value));
        }
    }

    pub fn get_z_score(&self, feature: &str, value: f64) -> Option<f64> {
        let metric = self.statistics.get(feature)?;
        let std_dev = metric.std_dev();
        if std_dev == 0.0 {
            Some(0.0)
        } else {
            Some((value - metric.mean) / std_dev)
        }
    }

    pub fn save(&self, storage_path: &str) -> Result<()> {
        let path = Path::new(storage_path).join(format!("peer_{}.json", self.peer_id));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).context("Failed to save peer profile")?;
        Ok(())
    }

    pub fn load(storage_path: &str, peer_id: &str) -> Result<Self> {
        let path = Path::new(storage_path).join(format!("peer_{}.json", peer_id));
        let json = fs::read_to_string(path).context("Failed to load peer profile")?;
        let profile = serde_json::from_str(&json)?;
        Ok(profile)
    }
}
