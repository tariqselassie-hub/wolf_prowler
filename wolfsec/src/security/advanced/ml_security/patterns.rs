use crate::security::advanced::ml_security::baselines::PeerProfile;
use crate::security::advanced::ml_security::{
    BehavioralDataPoint, BehavioralIndicator, MLSecurityConfig, RiskLevel, WolfBehavioralPattern,
};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Pattern analyzer
///
/// Analyzes behavioral data for patterns and anomalies.
pub struct PatternAnalyzer {
    config: MLSecurityConfig,
    peer_profiles: HashMap<String, PeerProfile>,
}

impl PatternAnalyzer {
    /// Create new pattern analyzer
    pub fn new(config: MLSecurityConfig) -> Result<Self> {
        Ok(Self {
            config,
            peer_profiles: HashMap::new(),
        })
    }

    pub async fn analyze_patterns(
        &mut self,
        data: &[BehavioralDataPoint],
    ) -> Result<Vec<WolfBehavioralPattern>> {
        let mut patterns = Vec::new();

        // First pass: Update all peer profiles
        for point in data {
            let profile = self
                .peer_profiles
                .entry(point.peer_id.clone())
                .or_insert_with(|| PeerProfile::new(point.peer_id.clone()));

            profile.update(point);
        }

        // Second pass: Check for patterns (now we can borrow profiles immutably)
        for point in data {
            if let Some(profile) = self.peer_profiles.get(&point.peer_id) {
                // Check for "Anomaly from Baseline" pattern
                if let Some(anomaly_pattern) = self.check_baseline_anomalies(profile, point) {
                    patterns.push(anomaly_pattern);
                }

                // Check for sequential patterns
                if let Some(sequential_pattern) = self.check_sequential_patterns(profile, point) {
                    patterns.push(sequential_pattern);
                }
            }
        }

        Ok(patterns)
    }

    fn check_baseline_anomalies(
        &self,
        profile: &PeerProfile,
        current: &BehavioralDataPoint,
    ) -> Option<WolfBehavioralPattern> {
        let mut indicators = Vec::new();
        let mut max_z_score = 0.0;

        for (feature, &value) in &current.features {
            if let Some(z_score) = profile.get_z_score(feature, value) {
                if z_score.abs() > 3.0 {
                    // Significant anomaly
                    indicators.push(BehavioralIndicator {
                        indicator_type: format!("Anomalous {}", feature),
                        value: serde_json::json!(value),
                        weight: 0.5,
                        threshold: 3.0,
                    });
                    if z_score.abs() > max_z_score {
                        max_z_score = z_score.abs();
                    }
                }
            }
        }

        if !indicators.is_empty() {
            Some(WolfBehavioralPattern {
                id: Uuid::new_v4().to_string(),
                name: "Baseline Deviation".to_string(),
                description: format!(
                    "Peer {} behavior deviated from historic baseline (Max Z-Score: {:.2})",
                    profile.peer_id, max_z_score
                ),
                indicators,
                risk_level: if max_z_score > 5.0 {
                    RiskLevel::High
                } else {
                    RiskLevel::Medium
                },
                frequency: 1.0,
                last_observed: Utc::now(),
            })
        } else {
            None
        }
    }

    fn check_sequential_patterns(
        &self,
        _profile: &PeerProfile,
        _current: &BehavioralDataPoint,
    ) -> Option<WolfBehavioralPattern> {
        // Placeholder for more complex temporal pattern matching
        // e.g. "Lateral Movement": [Login at X, Access unusual resource Y, Login at Z]
        None
    }
}
