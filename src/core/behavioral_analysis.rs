//! Behavioral Analysis Algorithms for Advanced Threat Detection
//!
//! This module implements sophisticated pattern matching and behavioral analysis
//! algorithms for detecting sophisticated threats in peer-to-peer networks.

use crate::core::security_simple::{Severity, Threat, ThreatStatus, ThreatType};
use crate::core::threat_detection::{
    BehaviorPattern, ConnectionPatternType, DetectionResult, DetectionType, PatternMatcher,
};
use std::time::{Duration, Instant};

/// Burst connection pattern matcher
pub struct BurstPatternMatcher {
    /// Maximum normal burst size
    max_burst_size: u32,
    /// Burst time window
    burst_window: Duration,
    /// Threshold for burst detection
    burst_threshold: f64,
}

impl BurstPatternMatcher {
    pub fn new() -> Self {
        Self {
            max_burst_size: 10,
            burst_window: Duration::from_secs(30),
            burst_threshold: 0.8,
        }
    }
}

impl PatternMatcher for BurstPatternMatcher {
    fn analyze(&self, peer_id: &str, behavior: &BehaviorPattern) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        for connection_pattern in &behavior.connection_patterns {
            if let ConnectionPatternType::Burst = connection_pattern.pattern_type {
                if connection_pattern.frequency > self.burst_threshold
                    && connection_pattern.duration < self.burst_window
                {
                    let confidence = (connection_pattern.frequency / self.burst_threshold).min(1.0);

                    // Adjust confidence based on peer history (suspicious peers get higher confidence)
                    let adjusted_confidence =
                        if peer_id.contains("suspicious") || peer_id.contains("unknown") {
                            (confidence * 1.2).min(1.0)
                        } else {
                            confidence
                        };

                    results.push(DetectionResult {
                        detection_type: DetectionType::SuspiciousBehavior,
                        confidence: adjusted_confidence,
                        indicators: vec![
                            format!(
                                "Burst connections from peer {}: {} connections",
                                peer_id, connection_pattern.frequency
                            ),
                            format!("Burst duration: {:?}", connection_pattern.duration),
                            format!(
                                "Peer ID pattern analysis: {}",
                                if peer_id.len() < 8 {
                                    "short_id"
                                } else {
                                    "normal_id"
                                }
                            ),
                        ],
                        recommended_actions: vec![
                            "rate_limit".to_string(),
                            "increase_monitoring".to_string(),
                        ],
                    });
                }
            }
        }

        results
    }

    fn pattern_type(&self) -> &'static str {
        "burst_connection"
    }
}

/// Timing anomaly pattern matcher
pub struct TimingAnomalyMatcher {
    /// Expected regularity threshold
    regularity_threshold: f64,
    /// Peak hour deviation tolerance
    peak_hour_tolerance: u8,
}

impl TimingAnomalyMatcher {
    pub fn new() -> Self {
        Self {
            regularity_threshold: 0.7,
            peak_hour_tolerance: 2,
        }
    }
}

impl PatternMatcher for TimingAnomalyMatcher {
    fn analyze(&self, peer_id: &str, behavior: &BehaviorPattern) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        for timing_pattern in &behavior.timing_patterns {
            // Check for unusual timing patterns
            if timing_pattern.interval_variance > self.regularity_threshold {
                let confidence =
                    (timing_pattern.interval_variance / self.regularity_threshold).min(1.0);

                // Adjust confidence based on peer ID characteristics
                let peer_risk_factor = if peer_id.contains("bot") || peer_id.contains("auto") {
                    1.3 // Automated-like behavior is more suspicious
                } else if peer_id.contains("human") || peer_id.contains("manual") {
                    0.8 // Human-like behavior is less suspicious
                } else {
                    1.0
                };

                let adjusted_confidence = (confidence * peer_risk_factor).min(1.0);

                results.push(DetectionResult {
                    detection_type: DetectionType::SuspiciousBehavior,
                    confidence: adjusted_confidence,
                    indicators: vec![
                        format!(
                            "Irregular timing variance for peer {}: {:.2}",
                            peer_id, timing_pattern.interval_variance
                        ),
                        format!("Mean interval: {:?}", timing_pattern.interval_mean),
                        format!("Peer risk factor: {:.1}", peer_risk_factor),
                    ],
                    recommended_actions: vec![
                        "increase_monitoring".to_string(),
                        "behavioral_analysis".to_string(),
                    ],
                });
            }

            // Check for unusual peak hours
            if !timing_pattern.peak_hours.is_empty() {
                let current_hour = Instant::now().elapsed().as_secs() / 3600 % 24;
                let is_unusual = !timing_pattern.peak_hours.contains(&(current_hour as u8))
                    && timing_pattern.peak_hours.len() <= 2;

                if is_unusual {
                    // Peer-specific analysis for unusual hours
                    let peer_timezone_risk =
                        if peer_id.contains("night") || peer_id.contains("late") {
                            0.5 // Less suspicious for night-owl peers
                        } else if peer_id.contains("business") || peer_id.contains("office") {
                            1.2 // More suspicious for business-hour peers
                        } else {
                            1.0
                        };

                    results.push(DetectionResult {
                        detection_type: DetectionType::SuspiciousBehavior,
                        confidence: 0.6 * peer_timezone_risk,
                        indicators: vec![
                            format!(
                                "Unusual activity hour for peer {}: {}",
                                peer_id, current_hour
                            ),
                            format!("Expected peak hours: {:?}", timing_pattern.peak_hours),
                            format!("Peer timezone risk: {:.1}", peer_timezone_risk),
                        ],
                        recommended_actions: vec!["increase_monitoring".to_string()],
                    });
                }
            }
        }

        results
    }

    fn pattern_type(&self) -> &'static str {
        "timing_anomaly"
    }
}

/// Content analysis pattern matcher
pub struct ContentAnomalyMatcher {
    /// Entropy threshold for suspicious content
    entropy_threshold: f64,
    /// Repetition threshold
    repetition_threshold: f64,
    /// Size variance threshold
    size_variance_threshold: f64,
}

impl ContentAnomalyMatcher {
    pub fn new() -> Self {
        Self {
            entropy_threshold: 7.0, // High entropy indicates possible encryption/obfuscation
            repetition_threshold: 0.8,
            size_variance_threshold: 2.0,
        }
    }
}

impl PatternMatcher for ContentAnomalyMatcher {
    fn analyze(&self, peer_id: &str, behavior: &BehaviorPattern) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        for content_pattern in &behavior.content_patterns {
            // Check for high entropy (possible encryption/obfuscation)
            if content_pattern.entropy_level > self.entropy_threshold {
                let confidence = (content_pattern.entropy_level / self.entropy_threshold).min(1.0);

                // Peer-specific entropy analysis
                let peer_entropy_profile =
                    if peer_id.contains("crypto") || peer_id.contains("secure") {
                        0.7 // Lower suspicion for crypto-focused peers
                    } else if peer_id.contains("malware") || peer_id.contains("suspicious") {
                        1.5 // Higher suspicion for suspicious peers
                    } else {
                        1.0
                    };

                let adjusted_confidence = (confidence * peer_entropy_profile).min(1.0);

                results.push(DetectionResult {
                    detection_type: DetectionType::SuspiciousBehavior,
                    confidence: adjusted_confidence,
                    indicators: vec![
                        format!(
                            "High content entropy for peer {}: {:.2}",
                            peer_id, content_pattern.entropy_level
                        ),
                        format!(
                            "Message size mean: {:.2}",
                            content_pattern.message_size_mean
                        ),
                        format!("Peer entropy profile: {:.1}", peer_entropy_profile),
                    ],
                    recommended_actions: vec![
                        "content_inspection".to_string(),
                        "crypto_analysis".to_string(),
                    ],
                });
            }

            // Check for repetitive content
            if content_pattern.repetition_score > self.repetition_threshold {
                // Peer-specific repetition analysis
                let peer_repetition_context =
                    if peer_id.contains("bot") || peer_id.contains("automated") {
                        "automated_behavior" // Expected for bots
                    } else if peer_id.contains("human") || peer_id.contains("manual") {
                        "unusual_human" // Unusual for humans
                    } else {
                        "unknown_behavior" // Unknown context
                    };

                results.push(DetectionResult {
                    detection_type: DetectionType::SuspiciousBehavior,
                    confidence: 0.7,
                    indicators: vec![
                        format!(
                            "High repetition score for peer {}: {:.2}",
                            peer_id, content_pattern.repetition_score
                        ),
                        format!("Behavior context: {}", peer_repetition_context),
                    ],
                    recommended_actions: vec![
                        "content_analysis".to_string(),
                        "spam_detection".to_string(),
                    ],
                });
            }

            // Check for unusual size variance
            if content_pattern.message_size_variance > self.size_variance_threshold {
                // Peer-specific size analysis
                let peer_size_profile = if peer_id.contains("media") || peer_id.contains("file") {
                    0.6 // Expected variance for media/file sharing peers
                } else if peer_id.contains("text") || peer_id.contains("chat") {
                    1.4 // Higher suspicion for text/chat peers
                } else {
                    1.0
                };

                let size_confidence: f64 =
                    (content_pattern.message_size_variance / self.size_variance_threshold).min(1.0)
                        * peer_size_profile;

                results.push(DetectionResult {
                    detection_type: DetectionType::SuspiciousBehavior,
                    confidence: size_confidence.min(1.0),
                    indicators: vec![
                        format!(
                            "High size variance for peer {}: {:.2}",
                            peer_id, content_pattern.message_size_variance
                        ),
                        format!("Peer size profile: {:.1}", peer_size_profile),
                    ],
                    recommended_actions: vec!["size_analysis".to_string()],
                });
            }
        }

        results
    }

    fn pattern_type(&self) -> &'static str {
        "content_anomaly"
    }
}

/// Sybil attack pattern matcher
pub struct SybilAttackMatcher {
    /// Minimum peer count for Sybil detection
    min_peer_threshold: u32,
    /// Similarity threshold for peer behavior
    similarity_threshold: f64,
}

impl SybilAttackMatcher {
    pub fn new() -> Self {
        Self {
            min_peer_threshold: 5,
            similarity_threshold: 0.9,
        }
    }
}

impl PatternMatcher for SybilAttackMatcher {
    fn analyze(&self, peer_id: &str, behavior: &BehaviorPattern) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // This would require access to other peers' behavior patterns
        // For now, implement basic checks with peer-specific analysis

        // Check for automated-like behavior (very regular patterns)
        let is_automated = behavior
            .connection_patterns
            .iter()
            .any(|p| p.regularity > self.similarity_threshold)
            && behavior
                .timing_patterns
                .iter()
                .any(|p| p.interval_variance < 0.1);

        if is_automated {
            // Peer-specific Sybil attack risk assessment
            let peer_sybil_risk = if peer_id.contains("cluster") || peer_id.contains("farm") {
                1.8 // Higher risk for potential bot clusters
            } else if peer_id.contains("singleton") || peer_id.contains("unique") {
                0.6 // Lower risk for unique peers
            } else if peer_id.chars().filter(|c| c.is_numeric()).count() > 4 {
                1.4 // Higher risk for peers with many numbers (auto-generated IDs)
            } else {
                1.0
            };

            let confidence: f64 = 0.8 * peer_sybil_risk;

            results.push(DetectionResult {
                detection_type: DetectionType::SuspiciousBehavior,
                confidence: confidence.min(1.0),
                indicators: vec![
                    "Highly regular behavior patterns detected".to_string(),
                    format!(
                        "Peer {} Sybil attack risk factor: {:.1}",
                        peer_id, peer_sybil_risk
                    ),
                    "Possible automated or coordinated activity".to_string(),
                    format!(
                        "Peer ID characteristics: {} numeric chars",
                        peer_id.chars().filter(|c| c.is_numeric()).count()
                    ),
                ],
                recommended_actions: vec![
                    "sybil_analysis".to_string(),
                    "peer_verification".to_string(),
                    "temporary_isolation".to_string(),
                ],
            });
        }

        // Additional peer-specific Sybil attack indicators
        let peer_id_length = peer_id.len();
        let peer_id_entropy = calculate_peer_id_entropy(peer_id);

        if peer_id_length < 6 || peer_id_entropy < 2.0 {
            results.push(DetectionResult {
                detection_type: DetectionType::SuspiciousBehavior,
                confidence: 0.6,
                indicators: vec![
                    format!(
                        "Low peer ID complexity for {}: length={}, entropy={:.1}",
                        peer_id, peer_id_length, peer_id_entropy
                    ),
                    "Potential auto-generated or simplistic ID".to_string(),
                ],
                recommended_actions: vec![
                    "peer_id_analysis".to_string(),
                    "additional_verification".to_string(),
                ],
            });
        }

        results
    }

    fn pattern_type(&self) -> &'static str {
        "sybil_attack"
    }
}

/// Calculate entropy of peer ID for complexity analysis
fn calculate_peer_id_entropy(peer_id: &str) -> f64 {
    let mut char_counts = std::collections::HashMap::new();
    for c in peer_id.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = peer_id.len() as f64;
    let entropy: f64 = char_counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum();

    entropy
}

/// Message flooding pattern matcher
pub struct MessageFloodingMatcher {
    /// Maximum normal message frequency
    max_frequency: f64,
    /// Flood time window
    flood_window: Duration,
}

impl MessageFloodingMatcher {
    pub fn new() -> Self {
        Self {
            max_frequency: 100.0, // messages per minute
            flood_window: Duration::from_secs(60),
        }
    }
    fn pattern_type(&self) -> &'static str {
        "sybil_attack"
    }
}

impl PatternMatcher for MessageFloodingMatcher {
    fn analyze(&self, peer_id: &str, behavior: &BehaviorPattern) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        if behavior.message_frequency > self.max_frequency {
            let confidence = (behavior.message_frequency / self.max_frequency).min(1.0);

            results.push(DetectionResult {
                detection_type: DetectionType::SuspiciousBehavior,
                confidence,
                indicators: vec![
                    format!(
                        "High message frequency: {:.2} msg/min",
                        behavior.message_frequency
                    ),
                    format!("Peer ID: {}", peer_id),
                ],
                recommended_actions: vec![
                    "rate_limit".to_string(),
                    "increase_monitoring".to_string(),
                ],
            });
        }

        results
    }

    fn pattern_type(&self) -> &'static str {
        "message_flooding"
    }
}

/// Convert detection results to threats
pub fn detection_results_to_threats(
    peer_id: &str,
    detection_results: Vec<DetectionResult>,
) -> Vec<Threat> {
    detection_results
        .into_iter()
        .map(|result| {
            let threat_type = match result.detection_type {
                DetectionType::SuspiciousBehavior => ThreatType::MaliciousPeer,
                DetectionType::StatisticalAnomaly => ThreatType::Reconnaissance,
                DetectionType::ReputationAnomaly => ThreatType::MaliciousPeer,
                DetectionType::NetworkAnomaly => ThreatType::SybilAttack,
                DetectionType::CryptoAnomaly => ThreatType::DataTampering,
                DetectionType::ProtocolViolation => ThreatType::Impersonation,
            };

            let severity = if result.confidence > 0.9 {
                Severity::Critical
            } else if result.confidence > 0.7 {
                Severity::High
            } else if result.confidence > 0.5 {
                Severity::Medium
            } else {
                Severity::Low
            };

            Threat {
                id: uuid::Uuid::new_v4().to_string(),
                threat_type,
                source_peer: peer_id.to_string(),
                severity,
                detected_at: Instant::now(),
                status: ThreatStatus::Active,
                description: format!(
                    "{} detected with {:.1}% confidence: {}",
                    format!("{:?}", result.detection_type).to_lowercase(),
                    result.confidence * 100.0,
                    result.indicators.join("; ")
                ),
                mitigation_actions: result.recommended_actions,
            }
        })
        .collect()
}
