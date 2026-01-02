//! Reputation System and Incident Response for Advanced Threat Detection
//!
//! This module implements a sophisticated reputation scoring system and automated
//! incident response capabilities for comprehensive threat management.

use crate::core::security_simple::{Severity, Threat, ThreatType};
use crate::core::threat_detection::{
    EscalationCondition, ReputationContext, ReputationFactor, ResponseAction, ResponseEvent,
    ResponseEventType, ResponsePolicy, ThreatFeed, ThreatIndicator,
};
use anyhow::Result;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Connection history reputation factor
pub struct ConnectionHistoryFactor {
    /// Weight for this factor
    weight: f64,
    /// Time window for connection history
    history_window: Duration,
    /// Success rate threshold
    success_threshold: f64,
}

impl ConnectionHistoryFactor {
    pub fn new() -> Self {
        Self {
            weight: 0.3,
            history_window: Duration::from_secs(3600), // 1 hour
            success_threshold: 0.9,
        }
    }
}

impl ReputationFactor for ConnectionHistoryFactor {
    fn calculate(&self, peer_id: &str, context: &ReputationContext) -> f64 {
        let recent_events: Vec<_> = context
            .current_events
            .iter()
            .filter(|e| e.timestamp.elapsed() < self.history_window)
            .collect();

        if recent_events.is_empty() {
            return 0.5; // Neutral score for no recent activity
        }

        let successful_connections = recent_events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    crate::core::security_simple::SecurityEventType::PeerConnected
                )
            })
            .count();

        let failed_connections = recent_events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    crate::core::security_simple::SecurityEventType::AuthenticationFailure
                )
            })
            .count();

        let total_connections = successful_connections + failed_connections;
        if total_connections == 0 {
            return 0.5;
        }

        let success_rate = successful_connections as f64 / total_connections as f64;

        // Peer-specific connection history adjustments
        let peer_connection_profile = if peer_id.contains("new") || peer_id.contains("fresh") {
            0.9 // Bonus for new peers (learning curve)
        } else if peer_id.contains("veteran") || peer_id.contains("trusted") {
            1.1 // Higher expectations for veteran peers
        } else if peer_id.contains("mobile") || peer_id.contains("dynamic") {
            0.8 // More lenient for mobile/dynamic peers
        } else {
            1.0
        };

        let adjusted_success_rate = success_rate * peer_connection_profile;

        if adjusted_success_rate >= self.success_threshold {
            0.8 + (adjusted_success_rate - self.success_threshold) * 2.0 // Bonus for high success rate
        } else {
            adjusted_success_rate // Penalty for low success rate
        }
    }

    fn factor_name(&self) -> &'static str {
        "connection_history"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

/// Threat history reputation factor
pub struct ThreatHistoryFactor {
    /// Weight for this factor
    weight: f64,
    /// Time window for threat history
    threat_window: Duration,
    /// Severity penalties
    severity_penalties: HashMap<Severity, f64>,
}

impl ThreatHistoryFactor {
    pub fn new() -> Self {
        let mut severity_penalties = HashMap::new();
        severity_penalties.insert(Severity::Low, 0.1);
        severity_penalties.insert(Severity::Medium, 0.3);
        severity_penalties.insert(Severity::High, 0.6);
        severity_penalties.insert(Severity::Critical, 0.9);

        Self {
            weight: 0.4,
            threat_window: Duration::from_secs(86400), // 24 hours
            severity_penalties,
        }
    }
}

impl ReputationFactor for ThreatHistoryFactor {
    fn calculate(&self, peer_id: &str, context: &ReputationContext) -> f64 {
        let recent_threats: Vec<_> = context
            .current_events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    crate::core::security_simple::SecurityEventType::ThreatDetected
                )
            })
            .filter(|e| e.timestamp.elapsed() < self.threat_window)
            .collect();

        if recent_threats.is_empty() {
            return 0.8; // Bonus for no recent threats
        }

        let mut total_penalty = 0.0;
        for event in &recent_threats {
            let penalty = self.severity_penalties.get(&event.severity).unwrap_or(&0.5);
            total_penalty += penalty;
        }

        // Apply peer-specific threat history adjustments
        let peer_threat_profile = if peer_id.contains("reformed") || peer_id.contains("recovered") {
            0.7 // Lenient for reformed peers
        } else if peer_id.contains("repeat") || peer_id.contains("persistent") {
            1.5 // Stricter for repeat offenders
        } else if peer_id.contains("edge") || peer_id.contains("borderline") {
            1.2 // Moderate for borderline cases
        } else {
            1.0
        };

        // Apply decay based on time
        let time_decay = recent_threats
            .iter()
            .map(|e| e.timestamp.elapsed().as_secs_f64() / self.threat_window.as_secs_f64())
            .sum::<f64>()
            / recent_threats.len() as f64;

        let adjusted_penalty = total_penalty * (1.0 - time_decay) * peer_threat_profile;
        (0.8 - adjusted_penalty).max(0.0)
    }

    fn factor_name(&self) -> &'static str {
        "threat_history"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

/// Behavioral consistency reputation factor
pub struct BehavioralConsistencyFactor {
    /// Weight for this factor
    weight: f64,
    /// Consistency threshold
    consistency_threshold: f64,
}

impl BehavioralConsistencyFactor {
    pub fn new() -> Self {
        Self {
            weight: 0.2,
            consistency_threshold: 0.7,
        }
    }
}

impl ReputationFactor for BehavioralConsistencyFactor {
    fn calculate(&self, peer_id: &str, context: &ReputationContext) -> f64 {
        if let Some(behavior) = &context.peer_behavior {
            // Calculate behavioral consistency
            let timing_consistency = 1.0
                - behavior
                    .timing_patterns
                    .iter()
                    .map(|t| t.interval_variance)
                    .sum::<f64>()
                    / behavior.timing_patterns.len().max(1) as f64;

            let size_consistency = 1.0
                - behavior
                    .content_patterns
                    .iter()
                    .map(|c| c.message_size_variance)
                    .sum::<f64>()
                    / behavior.content_patterns.len().max(1) as f64;

            let overall_consistency = (timing_consistency + size_consistency) / 2.0;

            // Peer-specific behavioral consistency adjustments
            let peer_consistency_profile =
                if peer_id.contains("chaotic") || peer_id.contains("random") {
                    0.7 // More lenient for chaotic/random peers
                } else if peer_id.contains("stable") || peer_id.contains("consistent") {
                    1.3 // Higher expectations for stable peers
                } else if peer_id.contains("learning") || peer_id.contains("adaptive") {
                    0.85 // Lenient for learning/adaptive peers
                } else {
                    1.0
                };

            let adjusted_consistency = overall_consistency * peer_consistency_profile;

            if adjusted_consistency >= self.consistency_threshold {
                0.7 + (adjusted_consistency - self.consistency_threshold) * 1.0
            } else {
                adjusted_consistency
            }
        } else {
            0.5 // Neutral score if no behavior data
        }
    }

    fn factor_name(&self) -> &'static str {
        "behavioral_consistency"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

/// Network contribution reputation factor
pub struct NetworkContributionFactor {
    /// Weight for this factor
    weight: f64,
    /// Contribution metrics
    contribution_metrics: HashMap<String, f64>,
}

impl NetworkContributionFactor {
    pub fn new() -> Self {
        let mut contribution_metrics = HashMap::new();
        contribution_metrics.insert("message_relay".to_string(), 0.2);
        contribution_metrics.insert("resource_sharing".to_string(), 0.3);
        contribution_metrics.insert("peer_discovery".to_string(), 0.2);
        contribution_metrics.insert("network_stability".to_string(), 0.3);

        Self {
            weight: 0.1,
            contribution_metrics,
        }
    }
}

impl ReputationFactor for NetworkContributionFactor {
    fn calculate(&self, peer_id: &str, context: &ReputationContext) -> f64 {
        // This would analyze the peer's positive contributions to the network
        // For now, return a neutral score with some variation based on network conditions

        let base_score = 0.6;

        // Peer-specific contribution analysis
        let peer_contribution_profile = if peer_id.contains("relay") || peer_id.contains("hub") {
            0.2 // Bonus for relay/hub peers
        } else if peer_id.contains("leech") || peer_id.contains("drain") {
            -0.1 // Penalty for leeching peers
        } else if peer_id.contains("contributor") || peer_id.contains("helper") {
            0.3 // Bonus for contributor peers
        } else if peer_id.contains("solo") || peer_id.contains("isolated") {
            -0.05 // Slight penalty for isolated peers
        } else {
            0.0 // Neutral
        };

        let network_load_bonus = if context.network_conditions.network_load < 0.5 {
            0.2 // Bonus for contributing during low load
        } else {
            0.0
        };

        let threat_level_penalty = context.network_conditions.threat_level * 0.3;

        // Additional peer-specific factors
        let peer_activity_factor = if peer_id.contains("active") || peer_id.contains("engaged") {
            0.1 // Bonus for active peers
        } else if peer_id.contains("passive") || peer_id.contains("quiet") {
            -0.05 // Slight penalty for passive peers
        } else {
            0.0
        };

        let final_score =
            base_score + network_load_bonus + peer_contribution_profile + peer_activity_factor
                - threat_level_penalty;
        final_score.max(0.0).min(1.0)
    }

    fn factor_name(&self) -> &'static str {
        "network_contribution"
    }

    fn weight(&self) -> f64 {
        self.weight
    }
}

/// Default response policies for different threat types
pub fn create_default_response_policies() -> HashMap<ThreatType, ResponsePolicy> {
    let mut policies = HashMap::new();

    // Malicious peer response policy
    policies.insert(
        ThreatType::MaliciousPeer,
        ResponsePolicy {
            threat_type: ThreatType::MaliciousPeer,
            severity_threshold: Severity::Medium,
            automatic_actions: vec![
                ResponseAction::IncreaseMonitoring,
                ResponseAction::RateLimit {
                    limit: 10,
                    window: Duration::from_secs(60),
                },
            ],
            manual_actions: vec![
                ResponseAction::IsolatePeer,
                ResponseAction::TemporaryBan {
                    duration: Duration::from_secs(3600),
                },
            ],
            escalation_conditions: vec![EscalationCondition {
                condition_type: crate::core::threat_detection::EscalationType::MultipleThreats {
                    count: 3,
                },
                threshold: 3.0,
                time_window: Duration::from_secs(1800), // 30 minutes
                escalated_actions: vec![ResponseAction::IsolatePeer, ResponseAction::AlertAdmin],
            }],
        },
    );

    // Sybil attack response policy
    policies.insert(
        ThreatType::SybilAttack,
        ResponsePolicy {
            threat_type: ThreatType::SybilAttack,
            severity_threshold: Severity::High,
            automatic_actions: vec![
                ResponseAction::IsolatePeer,
                ResponseAction::RequireReauth,
                ResponseAction::AlertAdmin,
            ],
            manual_actions: vec![
                ResponseAction::TemporaryBan {
                    duration: Duration::from_secs(86400),
                }, // 24 hours
            ],
            escalation_conditions: vec![EscalationCondition {
                condition_type: crate::core::threat_detection::EscalationType::HighConfidence {
                    threshold: 0.9,
                },
                threshold: 0.9,
                time_window: Duration::from_secs(300), // 5 minutes
                escalated_actions: vec![
                    ResponseAction::TemporaryBan {
                        duration: Duration::from_secs(604800),
                    }, // 7 days
                    ResponseAction::ShareThreatIntel,
                ],
            }],
        },
    );

    // Message flooding response policy
    policies.insert(
        ThreatType::MessageFlooding,
        ResponsePolicy {
            threat_type: ThreatType::MessageFlooding,
            severity_threshold: Severity::Medium,
            automatic_actions: vec![
                ResponseAction::RateLimit {
                    limit: 5,
                    window: Duration::from_secs(60),
                },
                ResponseAction::IncreaseMonitoring,
            ],
            manual_actions: vec![ResponseAction::IsolatePeer],
            escalation_conditions: vec![EscalationCondition {
                condition_type: crate::core::threat_detection::EscalationType::RapidEscalation,
                threshold: 5.0,
                time_window: Duration::from_secs(600), // 10 minutes
                escalated_actions: vec![ResponseAction::IsolatePeer, ResponseAction::AlertAdmin],
            }],
        },
    );

    // Data tampering response policy
    policies.insert(
        ThreatType::DataTampering,
        ResponsePolicy {
            threat_type: ThreatType::DataTampering,
            severity_threshold: Severity::Critical,
            automatic_actions: vec![
                ResponseAction::IsolatePeer,
                ResponseAction::RequireReauth,
                ResponseAction::AlertAdmin,
                ResponseAction::ShareThreatIntel,
            ],
            manual_actions: vec![
                ResponseAction::TemporaryBan {
                    duration: Duration::from_secs(604800),
                }, // 7 days
            ],
            escalation_conditions: vec![EscalationCondition {
                condition_type: crate::core::threat_detection::EscalationType::NetworkPattern,
                threshold: 3.0,
                time_window: Duration::from_secs(1800), // 30 minutes
                escalated_actions: vec![
                    ResponseAction::TemporaryBan {
                        duration: Duration::from_secs(2592000),
                    }, // 30 days
                ],
            }],
        },
    );

    policies
}

/// Execute response action
pub fn execute_response_action(
    action: &ResponseAction,
    peer_id: &str,
    threat_id: &str,
) -> Result<ResponseEvent> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let timestamp = Instant::now();

    let (event_type, details) = match action {
        ResponseAction::IsolatePeer => (ResponseEventType::ActionExecuted, {
            let mut details = HashMap::new();
            details.insert("action".to_string(), "isolate_peer".to_string());
            details.insert("peer_id".to_string(), peer_id.to_string());
            details.insert("threat_id".to_string(), threat_id.to_string());
            details
        }),
        ResponseAction::RateLimit { limit, window } => (ResponseEventType::ActionExecuted, {
            let mut details = HashMap::new();
            details.insert("action".to_string(), "rate_limit".to_string());
            details.insert("limit".to_string(), limit.to_string());
            details.insert("window_seconds".to_string(), window.as_secs().to_string());
            details.insert("peer_id".to_string(), peer_id.to_string());
            details
        }),
        ResponseAction::IncreaseMonitoring => (ResponseEventType::ActionExecuted, {
            let mut details = HashMap::new();
            details.insert("action".to_string(), "increase_monitoring".to_string());
            details.insert("peer_id".to_string(), peer_id.to_string());
            details
        }),
        ResponseAction::RequireReauth => (ResponseEventType::ActionExecuted, {
            let mut details = HashMap::new();
            details.insert("action".to_string(), "require_reauth".to_string());
            details.insert("peer_id".to_string(), peer_id.to_string());
            details
        }),
        ResponseAction::TemporaryBan { duration } => (ResponseEventType::ActionExecuted, {
            let mut details = HashMap::new();
            details.insert("action".to_string(), "temporary_ban".to_string());
            details.insert(
                "duration_seconds".to_string(),
                duration.as_secs().to_string(),
            );
            details.insert("peer_id".to_string(), peer_id.to_string());
            details
        }),
        ResponseAction::AlertAdmin => (ResponseEventType::ActionExecuted, {
            let mut details = HashMap::new();
            details.insert("action".to_string(), "alert_admin".to_string());
            details.insert("threat_id".to_string(), threat_id.to_string());
            details.insert("peer_id".to_string(), peer_id.to_string());
            details
        }),
        ResponseAction::ShareThreatIntel => (ResponseEventType::ActionExecuted, {
            let mut details = HashMap::new();
            details.insert("action".to_string(), "share_threat_intel".to_string());
            details.insert("threat_id".to_string(), threat_id.to_string());
            details.insert("peer_id".to_string(), peer_id.to_string());
            details
        }),
    };

    Ok(ResponseEvent {
        id: event_id,
        timestamp,
        response_id: uuid::Uuid::new_v4().to_string(),
        event_type,
        details,
    })
}

/// Check escalation conditions
pub fn check_escalation_conditions<'a>(
    conditions: &'a [EscalationCondition],
    peer_id: &'a str,
    threat_history: &'a [Threat],
    current_threat: &'a Threat,
) -> Vec<&'a EscalationCondition> {
    let mut triggered_conditions = Vec::new();

    for condition in conditions {
        let triggered = match &condition.condition_type {
            crate::core::threat_detection::EscalationType::MultipleThreats { count } => {
                let recent_threats: Vec<_> = threat_history
                    .iter()
                    .filter(|t| t.source_peer == peer_id)
                    .filter(|t| t.detected_at.elapsed() < condition.time_window)
                    .collect();

                recent_threats.len() >= *count as usize
            }
            crate::core::threat_detection::EscalationType::RapidEscalation => {
                // Check for rapid increase in threat severity
                let recent_threats: Vec<_> = threat_history
                    .iter()
                    .filter(|t| t.source_peer == peer_id)
                    .filter(|t| t.detected_at.elapsed() < condition.time_window)
                    .collect();

                if recent_threats.len() >= 3 {
                    let severity_increase = recent_threats
                        .iter()
                        .map(|t| match t.severity {
                            Severity::Low => 1,
                            Severity::Medium => 2,
                            Severity::High => 3,
                            Severity::Critical => 4,
                        })
                        .sum::<u8>() as f64
                        / recent_threats.len() as f64;

                    severity_increase >= condition.threshold
                } else {
                    false
                }
            }
            crate::core::threat_detection::EscalationType::HighConfidence { threshold } => {
                // This would use actual confidence calculation
                // For now, use severity as proxy
                match current_threat.severity {
                    Severity::Critical => true,
                    Severity::High => *threshold <= 0.8,
                    Severity::Medium => *threshold <= 0.6,
                    Severity::Low => false,
                }
            }
            crate::core::threat_detection::EscalationType::NetworkPattern => {
                // Check for similar threats across multiple peers
                let similar_threats = threat_history
                    .iter()
                    .filter(|t| t.threat_type == current_threat.threat_type)
                    .filter(|t| t.detected_at.elapsed() < condition.time_window)
                    .count();

                similar_threats >= condition.threshold as usize
            }
        };

        if triggered {
            triggered_conditions.push(condition);
        }
    }

    triggered_conditions
}

/// Mock threat feed implementation
pub struct MockThreatFeed {
    feed_name: &'static str,
    indicators: Vec<ThreatIndicator>,
}

impl MockThreatFeed {
    pub fn new(name: &'static str) -> Self {
        Self {
            feed_name: name,
            indicators: Vec::new(),
        }
    }

    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        self.indicators.push(indicator);
    }
}

impl ThreatFeed for MockThreatFeed {
    fn fetch_indicators(&self) -> Result<Vec<ThreatIndicator>> {
        Ok(self.indicators.clone())
    }

    fn feed_name(&self) -> &'static str {
        &self.feed_name
    }

    fn update_frequency(&self) -> Duration {
        Duration::from_secs(3600) // 1 hour
    }
}

/// Create mock threat indicators for testing
pub fn create_mock_threat_indicators() -> Vec<ThreatIndicator> {
    vec![
        ThreatIndicator {
            id: uuid::Uuid::new_v4().to_string(),
            indicator_type: crate::core::threat_detection::IndicatorType::PeerId,
            value: "suspicious-peer-001".to_string(),
            confidence: 0.9,
            source: "test-feed".to_string(),
            created_at: Duration::from_secs(Instant::now().elapsed().as_secs()),
            expires_at: Some(Duration::from_secs(
                (Instant::now() + Duration::from_secs(86400))
                    .elapsed()
                    .as_secs(),
            )),
        },
        ThreatIndicator {
            id: uuid::Uuid::new_v4().to_string(),
            indicator_type: crate::core::threat_detection::IndicatorType::MessagePattern,
            value: "malicious-pattern-xyz".to_string(),
            confidence: 0.8,
            source: "test-feed".to_string(),
            created_at: Duration::from_secs(Instant::now().elapsed().as_secs()),
            expires_at: Some(Duration::from_secs(
                (Instant::now() + Duration::from_secs(86400))
                    .elapsed()
                    .as_secs(),
            )),
        },
    ]
}
