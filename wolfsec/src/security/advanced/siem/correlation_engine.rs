use super::{MitreTactic, SecurityEvent};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub correlated_events: Vec<Uuid>,
    pub correlation_score: f64,
    pub attack_chain_detected: bool,
    pub attack_chain: Option<AttackChainAnalysis>,
    pub correlation_rules_matched: Vec<String>,
}

/// Attack chain analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainAnalysis {
    pub chain_id: Uuid,
    pub stages: Vec<AttackStageInfo>,
    pub confidence: f64,
    pub predicted_next_stages: Vec<MitreTactic>,
}

/// Attack stage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStageInfo {
    pub tactic: MitreTactic,
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub completed: bool,
}

/// Wolf Correlation Engine
pub struct WolfCorrelationEngine {
    /// Recent events buffer for correlation
    event_buffer: Vec<SecurityEvent>,
    /// Maximum buffer size
    max_buffer_size: usize,
    /// Correlation time window
    correlation_window: Duration,
}

impl WolfCorrelationEngine {
    /// Create new correlation engine
    pub fn new() -> Result<Self> {
        Ok(Self {
            event_buffer: Vec::new(),
            max_buffer_size: 1000,
            correlation_window: Duration::minutes(60),
        })
    }

    /// Correlate event with historical events
    pub async fn correlate_event(&mut self, event: &SecurityEvent) -> Result<CorrelationResult> {
        // Add event to buffer
        self.event_buffer.push(event.clone());

        // Trim buffer if needed
        if self.event_buffer.len() > self.max_buffer_size {
            self.event_buffer.remove(0);
        }

        // Find related events within time window
        let related_events = self.find_related_events(event);

        // Calculate correlation score
        let correlation_score = self.calculate_correlation_score(&related_events);

        // Detect attack chains
        let (attack_chain_detected, attack_chain) =
            self.detect_attack_chain(event, &related_events);

        // Match correlation rules
        let correlation_rules_matched = self.match_correlation_rules(event, &related_events);

        Ok(CorrelationResult {
            correlated_events: related_events.iter().map(|e| e.event_id).collect(),
            correlation_score,
            attack_chain_detected,
            attack_chain,
            correlation_rules_matched,
        })
    }

    /// Find events related to the current event
    fn find_related_events(&self, event: &SecurityEvent) -> Vec<SecurityEvent> {
        let cutoff_time = event.timestamp - self.correlation_window;

        self.event_buffer
            .iter()
            .filter(|e| {
                e.timestamp >= cutoff_time
                    && e.event_id != event.event_id
                    && self.is_related(event, e)
            })
            .cloned()
            .collect()
    }

    /// Check if two events are related
    fn is_related(&self, event1: &SecurityEvent, event2: &SecurityEvent) -> bool {
        // Events are related if they:
        // 1. Share the same source
        // 2. Affect the same assets
        // 3. Have overlapping MITRE tactics

        let same_source = event1.source.source_id == event2.source.source_id;

        let shared_assets = event1.affected_assets.iter().any(|a1| {
            event2
                .affected_assets
                .iter()
                .any(|a2| a1.asset_id == a2.asset_id)
        });

        let shared_tactics = event1
            .mitre_tactics
            .iter()
            .any(|t1| event2.mitre_tactics.contains(t1));

        same_source || shared_assets || shared_tactics
    }

    /// Calculate correlation score
    fn calculate_correlation_score(&self, related_events: &[SecurityEvent]) -> f64 {
        if related_events.is_empty() {
            return 0.0;
        }

        // Score based on number of related events and their severity
        let event_count_score = (related_events.len() as f64 / 10.0).min(0.5);

        let severity_score: f64 = related_events
            .iter()
            .map(|e| match e.severity {
                super::EventSeverity::Alpha => 1.0,
                super::EventSeverity::Beta => 0.8,
                super::EventSeverity::Hunter => 0.5,
                super::EventSeverity::Scout => 0.3,
                super::EventSeverity::Pup => 0.1,
            })
            .sum::<f64>()
            / related_events.len() as f64;

        (event_count_score + severity_score) / 2.0
    }

    /// Detect attack chains using MITRE ATT&CK sequences
    fn detect_attack_chain(
        &self,
        current_event: &SecurityEvent,
        related_events: &[SecurityEvent],
    ) -> (bool, Option<AttackChainAnalysis>) {
        // Common attack chain: Initial Access → Execution → Persistence → Privilege Escalation
        let attack_sequence = vec![
            MitreTactic::InitialAccess,
            MitreTactic::Execution,
            MitreTactic::Persistence,
            MitreTactic::PrivilegeEscalation,
        ];

        // Collect all tactics from related events
        let mut all_events: Vec<&SecurityEvent> = related_events.iter().collect();
        all_events.push(current_event);
        all_events.sort_by_key(|e| e.timestamp);

        // Track which stages have been observed
        let mut observed_stages: Vec<AttackStageInfo> = Vec::new();

        for event in &all_events {
            for tactic in &event.mitre_tactics {
                if attack_sequence.contains(tactic) {
                    observed_stages.push(AttackStageInfo {
                        tactic: tactic.clone(),
                        event_id: event.event_id,
                        timestamp: event.timestamp,
                        completed: true,
                    });
                }
            }
        }

        // Deduplicate stages (keep first occurrence of each tactic)
        let mut seen_tactics: HashMap<String, bool> = HashMap::new();
        observed_stages.retain(|stage| {
            let key = format!("{:?}", stage.tactic);
            if seen_tactics.contains_key(&key) {
                false
            } else {
                seen_tactics.insert(key, true);
                true
            }
        });

        // Attack chain detected if we see at least 2 consecutive stages
        let chain_detected = observed_stages.len() >= 2;

        if chain_detected {
            // Predict next stages
            let last_tactic = &observed_stages.last().unwrap().tactic;
            let predicted_next = self.predict_next_tactics(last_tactic);

            let confidence = (observed_stages.len() as f64 / attack_sequence.len() as f64).min(1.0);

            (
                true,
                Some(AttackChainAnalysis {
                    chain_id: Uuid::new_v4(),
                    stages: observed_stages,
                    confidence,
                    predicted_next_stages: predicted_next,
                }),
            )
        } else {
            (false, None)
        }
    }

    /// Predict next tactics in attack chain
    fn predict_next_tactics(&self, current_tactic: &MitreTactic) -> Vec<MitreTactic> {
        match current_tactic {
            MitreTactic::InitialAccess => vec![MitreTactic::Execution, MitreTactic::Persistence],
            MitreTactic::Execution => {
                vec![MitreTactic::Persistence, MitreTactic::PrivilegeEscalation]
            }
            MitreTactic::Persistence => vec![
                MitreTactic::PrivilegeEscalation,
                MitreTactic::DefenseEvasion,
            ],
            MitreTactic::PrivilegeEscalation => {
                vec![MitreTactic::DefenseEvasion, MitreTactic::CredentialAccess]
            }
            MitreTactic::DefenseEvasion => {
                vec![MitreTactic::CredentialAccess, MitreTactic::Discovery]
            }
            MitreTactic::CredentialAccess => {
                vec![MitreTactic::Discovery, MitreTactic::LateralMovement]
            }
            MitreTactic::Discovery => vec![MitreTactic::LateralMovement, MitreTactic::Collection],
            MitreTactic::LateralMovement => {
                vec![MitreTactic::Collection, MitreTactic::Exfiltration]
            }
            MitreTactic::Collection => vec![MitreTactic::Exfiltration, MitreTactic::Impact],
            MitreTactic::CommandAndControl => vec![MitreTactic::Exfiltration, MitreTactic::Impact],
            MitreTactic::Exfiltration => vec![MitreTactic::Impact],
            MitreTactic::Impact => vec![],
        }
    }

    /// Match correlation rules
    fn match_correlation_rules(
        &self,
        event: &SecurityEvent,
        related_events: &[SecurityEvent],
    ) -> Vec<String> {
        let mut matched_rules = Vec::new();

        // Rule: Multiple failed logins followed by successful login
        if self.check_brute_force_pattern(event, related_events) {
            matched_rules.push("Brute Force Attack Pattern".to_string());
        }

        // Rule: Privilege escalation after unusual access
        if self.check_privilege_escalation_pattern(event, related_events) {
            matched_rules.push("Privilege Escalation After Anomaly".to_string());
        }

        // Rule: Data exfiltration after lateral movement
        if self.check_exfiltration_pattern(event, related_events) {
            matched_rules.push("Data Exfiltration After Lateral Movement".to_string());
        }

        matched_rules
    }

    /// Check for brute force attack pattern
    fn check_brute_force_pattern(
        &self,
        _event: &SecurityEvent,
        related_events: &[SecurityEvent],
    ) -> bool {
        // Count failed login attempts in related events
        let failed_logins = related_events
            .iter()
            .filter(|e| matches!(e.event_type, super::SecurityEventType::AuthEvent(_)))
            .count();

        failed_logins >= 3
    }

    /// Check for privilege escalation pattern
    fn check_privilege_escalation_pattern(
        &self,
        event: &SecurityEvent,
        _related_events: &[SecurityEvent],
    ) -> bool {
        event
            .mitre_tactics
            .contains(&MitreTactic::PrivilegeEscalation)
    }

    /// Check for data exfiltration pattern
    fn check_exfiltration_pattern(
        &self,
        event: &SecurityEvent,
        related_events: &[SecurityEvent],
    ) -> bool {
        let has_lateral_movement = related_events
            .iter()
            .any(|e| e.mitre_tactics.contains(&MitreTactic::LateralMovement));

        let has_exfiltration = event.mitre_tactics.contains(&MitreTactic::Exfiltration);

        has_lateral_movement && has_exfiltration
    }
    /// Get correlation statistics
    pub fn get_statistics(&self) -> CorrelationStatistics {
        CorrelationStatistics {
            total_correlations: 0, // TODO: Track actual stats
            active_chains: 0,
        }
    }
}

/// Correlation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationStatistics {
    pub total_correlations: usize,
    pub active_chains: usize,
}
