//! Wolf Trust Engine
//!
//! Implements sophisticated trust evaluation algorithms with wolf pack behavioral patterns.
//! Wolves constantly evaluate trust levels of pack members and outsiders.

use anyhow::Result;
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

use super::{
    ContextualFactor, SecurityAction, TrustContext, TrustEvaluationResult,
    TrustLevel,
};
use libp2p::PeerId; // Use libp2p's PeerId directly

/// Wolf Trust Engine - evaluates trust based on behavioral patterns
pub struct WolfTrustEngine {
    /// Current trust levels for all peers
    trust_levels: HashMap<PeerId, TrustLevel>,
    /// Historical trust data
    trust_history: HashMap<PeerId, Vec<TrustSnapshot>>,
    /// Behavioral analysis engine
    behavior_analyzer: WolfBehaviorAnalyzer,
    /// Trust decay configuration
    decay_config: TrustDecayConfig,
    /// Risk factors configuration
    risk_factors: RiskFactors,
}

/// Trust snapshot for historical tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSnapshot {
    pub timestamp: DateTime<Utc>,
    pub trust_level: TrustLevel,
    pub confidence_score: f64,
    pub risk_score: f64,
    pub context_factors: Vec<String>,
    pub evaluation_reason: String,
}

/// Behavioral analysis engine
pub struct WolfBehaviorAnalyzer {
    /// Normal behavioral patterns
    normal_patterns: HashMap<PeerId, BehavioralPattern>,
    /// Anomaly detection thresholds
    anomaly_thresholds: AnomalyThresholds,
    /// Learning rate for pattern adaptation
    learning_rate: f64,
}

/// Behavioral pattern for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    pub peer_id: PeerId,
    pub access_frequency: f64,
    pub typical_locations: Vec<String>,
    pub typical_devices: Vec<String>,
    pub typical_time_windows: Vec<TimeWindow>,
    pub communication_patterns: CommunicationPattern,
    pub resource_usage: ResourceUsagePattern,
    pub last_updated: DateTime<Utc>,
}

/// Time window for typical access patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start_hour: u8,
    pub end_hour: u8,
    pub day_type: DayType,
    pub confidence: f64,
}

/// Day type classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DayType {
    Weekday,
    Weekend,
    Holiday,
}

/// Communication patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationPattern {
    pub average_message_frequency: f64,
    pub typical_message_sizes: Vec<f64>,
    pub preferred_protocols: Vec<String>,
    pub communication_partners: Vec<PeerId>,
}

/// Resource usage patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsagePattern {
    pub cpu_usage_average: f64,
    pub memory_usage_average: f64,
    pub network_usage_average: f64,
    pub storage_access_patterns: Vec<String>,
}

/// Anomaly detection thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyThresholds {
    pub location_deviation_threshold: f64,
    pub time_deviation_threshold: f64,
    pub behavior_deviation_threshold: f64,
    pub resource_usage_threshold: f64,
    pub communication_deviation_threshold: f64,
}

/// Trust decay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDecayConfig {
    /// Decay rate per hour of inactivity
    pub hourly_decay_rate: f64,
    /// Minimum trust level before reset
    pub minimum_trust_level: TrustLevel,
    /// Boost factor for positive interactions
    pub positive_interaction_boost: f64,
    /// Penalty factor for negative interactions
    pub negative_interaction_penalty: f64,
}

/// Risk factors configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactors {
    /// Location-based risk factors
    pub location_risks: HashMap<String, f64>,
    /// Device-based risk factors
    pub device_risks: HashMap<String, f64>,
    /// Time-based risk factors
    pub time_risks: HashMap<String, f64>,
    /// Behavioral risk factors
    pub behavioral_risks: HashMap<String, f64>,
    /// Environmental risk factors
    pub environmental_risks: HashMap<String, f64>,
}

/// Behavioral score calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralScore {
    pub overall_score: f64,
    pub consistency_score: f64,
    pub predictability_score: f64,
    pub risk_score: f64,
    pub confidence: f64,
}

impl WolfTrustEngine {
    /// Create new Wolf Trust Engine
    pub fn new() -> Result<Self> {
        info!("🐺 Initializing Wolf Trust Engine");

        let engine = Self {
            trust_levels: HashMap::new(),
            trust_history: HashMap::new(),
            behavior_analyzer: WolfBehaviorAnalyzer::new(),
            decay_config: TrustDecayConfig::default(),
            risk_factors: RiskFactors::default(),
        };

        Ok(engine)
    }

    /// Initialize the trust engine
    pub async fn initialize(&mut self) -> Result<()> {
        info!("🐺 Trust Engine initialized");
        Ok(())
    }

    /// Evaluate base trust level for a peer
    pub async fn evaluate_base_trust(
        &self,
        context: &TrustContext,
    ) -> Result<TrustEvaluationResult> {
        debug!(
            "🔍 Evaluating base trust for peer: {}",
            context.peer_id.to_string()
        );

        // Get current trust level or default to Unknown
        let current_trust = self
            .trust_levels
            .get(&context.peer_id)
            .unwrap_or(&TrustLevel::Unknown)
            .clone();

        // Analyze behavioral patterns
        let behavioral_score = self.behavior_analyzer.analyze_behavior(context).await?;

        // Calculate contextual risk factors
        let contextual_risks = self.calculate_contextual_risks(context);

        // Apply trust decay
        let decayed_trust = self.apply_trust_decay(&context.peer_id, current_trust);

        // Calculate final trust level
        let final_trust = self.calculate_final_trust(
            decayed_trust,
            &behavioral_score,
            &contextual_risks,
            context,
        );

        // Generate contextual factors
        let contextual_factors =
            self.generate_contextual_factors(&behavioral_score, &contextual_risks, context);

        // Calculate confidence and risk scores
        let confidence_score =
            self.calculate_confidence_score(&behavioral_score, &contextual_factors);
        let risk_score = self.calculate_risk_score(&behavioral_score, &contextual_risks);

        // Generate recommended actions
        let recommended_actions = self.generate_recommendations(
            final_trust,
            confidence_score,
            risk_score,
            &contextual_factors,
        );

        let result = TrustEvaluationResult {
            peer_id: context.peer_id.clone(),
            trust_level: final_trust,
            confidence_score,
            risk_score,
            contextual_factors,
            recommended_actions,
            evaluation_timestamp: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };

        info!(
            "🎯 Trust evaluation completed for {}: {:?} (confidence: {:.2}, risk: {:.2})",
            context.peer_id.to_string(),
            final_trust,
            confidence_score,
            risk_score
        );

        Ok(result)
    }

    /// Update trust level based on interaction
    pub async fn update_trust_from_interaction(
        &mut self,
        peer_id: &PeerId,
        interaction: &Interaction,
    ) -> Result<()> {
        debug!("🐺 Updating trust for peer: {}", peer_id.to_string());

        let current_trust = self
            .trust_levels
            .get(peer_id)
            .cloned()
            .unwrap_or(TrustLevel::Unknown);
        let new_trust = self.calculate_trust_change(&current_trust, interaction);

        // Update trust level
        self.trust_levels.insert(peer_id.clone(), new_trust);

        // Store trust snapshot
        let snapshot = TrustSnapshot {
            timestamp: Utc::now(),
            trust_level: new_trust,
            confidence_score: 0.8, // Default confidence for interaction-based updates
            risk_score: self.calculate_interaction_risk(interaction),
            context_factors: vec![format!("interaction: {:?}", interaction.interaction_type)],
            evaluation_reason: format!("Updated from {:?}", interaction.interaction_type),
        };

        // Add to history
        let history = self
            .trust_history
            .entry(peer_id.clone())
            .or_insert_with(Vec::new);
        history.push(snapshot);

        // Keep only last 100 snapshots
        if history.len() > 100 {
            history.remove(0);
        }

        // Update behavioral patterns
        self.behavior_analyzer
            .update_patterns(peer_id, interaction)
            .await?;

        info!(
            "✅ Trust updated for {}: {:?} -> {:?}",
            peer_id.to_string(),
            current_trust,
            new_trust
        );
        Ok(())
    }

    /// Get trust history for a peer
    pub fn get_trust_history(&self, peer_id: &PeerId) -> Vec<&TrustSnapshot> {
        self.trust_history
            .get(peer_id)
            .map(|history| history.iter().collect())
            .unwrap_or_default()
    }

    /// Apply trust decay based on inactivity
    fn apply_trust_decay(&self, peer_id: &PeerId, current_trust: TrustLevel) -> TrustLevel {
        let history = self.trust_history.get(peer_id);

        if let Some(snapshots) = history {
            if let Some(latest) = snapshots.last() {
                let hours_since_last = (Utc::now() - latest.timestamp).num_hours() as f64;

                if hours_since_last > 0.0 {
                    let decay_amount =
                        (hours_since_last * self.decay_config.hourly_decay_rate) as i32;
                    let current_level = current_trust as i32;
                    let decayed_level = (current_level - decay_amount)
                        .max(self.decay_config.minimum_trust_level as i32);

                    debug!(
                        "⏰ Trust decay applied to {}: {:?} -> {:?} ({} hours inactive)",
                        peer_id.to_string(),
                        current_trust,
                        TrustLevel::from(decayed_level as u8),
                        hours_since_last
                    );

                    return TrustLevel::from(decayed_level as u8);
                }
            }
        }

        current_trust
    }

    /// Calculate contextual risk factors
    fn calculate_contextual_risks(&self, context: &TrustContext) -> HashMap<String, f64> {
        let mut risks = HashMap::new();

        // Location risk
        if let Some(location_risk) = self
            .risk_factors
            .location_risks
            .get(&context.location.network_segment)
        {
            risks.insert("location".to_string(), *location_risk);
        }

        // Device risk
        let device_key = format!("{:?}", context.device_info.device_type);
        if let Some(device_risk) = self.risk_factors.device_risks.get(&device_key) {
            risks.insert("device".to_string(), *device_risk);
        }

        // Time risk
        let time_key = format!(
            "{:?}-{:?}",
            context.environmental_factors.time_of_day, context.environmental_factors.day_of_week
        );
        if let Some(time_risk) = self.risk_factors.time_risks.get(&time_key) {
            risks.insert("time".to_string(), *time_risk);
        }

        // Behavioral risk
        let behavioral_risk = 1.0 - context.behavioral_score;
        risks.insert("behavioral".to_string(), behavioral_risk);

        // Environmental risk
        let env_risk = match context.environmental_factors.current_threat_level {
            super::ThreatLevel::Low => 0.1,
            super::ThreatLevel::Medium => 0.3,
            super::ThreatLevel::High => 0.6,
            super::ThreatLevel::Critical => 0.9,
        };
        risks.insert("environmental".to_string(), env_risk);

        debug!(
            "🎯 Contextual risks calculated for {}: {:?}",
            context.peer_id.to_string(),
            risks
        );
        risks
    }

    /// Calculate final trust level
    fn calculate_final_trust(
        &self,
        base_trust: TrustLevel,
        behavioral_score: &BehavioralScore,
        contextual_risks: &HashMap<String, f64>,
        context: &TrustContext,
    ) -> TrustLevel {
        let base_level = base_trust as u8;

        // Behavioral adjustment
        let behavioral_adjustment = (behavioral_score.consistency_score * 2.0) as i8;

        // Contextual risk adjustment
        let avg_contextual_risk: f64 =
            contextual_risks.values().sum::<f64>() / contextual_risks.len() as f64;
        let risk_adjustment = -(avg_contextual_risk * 3.0) as i8;

        // Historical trust adjustment
        let historical_adjustment = if context.historical_trust.successful_interactions > 0 {
            let success_rate = context.historical_trust.successful_interactions as f64
                / context.historical_trust.total_interactions as f64;
            (success_rate * 2.0) as i8
        } else {
            -1 // No history, slight penalty
        };

        let final_level =
            base_level as i8 + behavioral_adjustment + risk_adjustment + historical_adjustment;
        let clamped_level = final_level.clamp(0, 6) as u8;

        debug!("🎯 Trust calculation for {}: base={}, behavioral={}, risk={}, historical={}, final={:?}",
               context.peer_id.to_string(), base_level, behavioral_adjustment, risk_adjustment, historical_adjustment, 
               TrustLevel::from(clamped_level));

        TrustLevel::from(clamped_level)
    }

    /// Generate contextual factors for result
    fn generate_contextual_factors(
        &self,
        behavioral_score: &BehavioralScore,
        contextual_risks: &HashMap<String, f64>,
        context: &TrustContext,
    ) -> Vec<ContextualFactor> {
        let mut factors = Vec::new();

        // Behavioral factors
        factors.push(ContextualFactor {
            factor_type: "behavioral_consistency".to_string(),
            value: serde_json::json!(behavioral_score.consistency_score),
            impact_on_trust: behavioral_score.consistency_score,
            confidence: behavioral_score.confidence,
        });

        // Contextual risk factors
        for (risk_type, risk_value) in contextual_risks {
            factors.push(ContextualFactor {
                factor_type: format!("risk_{}", risk_type),
                value: serde_json::json!(risk_value),
                impact_on_trust: 1.0 - risk_value,
                confidence: 0.8,
            });
        }

        // Historical factors
        let interaction_ratio = if context.historical_trust.total_interactions > 0 {
            context.historical_trust.successful_interactions as f64
                / context.historical_trust.total_interactions as f64
        } else {
            0.0
        };

        factors.push(ContextualFactor {
            factor_type: "historical_success_rate".to_string(),
            value: serde_json::json!(interaction_ratio),
            impact_on_trust: interaction_ratio,
            confidence: 0.9,
        });

        factors
    }

    /// Calculate confidence score
    fn calculate_confidence_score(
        &self,
        behavioral_score: &BehavioralScore,
        contextual_factors: &[ContextualFactor],
    ) -> f64 {
        let behavioral_confidence = behavioral_score.confidence;
        let contextual_confidence: f64 =
            contextual_factors.iter().map(|f| f.confidence).sum::<f64>()
                / contextual_factors.len() as f64;

        (behavioral_confidence * 0.6 + contextual_confidence * 0.4).min(1.0)
    }

    /// Calculate risk score
    fn calculate_risk_score(
        &self,
        behavioral_score: &BehavioralScore,
        contextual_risks: &HashMap<String, f64>,
    ) -> f64 {
        let behavioral_risk = behavioral_score.risk_score;
        let contextual_risk: f64 =
            contextual_risks.values().sum::<f64>() / contextual_risks.len() as f64;

        (behavioral_risk * 0.4 + contextual_risk * 0.6).min(1.0)
    }

    /// Generate security recommendations
    fn generate_recommendations(
        &self,
        trust_level: TrustLevel,
        confidence_score: f64,
        risk_score: f64,
        _contextual_factors: &[ContextualFactor],
    ) -> Vec<SecurityAction> {
        let mut actions = Vec::new();

        // Trust level based recommendations
        match trust_level {
            TrustLevel::Unknown | TrustLevel::Suspicious => {
                actions.push(SecurityAction::BlockAccess);
                actions.push(SecurityAction::RequireMFA);
                actions.push(SecurityAction::SendAlert);
            }
            TrustLevel::Untrusted => {
                actions.push(SecurityAction::RequireMFA);
                actions.push(SecurityAction::LimitAccess);
                actions.push(SecurityAction::IncreaseMonitoring);
            }
            TrustLevel::PartiallyTrusted => {
                actions.push(SecurityAction::LimitAccess);
                actions.push(SecurityAction::IncreaseMonitoring);
            }
            TrustLevel::Trusted => {
                // Standard access, no additional actions
            }
            TrustLevel::HighlyTrusted | TrustLevel::AlphaTrusted => {
                // Elevated access, maintain monitoring
                actions.push(SecurityAction::IncreaseMonitoring);
            }
        }

        // Confidence based recommendations
        if confidence_score < 0.5 {
            actions.push(SecurityAction::RequireMFA);
        }

        // Risk based recommendations
        if risk_score > 0.7 {
            actions.push(SecurityAction::IncreaseMonitoring);
            actions.push(SecurityAction::SendAlert);
        }

        if risk_score > 0.9 {
            actions.push(SecurityAction::BlockAccess);
        }

        actions
    }

    /// Calculate trust change from interaction
    fn calculate_trust_change(
        &self,
        current_trust: &TrustLevel,
        interaction: &Interaction,
    ) -> TrustLevel {
        let current_level = *current_trust as i8;
        let change = match interaction.interaction_type {
            InteractionType::Successful => self.decay_config.positive_interaction_boost as i8,
            InteractionType::Failed => -(self.decay_config.negative_interaction_penalty as i8),
            InteractionType::Suspicious => -2,
            InteractionType::Malicious => -3,
        };

        let new_level = (current_level + change).clamp(0, 6);
        TrustLevel::from(new_level as u8)
    }

    /// Calculate interaction risk
    fn calculate_interaction_risk(&self, interaction: &Interaction) -> f64 {
        match interaction.interaction_type {
            InteractionType::Successful => 0.1,
            InteractionType::Failed => 0.4,
            InteractionType::Suspicious => 0.7,
            InteractionType::Malicious => 0.9,
        }
    }
}

/// Interaction type for trust updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    pub interaction_type: InteractionType,
    pub timestamp: DateTime<Utc>,
    pub context: String,
    pub severity: InteractionSeverity,
}

/// Types of interactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InteractionType {
    Successful,
    Failed,
    Suspicious,
    Malicious,
}

/// Interaction severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InteractionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl WolfBehaviorAnalyzer {
    /// Create new behavior analyzer
    pub fn new() -> Self {
        Self {
            normal_patterns: HashMap::new(),
            anomaly_thresholds: AnomalyThresholds::default(),
            learning_rate: 0.1,
        }
    }

    /// Analyze behavior for a peer
    pub async fn analyze_behavior(&self, context: &TrustContext) -> Result<BehavioralScore> {
        debug!("🧠 Analyzing behavior for peer: {}", context.peer_id.to_string());

        let pattern = self.normal_patterns.get(&context.peer_id);

        let (consistency, predictability) = if let Some(established_pattern) = pattern {
            self.calculate_pattern_deviations(context, established_pattern)
        } else {
            // No established pattern, use defaults
            (0.5, 0.5)
        };

        let overall_score = (consistency + predictability) / 2.0;
        let risk_score = 1.0 - overall_score;

        Ok(BehavioralScore {
            overall_score,
            consistency_score: consistency,
            predictability_score: predictability,
            risk_score,
            confidence: 0.8,
        })
    }

    /// Update behavioral patterns
    pub async fn update_patterns(
        &mut self,
        peer_id: &PeerId,
        _interaction: &Interaction,
    ) -> Result<()> {
        // This would update the behavioral patterns based on interactions
        // For now, we'll just log the update
        debug!("📊 Updating behavioral patterns for {}", peer_id.to_string());
        Ok(())
    }

    /// Calculate pattern deviations
    fn calculate_pattern_deviations(
        &self,
        context: &TrustContext,
        pattern: &BehavioralPattern,
    ) -> (f64, f64) {
        let mut consistency_points = 0.0;
        let mut total_points = 0.0;

        // Check location consistency
        total_points += 1.0;
        if pattern
            .typical_locations
            .contains(&context.location.network_segment)
        {
            consistency_points += 1.0;
        }

        // Check device consistency
        total_points += 1.0;
        let device_id = &context.device_info.device_id;
        if pattern.typical_devices.contains(device_id) {
            consistency_points += 1.0;
        }

        // Check time window consistency
        total_points += 1.0;
        let current_hour = context.timestamp.hour() as u8;
        let _current_day = context.timestamp.weekday();

        let is_time_consistent = pattern.typical_time_windows.iter().any(|window| {
            // Simplified check: just hour range
            current_hour >= window.start_hour && current_hour <= window.end_hour
        });

        if is_time_consistent {
            consistency_points += 1.0;
        }

        let consistency = if total_points > 0.0 {
            consistency_points / total_points
        } else {
            0.5
        };

        // Predictability: how close strictly we follow patterns.
        // For now, we correlate it with consistency but dampen it.
        let predictability = (consistency * 0.9_f64).min(1.0);

        (consistency, predictability)
    }
}

// Default implementations
impl Default for TrustDecayConfig {
    fn default() -> Self {
        Self {
            hourly_decay_rate: 0.01,
            minimum_trust_level: TrustLevel::Unknown,
            positive_interaction_boost: 0.5,
            negative_interaction_penalty: 1.0,
        }
    }
}

impl Default for RiskFactors {
    fn default() -> Self {
        let mut location_risks = HashMap::new();
        location_risks.insert("internal".to_string(), 0.1);
        location_risks.insert("dmz".to_string(), 0.4);
        location_risks.insert("external".to_string(), 0.8);

        let mut device_risks = HashMap::new();
        device_risks.insert("Alpha".to_string(), 0.1);
        device_risks.insert("Beta".to_string(), 0.2);
        device_risks.insert("Gamma".to_string(), 0.5);
        device_risks.insert("Delta".to_string(), 0.7);
        device_risks.insert("Omega".to_string(), 0.9);

        Self {
            location_risks,
            device_risks,
            time_risks: HashMap::new(),
            behavioral_risks: HashMap::new(),
            environmental_risks: HashMap::new(),
        }
    }
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            location_deviation_threshold: 0.3,
            time_deviation_threshold: 0.4,
            behavior_deviation_threshold: 0.5,
            resource_usage_threshold: 0.6,
            communication_deviation_threshold: 0.4,
        }
    }
}

// Conversion from u8 to TrustLevel
impl From<u8> for TrustLevel {
    fn from(value: u8) -> Self {
        match value {
            0 => TrustLevel::Unknown,
            1 => TrustLevel::Suspicious,
            2 => TrustLevel::Untrusted,
            3 => TrustLevel::PartiallyTrusted,
            4 => TrustLevel::Trusted,
            5 => TrustLevel::HighlyTrusted,
            6 => TrustLevel::AlphaTrusted,
            _ => TrustLevel::Unknown,
        }
    }
}

/// Trust Analytics Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnalytics {
    pub average_trust_score: f64,
    pub total_peers_tracked: usize,
    pub untrusted_peers_count: usize,
    pub highly_trusted_peers_count: usize,
    pub trust_distribution: HashMap<String, usize>,
}

impl WolfTrustEngine {
    /// Get real-time trust analytics
    pub fn get_analytics(&self) -> TrustAnalytics {
        let total = self.trust_levels.len();
        let mut distribution = HashMap::new();
        let mut untrusted = 0;
        let mut highly_trusted = 0;

        for level in self.trust_levels.values() {
            let key = format!("{:?}", level);
            *distribution.entry(key).or_insert(0) += 1;

            // Assuming TrustLevel variants order: Unknown, Suspicious, Untrusted, PartiallyTrusted, Trusted, HighlyTrusted, AlphaTrusted
            if *level == TrustLevel::Untrusted || *level == TrustLevel::Suspicious {
                untrusted += 1;
            }
            if *level >= TrustLevel::Trusted {
                highly_trusted += 1;
            }
        }

        // Calculate average trust (mapping enum to u8)
        let sum: u64 = self.trust_levels.values().map(|l| *l as u64).sum();
        let avg = if total > 0 {
            sum as f64 / total as f64
        } else {
            0.0
        };

        TrustAnalytics {
            average_trust_score: avg,
            total_peers_tracked: total,
            untrusted_peers_count: untrusted,
            highly_trusted_peers_count: highly_trusted,
            trust_distribution: distribution,
        }
    }
}
