//! Wolf Trust Engine
//!
//! Implements sophisticated trust evaluation algorithms with wolf pack behavioral patterns.
//! Wolves constantly evaluate trust levels of pack members and outsiders.

use anyhow::Result;
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

use super::{ContextualFactor, SecurityAction, TrustContext, TrustEvaluationResult, TrustLevel};
use libp2p::PeerId; // Use libp2p's PeerId directly

/// Behavioral trust evaluation engine that applies wolf pack patterns to peer interactions
pub struct WolfTrustEngine {
    /// Mapping of peer identities to their current trust tier
    trust_levels: HashMap<PeerId, TrustLevel>,
    /// Historical interaction logs used for trend analysis and trust decay
    trust_history: HashMap<PeerId, Vec<TrustSnapshot>>,
    /// Active engine for analyzing real-time behavioral anomalies
    behavior_analyzer: WolfBehaviorAnalyzer,
    /// Settings for how trust diminishes over time without interaction
    decay_config: TrustDecayConfig,
    /// weighted factors influencing the risk probability
    risk_factors: RiskFactors,
}

/// Point-in-time record of a trust evaluation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSnapshot {
    /// When the evaluation occurred
    pub timestamp: DateTime<Utc>,
    /// The trust tier assigned at this moment
    pub trust_level: TrustLevel,
    /// Statistical certainty of the evaluation
    pub confidence_score: f64,
    /// Calculated probability of threat at this moment
    pub risk_score: f64,
    /// Key contextual signals that influenced the result
    pub context_factors: Vec<String>,
    /// Narrative justifying the evaluation outcome
    pub evaluation_reason: String,
}

/// Specialized analyzer for detecting deviations from expected peer behavior
pub struct WolfBehaviorAnalyzer {
    /// Baselined behavioral patterns for known peers
    normal_patterns: HashMap<PeerId, BehavioralPattern>,
    /// Sensitivity limits for various behavioral dimensions
    #[allow(dead_code)]
    anomaly_thresholds: AnomalyThresholds,
    /// Speed at which the analyzer adapts to legitimate behavioral changes
    #[allow(dead_code)]
    learning_rate: f64,
}

/// baseline Behavioral profile for a specific peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    /// The peer identity this pattern describes
    pub peer_id: PeerId,
    /// Average number of requests or interactions per time unit
    pub access_frequency: f64,
    /// Historical network segments or geographic origins
    pub typical_locations: Vec<String>,
    /// Historical hardware identifiers used by this peer
    pub typical_devices: Vec<String>,
    /// Chronological windows where most interactions occur
    pub typical_time_windows: Vec<TimeWindow>,
    /// Signatures of typical network communication (metadata)
    pub communication_patterns: CommunicationPattern,
    /// Typical infrastructure consumption metrics
    pub resource_usage: ResourceUsagePattern,
    /// When the pattern was last recalculated
    pub last_updated: DateTime<Utc>,
}

/// specific Chronological window for expected behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Beginning of the window (0-23)
    pub start_hour: u8,
    /// End of the window (0-23)
    pub end_hour: u8,
    /// Categorization of the day (Weekday, Weekend, etc.)
    pub day_type: DayType,
    /// Mathematical confidence that this window is typical
    pub confidence: f64,
}

/// Categorization of days for behavioral analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DayType {
    /// A standard working day (Monday through Friday).
    Weekday,
    /// A weekend day (Saturday or Sunday).
    Weekend,
    /// A recognized holiday.
    Holiday,
}

/// Network communication signature and frequency analysis for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationPattern {
    /// Baseline rolling average of message volume per unit of time
    pub average_message_frequency: f64,
    /// Statistical distribution of typical payload sizes
    pub typical_message_sizes: Vec<f64>,
    /// Most frequently utilized network protocols by this peer
    pub preferred_protocols: Vec<String>,
    /// Identities of peers frequently interacted with
    pub communication_partners: Vec<PeerId>,
}

/// Infrastructure consumption profile and resource demand for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsagePattern {
    /// Normalized average of CPU cycles consumed
    pub cpu_usage_average: f64,
    /// Normalized average of memory allocation
    pub memory_usage_average: f64,
    /// Normalized average of network bandwidth utilization
    pub network_usage_average: f64,
    /// Signature of common storage access patterns (path depth, frequency)
    pub storage_access_patterns: Vec<String>,
}

/// Configuration for anomaly detection sensitivity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyThresholds {
    /// Limit for deviation from expected locations
    pub location_deviation_threshold: f64,
    /// Limit for deviation from expected time windows
    pub time_deviation_threshold: f64,
    /// Limit for general behavioral pattern deviation
    pub behavior_deviation_threshold: f64,
    /// Limit for abnormal resource consumption spikes
    pub resource_usage_threshold: f64,
    /// Limit for abnormal communication frequency or volume
    pub communication_deviation_threshold: f64,
}

/// Configuration rules for trust temporal decay and interaction bonuses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDecayConfig {
    /// Percentage reduction in trust per hour of inactivity (0.0 to 1.0)
    pub hourly_decay_rate: f64,
    /// The floor for trust decay before requiring manual re-verification
    pub minimum_trust_level: TrustLevel,
    /// Trust tier adjustment added after a verified positive interaction
    pub positive_interaction_boost: f64,
    /// Trust tier adjustment subtracted after a verified negative interaction
    pub negative_interaction_penalty: f64,
}

/// Aggregated risk parameters used in probability calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactors {
    /// Probability adjustments based on geographic and network location
    pub location_risks: HashMap<String, f64>,
    /// Probability adjustments based on hardware and software profile
    pub device_risks: HashMap<String, f64>,
    /// Probability adjustments based on temporal constraints
    pub time_risks: HashMap<String, f64>,
    /// Probability adjustments based on behavioral deviations
    pub behavioral_risks: HashMap<String, f64>,
    /// Probability adjustments based on global threat telemetry
    pub environmental_risks: HashMap<String, f64>,
}

/// Comprehensive outcome of a behavioral analysis event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralScore {
    /// The final normalized behavioral score (0-1.0)
    pub overall_score: f64,
    /// Score representing how well current actions match established patterns
    pub consistency_score: f64,
    /// Score representing how easily current behavior could be forecasted
    pub predictability_score: f64,
    /// Probability that the current behavior indicates a threat
    pub risk_score: f64,
    /// Statistical certainty of the analysis
    pub confidence: f64,
}

impl WolfTrustEngine {
    /// Initializes a new WolfTrustEngine with default decay and risk settings.
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

    /// Initializes all internal components of the trust engine.
    ///
    /// # Errors
    /// Returns an error if sub-component initialization fails.
    pub async fn initialize(&mut self) -> Result<()> {
        info!("🐺 Trust Engine initialized");
        Ok(())
    }

    /// Triggers a re-evaluation of all tracked peers to apply trust decay.
    ///
    /// # Errors
    /// Returns an error if the re-evaluation process fails for any peer.
    pub async fn periodic_reevaluation(&mut self) -> Result<()> {
        // Placeholder for periodic re-evaluation logic
        // This would iterate through all peers and apply decay,
        // or trigger a full re-evaluation based on current context.
        info!("🐺 Performing periodic re-evaluation of all peers.");
        // Example: Apply decay to all peers
        let peer_ids: Vec<PeerId> = self.trust_levels.keys().cloned().collect();
        for peer_id in peer_ids {
            let current_trust = self
                .trust_levels
                .get(&peer_id)
                .cloned()
                .unwrap_or(TrustLevel::Unknown);
            let decayed_trust = self.apply_trust_decay(&peer_id, current_trust);
            self.trust_levels.insert(peer_id, decayed_trust);
        }
        Ok(())
    }

    /// Calculates the baseline trust evaluation for a peer using the provided context.
    ///
    /// # Errors
    /// Returns an error if behavioral analysis or risk calculation fails.
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

    /// Calculates the trust level for a specific peer based on their history and current context.
    ///
    /// # Errors
    /// Returns an error if the peer's trust cannot be calculated.
    pub fn calculate_peer_trust(
        &self,
        peer_id: &PeerId,
        _context: &TrustContext,
    ) -> Result<TrustLevel> {
        // In a real async application, you'd await evaluate_base_trust.
        // For this synchronous method, we'll simulate or block if necessary.
        // For now, we'll just return the current trust level if available.
        Ok(self
            .trust_levels
            .get(peer_id)
            .cloned()
            .unwrap_or(TrustLevel::Unknown))
    }

    /// Updates a peer's trust tier and behavioral history based on a recent event.
    ///
    /// # Errors
    /// Returns an error if behavioral analysis or history update fails.
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

    /// Informs the engine of a security action taken (e.g., lockdown) for a peer.
    ///
    /// # Errors
    /// Returns an error if recording the action fails.
    pub async fn record_security_action(
        &mut self,
        peer_id: &PeerId,
        action: &SecurityAction,
    ) -> Result<()> {
        debug!(
            "🚨 Recording security action {:?} for peer: {}",
            action,
            peer_id.to_string()
        );
        // This method would typically update the peer's trust level or history
        // based on the security action taken. For example, a BlockAccess action
        // might immediately set trust to Untrusted or Suspicious.
        match action {
            SecurityAction::BlockAccess => {
                self.trust_levels
                    .insert(peer_id.clone(), TrustLevel::Suspicious);
                // Also record a snapshot for this significant event
                let snapshot = TrustSnapshot {
                    timestamp: Utc::now(),
                    trust_level: TrustLevel::Suspicious,
                    confidence_score: 1.0,
                    risk_score: 1.0,
                    context_factors: vec![format!("SecurityAction: {:?}", action)],
                    evaluation_reason: format!("Security action {:?} taken", action),
                };
                self.trust_history
                    .entry(peer_id.clone())
                    .or_insert_with(Vec::new)
                    .push(snapshot);
            }
            _ => { /* Other actions might have different impacts */ }
        }
        Ok(())
    }

    /// Retrieves the ordered set of trust snapshots recorded for a peer.
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

    /// Applies a penalty to the trust level.
    ///
    /// # Arguments
    /// * `current` - The current `TrustLevel`.
    /// * `penalty` - The amount of penalty to apply (e.g., 0.1 for 10% reduction).
    ///
    /// # Returns
    /// The new `TrustLevel` after applying the penalty.
    pub fn penalty_level(current: &TrustLevel, penalty: f64) -> TrustLevel {
        let current_value = *current as u8 as f64;
        let new_value = (current_value - (current_value * penalty)).max(0.0);
        TrustLevel::from(new_value.round() as u8)
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

    /// Calculates the overall risk score based on contextual factors.
    ///
    /// # Arguments
    /// * `factors` - A slice of `ContextualFactor` to consider for risk calculation.
    ///
    /// # Returns
    /// A `f64` representing the aggregated risk score (0.0 to 1.0).
    pub fn calculate_contextual_risk(&self, factors: &[ContextualFactor]) -> f64 {
        if factors.is_empty() {
            return 0.0;
        }
        let total_risk: f64 = factors.iter().map(|f| f.impact_on_trust).sum();
        total_risk / factors.len() as f64
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

    /// Records a point-in-time snapshot of a peer's trust level.
    /// This is useful for auditing and historical analysis.
    ///
    /// # Arguments
    /// * `peer_id` - The `PeerId` of the peer.
    /// * `trust_level` - The `TrustLevel` at the time of the snapshot.
    /// * `confidence` - The confidence score of the evaluation.
    /// * `risk` - The risk score associated with the evaluation.
    /// * `reason` - A string explaining the reason for this snapshot.
    pub fn record_snapshot(
        &mut self,
        peer_id: PeerId,
        trust_level: TrustLevel,
        confidence: f64,
        risk: f64,
        reason: String,
    ) {
        let snapshot = TrustSnapshot {
            timestamp: Utc::now(),
            trust_level,
            confidence_score: confidence,
            risk_score: risk,
            context_factors: vec![], // Can be populated if needed
            evaluation_reason: reason,
        };
        self.trust_history
            .entry(peer_id)
            .or_insert_with(Vec::new)
            .push(snapshot);
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

    /// Maps a raw trust score (0-1.0) to a discrete `TrustLevel`.
    ///
    /// # Arguments
    /// * `score` - The raw trust score.
    ///
    /// # Returns
    /// The corresponding `TrustLevel`.
    pub fn score_to_level(&self, score: f64) -> TrustLevel {
        match score {
            s if s >= 0.9 => TrustLevel::AlphaTrusted,
            s if s >= 0.7 => TrustLevel::HighlyTrusted,
            s if s >= 0.5 => TrustLevel::Trusted,
            s if s >= 0.3 => TrustLevel::PartiallyTrusted,
            s if s >= 0.1 => TrustLevel::Untrusted,
            _ => TrustLevel::Suspicious, // Scores below 0.1 or negative
        }
    }

    /// Calculates trust decay for a peer based on elapsed time since last interaction.
    ///
    /// # Arguments
    /// * `current_level` - The peer's current `TrustLevel`.
    /// * `last_activity` - The `DateTime<Utc>` of the peer's last recorded activity.
    ///
    /// # Returns
    /// A `f64` representing the total decay amount that should be applied.
    pub fn calculate_decay(
        &self,
        _current_level: &TrustLevel,
        last_activity: DateTime<Utc>,
    ) -> f64 {
        let hours_since_last = (Utc::now() - last_activity).num_hours() as f64;
        if hours_since_last > 0.0 {
            hours_since_last * self.decay_config.hourly_decay_rate
        } else {
            0.0
        }
    }

    /// Adjusts trust scores based on environmental or collective signals.
    ///
    /// # Errors
    /// Returns an error if the adjustment process encounters an issue.
    pub fn apply_collective_signals(&mut self, signals: &HashMap<String, f64>) -> Result<()> {
        info!("Applying collective signals: {:?}", signals);
        // This method would iterate through all peers or specific peers
        // and adjust their trust levels based on the provided signals.
        // For example, a high "global_threat_level" signal might reduce
        // the trust of all peers by a small margin.
        if let Some(global_threat_level) = signals.get("global_threat_level") {
            let penalty_factor = *global_threat_level * 0.05; // Example: 5% penalty per unit of threat
            for (peer_id, trust_level) in self.trust_levels.iter_mut() {
                let new_level = Self::penalty_level(trust_level, penalty_factor);
                *trust_level = new_level;
                debug!(
                    "Adjusted trust for {} due to global threat: {:?}",
                    peer_id.to_string(),
                    new_level
                );
            }
        }
        Ok(())
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

/// Detailed data about a single interaction event between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interaction {
    /// The classification of the interaction (Successful, Failed, etc.).
    pub interaction_type: InteractionType,
    /// Timestamp when the interaction took place.
    pub timestamp: DateTime<Utc>,
    /// Narrative or metadata providing further context.
    pub context: String,
    /// The severity of the interaction from a security perspective.
    pub severity: InteractionSeverity,
}

/// binary classification of a network or system interaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InteractionType {
    /// Interaction reached its intended logical conclusion without error
    Successful,
    /// Interaction was terminated or failed due to system or protocol error
    Failed,
    /// Interaction characteristics deviate from established normal patterns
    Suspicious,
    /// Interaction is confirmed to be part of a malicious activity chain
    Malicious,
}

/// impact of an interaction on the security posture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InteractionSeverity {
    /// Minimal impact, part of normal operational noise
    Low,
    /// Noteworthy interaction requiring logging but no immediate action
    Medium,
    /// High-risk interaction that may suggest an active threat
    High,
    /// confirmed breach or severe threat requiring immediate orchestration response
    Critical,
}

impl WolfBehaviorAnalyzer {
    /// Initializes a new behavior analyzer with empty patterns.
    pub fn new() -> Self {
        Self {
            normal_patterns: HashMap::new(),
            anomaly_thresholds: AnomalyThresholds::default(),
            learning_rate: 0.1,
        }
    }

    /// Compares the current context against baselined patterns to derive a behavioral score.
    ///
    /// # Errors
    /// Returns an error if the deviation calculation fails.
    pub async fn analyze_behavior(&self, context: &TrustContext) -> Result<BehavioralScore> {
        debug!(
            "🧠 Analyzing behavior for peer: {}",
            context.peer_id.to_string()
        );

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

    /// Integrates new interaction metadata into a peer's behavioral baseline.
    ///
    /// # Errors
    /// Returns an error if the pattern update fails.
    pub async fn update_patterns(
        &mut self,
        peer_id: &PeerId,
        _interaction: &Interaction,
    ) -> Result<()> {
        // This would update the behavioral patterns based on interactions
        // For now, we'll just log the update
        debug!(
            "📊 Updating behavioral patterns for {}",
            peer_id.to_string()
        );
        Ok(())
    }

    /// Calculates deviations from established behavioral patterns.
    ///
    /// # Arguments
    /// * `context` - The current `TrustContext`.
    /// * `pattern` - The `BehavioralPattern` to compare against.
    ///
    /// # Returns
    /// A tuple of `(consistency_score, predictability_score)`.
    pub fn calculate_pattern_deviations(
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

/// snapshot Summary of global trust metrics across the ecosystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnalytics {
    /// rolling Average trust score for all tracked peers
    pub average_trust_score: f64,
    /// Total number of unique identities in the trust registry
    pub total_peers_tracked: usize,
    /// Count of peers currently assigned to Untrusted or Suspicious tiers
    pub untrusted_peers_count: usize,
    /// Count of peers currently assigned to Trusted or higher tiers
    pub highly_trusted_peers_count: usize,
    /// Frequency mapping of peers across all trust tiers
    pub trust_distribution: HashMap<String, usize>,
}

impl WolfTrustEngine {
    /// Calculates and returns an aggregate snapshot of the trust registry.
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
