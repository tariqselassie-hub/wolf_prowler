//! Wolf Policy Engine
//!
//! Implements policy enforcement with wolf pack governance patterns.
//! Alpha wolves enforce pack rules and maintain order.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::{
    AdaptiveControl, ContextualRequirement, PolicyEvaluationResult, SecurityAction, TrustContext,
    TrustLevel, ZeroTrustPolicy,
};
use libp2p::PeerId;

/// Governance and enforcement engine for Zero Trust security policies.
///
/// Responsible for registering, evaluating, and tracking policy enforcement across the pack.
pub struct WolfPolicyEngine {
    /// Active policy registry indexed by unique identifier
    policies: HashMap<String, ZeroTrustPolicy>,
    /// Pre-defined policy blueprints for rapid deployment
    policy_templates: HashMap<String, ZeroTrustPolicy>,
    /// Temporary storage for evaluation results to optimize performance
    evaluation_cache: HashMap<String, CachedEvaluation>,
    /// Chronological record of policy breaches per peer identity
    violations: HashMap<PeerId, Vec<PolicyViolation>>,
    /// Aggregate telemetry regarding policy enforcement performance
    statistics: PolicyStatistics,
}

/// entry for a previously finalized policy assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEvaluation {
    /// The outcome of the policy check
    pub result: PolicyEvaluationResult,
    /// When the assessment was recorded
    pub timestamp: DateTime<Utc>,
    /// When this entry should be invalidated
    pub expires_at: DateTime<Utc>,
}

/// Record of a failed policy requirement or unauthorized attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Unique identifier for the specific breach event
    pub violation_id: String,
    /// Identifier of the policy that was breached
    pub policy_id: String,
    /// Identity of the peer responsible for the breach
    pub peer_id: PeerId,
    /// Classification of the failure (Trust, Context, etc.)
    pub violation_type: ViolationType,
    /// Criticality of the breach event
    pub severity: ViolationSeverity,
    /// Narrative detailing the failure circumstances
    pub description: String,
    /// Point in time when the failure was detected
    pub detected_at: DateTime<Utc>,
    /// True if remediation actions have finalized the event
    pub resolved: bool,
    /// Notes regarding the investigation or remediation
    pub resolution_notes: Option<String>,
}

/// Types of policy violations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    /// The subject's trust level was below the required threshold.
    TrustLevelInsufficient,
    /// A specific contextual requirement (e.g., location, time) was not met.
    ContextualRequirementFailed,
    /// An adaptive control mechanism (e.g., rate limiting) was triggered.
    AdaptiveControlTriggered,
    /// The policy used for evaluation has expired.
    PolicyExpired,
    /// An attempt was made to access a resource without proper authorization.
    UnauthorizedAccess,
    /// Behavior was detected that deviates significantly from established baselines.
    SuspiciousBehavior,
}

/// Severity levels for policy violations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Minor violation with low security impact.
    Low,
    /// Moderate violation that should be investigated.
    Medium,
    /// Significant violation requiring prompt response.
    High,
    /// Severe violation requiring immediate intervention.
    Critical,
}

/// Comprehensive telemetry for the policy enforcement subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatistics {
    /// Global count of policy assessment events
    pub total_evaluations: u64,
    /// Global count of recorded breaches
    pub policy_violations: u64,
    /// Count of assessment events that resulted in positive enforcement
    pub policies_enforced: u64,
    /// Mean latency for policy assessment operations in milliseconds
    pub average_evaluation_time_ms: f64,
    /// Ranking of policy IDs by violation frequency
    pub most_violated_policies: Vec<String>,
    /// Temporal trends of violation occurrences across time buckets
    pub violation_trends: ViolationTrends,
}

/// Statistical trends of policy violations over different time buckets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationTrends {
    /// Number of violations in the last hour.
    pub last_hour: u64,
    /// Number of violations in the last 24 hours.
    pub last_day: u64,
    /// Number of violations in the last 7 days.
    pub last_week: u64,
    /// Number of violations in the last 30 days.
    pub last_month: u64,
}

impl WolfPolicyEngine {
    /// Initializes a new `WolfPolicyEngine` and loads default policy templates.
    ///
    /// # Errors
    /// Returns an error if template loading fails.
    pub fn new() -> Result<Self> {
        info!("🐺 Initializing Wolf Policy Engine");

        let mut engine = Self {
            policies: HashMap::new(),
            policy_templates: HashMap::new(),
            evaluation_cache: HashMap::new(),
            violations: HashMap::new(),
            statistics: PolicyStatistics::default(),
        };

        // Load default policy templates
        engine.load_default_templates()?;

        info!("✅ Wolf Policy Engine initialized successfully");
        Ok(engine)
    }

    /// Loads default policy templates into the engine.
    ///
    /// These templates provide a baseline for security governance (Alpha, Beta, Standard, Guest).
    ///
    /// # Errors
    /// Returns an error if a template definition is invalid.
    fn load_default_templates(&mut self) -> Result<()> {
        debug!("📋 Loading default policy templates");

        // Alpha Access Policy - Highest privilege
        let alpha_policy = ZeroTrustPolicy {
            id: "alpha_access".to_string(),
            name: "Alpha Wolf Access Policy".to_string(),
            description: "Maximum privilege access for alpha wolves".to_string(),
            trust_level_required: TrustLevel::AlphaTrusted,
            contextual_requirements: vec![
                ContextualRequirement {
                    requirement_type: super::RequirementType::DeviceType,
                    operator: super::ComparisonOperator::Equals,
                    value: serde_json::json!("Alpha"),
                    weight: 1.0,
                },
                ContextualRequirement {
                    requirement_type: super::RequirementType::SecurityPosture,
                    operator: super::ComparisonOperator::GreaterThan,
                    value: serde_json::json!(0.9),
                    weight: 1.0,
                },
            ],
            adaptive_controls: vec![AdaptiveControl {
                control_type: super::ControlType::Monitoring,
                trigger_conditions: vec![],
                actions: vec![SecurityAction::IncreaseMonitoring],
                is_active: true,
            }],
            exceptions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Beta Access Policy - High privilege
        let beta_policy = ZeroTrustPolicy {
            id: "beta_access".to_string(),
            name: "Beta Wolf Access Policy".to_string(),
            description: "High privilege access for beta wolves".to_string(),
            trust_level_required: TrustLevel::HighlyTrusted,
            contextual_requirements: vec![
                ContextualRequirement {
                    requirement_type: super::RequirementType::DeviceType,
                    operator: super::ComparisonOperator::In,
                    value: serde_json::json!(["Alpha", "Beta"]),
                    weight: 1.0,
                },
                ContextualRequirement {
                    requirement_type: super::RequirementType::BehavioralScore,
                    operator: super::ComparisonOperator::GreaterThanOrEqual,
                    value: serde_json::json!(0.8),
                    weight: 0.8,
                },
            ],
            adaptive_controls: vec![AdaptiveControl {
                control_type: super::ControlType::AccessControl,
                trigger_conditions: vec![],
                actions: vec![SecurityAction::LimitAccess],
                is_active: true,
            }],
            exceptions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Standard Pack Member Policy
        let standard_policy = ZeroTrustPolicy {
            id: "standard_pack_member".to_string(),
            name: "Standard Pack Member Policy".to_string(),
            description: "Standard access for trusted pack members".to_string(),
            trust_level_required: TrustLevel::Trusted,
            contextual_requirements: vec![
                ContextualRequirement {
                    requirement_type: super::RequirementType::HistoricalTrust,
                    operator: super::ComparisonOperator::GreaterThan,
                    value: serde_json::json!(0.7),
                    weight: 0.7,
                },
                ContextualRequirement {
                    requirement_type: super::RequirementType::Location,
                    operator: super::ComparisonOperator::Contains,
                    value: serde_json::json!("internal"),
                    weight: 0.6,
                },
            ],
            adaptive_controls: vec![AdaptiveControl {
                control_type: super::ControlType::Monitoring,
                trigger_conditions: vec![],
                actions: vec![SecurityAction::IncreaseMonitoring],
                is_active: true,
            }],
            exceptions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Guest/Omega Policy - Limited access
        let guest_policy = ZeroTrustPolicy {
            id: "guest_omega".to_string(),
            name: "Guest/Omega Wolf Policy".to_string(),
            description: "Limited access for guests and omega wolves".to_string(),
            trust_level_required: TrustLevel::PartiallyTrusted,
            contextual_requirements: vec![
                ContextualRequirement {
                    requirement_type: super::RequirementType::TimeContext,
                    operator: super::ComparisonOperator::In,
                    value: serde_json::json!(["Normal", "AfterHours"]),
                    weight: 0.5,
                },
                ContextualRequirement {
                    requirement_type: super::RequirementType::NetworkLoad,
                    operator: super::ComparisonOperator::LessThan,
                    value: serde_json::json!("High"),
                    weight: 0.4,
                },
            ],
            adaptive_controls: vec![
                AdaptiveControl {
                    control_type: super::ControlType::RateLimiting,
                    trigger_conditions: vec![],
                    actions: vec![SecurityAction::LimitAccess],
                    is_active: true,
                },
                AdaptiveControl {
                    control_type: super::ControlType::Alerting,
                    trigger_conditions: vec![],
                    actions: vec![SecurityAction::SendAlert],
                    is_active: true,
                },
            ],
            exceptions: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Add templates
        self.policy_templates
            .insert("alpha".to_string(), alpha_policy);
        self.policy_templates
            .insert("beta".to_string(), beta_policy);
        self.policy_templates
            .insert("standard".to_string(), standard_policy);
        self.policy_templates
            .insert("guest".to_string(), guest_policy);

        info!(
            "✅ Loaded {} default policy templates",
            self.policy_templates.len()
        );
        Ok(())
    }

    /// Adds a new policy to the active registry.
    ///
    /// # Arguments
    /// * `policy` - The `ZeroTrustPolicy` to add.
    ///
    /// # Errors
    /// Returns an error if the policy identifier already exists or if the policy is invalid.
    pub fn add_policy(&mut self, policy: ZeroTrustPolicy) -> Result<()> {
        info!("📋 Adding policy: {}", policy.name);

        self.policies.insert(policy.id.clone(), policy.clone());

        // Clear cache when policy changes
        self.evaluation_cache.clear();

        info!("✅ Policy added successfully");
        Ok(())
    }

    /// Evaluates all applicable policies for a given trust context and level.
    ///
    /// Coordinates policy matching, violation detection, and adaptive control triggering.
    ///
    /// # Errors
    /// Returns an error if the evaluation process fails to complete.
    pub async fn evaluate_policies(
        &mut self,
        context: &TrustContext,
        trust_level: &TrustLevel,
    ) -> Result<PolicyEvaluationResult> {
        debug!(
            "🔍 Evaluating policies for peer: {}",
            context.peer_id.to_string()
        );

        let start_time = std::time::Instant::now();

        // Check cache first
        let cache_key = format!("{}-{:?}", context.peer_id.to_string(), trust_level);
        if let Some(cached) = self.evaluation_cache.get(&cache_key) {
            if cached.expires_at > Utc::now() {
                debug!("📦 Using cached policy evaluation");
                return Ok(cached.result.clone());
            }
        }

        // Find applicable policies
        let applicable_policies = self.find_applicable_policies(context, trust_level);

        if applicable_policies.is_empty() {
            warn!(
                "⚠️ No applicable policies found for {}",
                context.peer_id.to_string()
            );
            return Ok(PolicyEvaluationResult::default());
        }

        // Evaluate each policy
        let mut applied_policies = Vec::new();
        let mut violations = Vec::new();
        let mut confidence = 1.0;
        let mut risk_score = 0.0;
        let mut required_trust = TrustLevel::Unknown;

        for policy in &applicable_policies {
            debug!("📋 Evaluating policy: {}", policy.name);

            // Check trust level requirement
            if trust_level < &policy.trust_level_required {
                violations.push(PolicyViolation {
                    violation_id: format!("violation-{}-{}", policy.id, uuid::Uuid::new_v4()),
                    policy_id: policy.id.clone(),
                    peer_id: context.peer_id.clone(),
                    violation_type: ViolationType::TrustLevelInsufficient,
                    severity: self
                        .calculate_violation_severity(trust_level, &policy.trust_level_required),
                    description: format!(
                        "Trust level {:?} insufficient for policy requiring {:?}",
                        trust_level, policy.trust_level_required
                    ),
                    detected_at: Utc::now(),
                    resolved: false,
                    resolution_notes: None,
                });

                risk_score += 0.3;
                confidence *= 0.8;
            }

            // Check contextual requirements
            for requirement in &policy.contextual_requirements {
                if !self.evaluate_contextual_requirement(context, requirement) {
                    violations.push(PolicyViolation {
                        violation_id: format!("violation-{}-{}", policy.id, uuid::Uuid::new_v4()),
                        policy_id: policy.id.clone(),
                        peer_id: context.peer_id.clone(),
                        violation_type: ViolationType::ContextualRequirementFailed,
                        severity: ViolationSeverity::Medium,
                        description: format!(
                            "Contextual requirement failed: {:?}",
                            requirement.requirement_type
                        ),
                        detected_at: Utc::now(),
                        resolved: false,
                        resolution_notes: None,
                    });

                    risk_score += 0.2 * (1.0 - requirement.weight);
                    confidence *= 0.9 + requirement.weight * 0.1;
                }
            }

            // Update required trust level
            if policy.trust_level_required > required_trust {
                required_trust = policy.trust_level_required;
            }

            applied_policies.push(policy.name.clone());
        }

        // Check adaptive controls
        let mut recommended_actions = Vec::new();
        for policy in &applicable_policies {
            for control in &policy.adaptive_controls {
                if self.should_trigger_adaptive_control(context, control) {
                    recommended_actions.extend(control.actions.clone());
                }
            }
        }

        // Record violations
        if !violations.is_empty() {
            let peer_violations = self
                .violations
                .entry(context.peer_id.clone())
                .or_insert_with(Vec::new);
            peer_violations.extend(violations.clone());

            // Keep only last 100 violations per peer
            if peer_violations.len() > 100 {
                peer_violations.drain(0..peer_violations.len() - 100);
            }
        }

        // Update statistics
        self.statistics.total_evaluations += 1;
        self.statistics.policy_violations += violations.len() as u64;
        self.statistics.policies_enforced += applied_policies.len() as u64;

        let evaluation_time = start_time.elapsed().as_millis() as f64;
        self.statistics.average_evaluation_time_ms = (self.statistics.average_evaluation_time_ms
            * (self.statistics.total_evaluations - 1) as f64
            + evaluation_time)
            / self.statistics.total_evaluations as f64;

        debug!(
            "🎯 Policy evaluation completed: {} policies applied, {} violations",
            applied_policies.len(),
            violations.len()
        );

        let result = PolicyEvaluationResult {
            required_trust_level: required_trust,
            confidence: confidence.min(1.0),
            risk_score: risk_score.min(1.0),
            recommended_actions,
            applied_policies,
        };

        // Cache result
        let cached = CachedEvaluation {
            result: result.clone(),
            timestamp: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        self.evaluation_cache.insert(cache_key, cached);

        Ok(result)
    }

    /// Finds all policies that are applicable to the given context and trust level.
    ///
    /// # Arguments
    /// * `context` - The `TrustContext` to check against.
    /// * `trust_level` - The subject's `TrustLevel`.
    ///
    /// # Returns
    /// A vector of references to applicable `ZeroTrustPolicy` objects.
    fn find_applicable_policies(
        &self,
        context: &TrustContext,
        trust_level: &TrustLevel,
    ) -> Vec<&ZeroTrustPolicy> {
        let mut applicable = Vec::new();

        for policy in self.policies.values() {
            // Check if trust level meets minimum requirement
            if trust_level >= &policy.trust_level_required {
                // Check for exceptions
                let has_exception = policy.exceptions.iter().any(|e| {
                    e.peer_id == context.peer_id
                        && (e.expires_at.is_none() || e.expires_at.unwrap() > Utc::now())
                });

                if !has_exception {
                    applicable.push(policy);
                }
            }
        }

        // Sort by trust level requirement (highest first)
        applicable.sort_by(|a, b| b.trust_level_required.cmp(&a.trust_level_required));

        applicable
    }

    /// Evaluates a specific contextual requirement.
    ///
    /// # Arguments
    /// * `context` - The `TrustContext` providing current environment data.
    /// * `requirement` - The `ContextualRequirement` to evaluate.
    ///
    /// # Returns
    /// `true` if the requirement is met, `false` otherwise.
    fn evaluate_contextual_requirement(
        &self,
        context: &TrustContext,
        requirement: &ContextualRequirement,
    ) -> bool {
        match requirement.requirement_type {
            super::RequirementType::Location => {
                let location_value = context.location.network_segment.clone();
                self.compare_values(&location_value, &requirement.value, &requirement.operator)
            }
            super::RequirementType::DeviceType => {
                let device_value = format!("{:?}", context.device_info.device_type);
                self.compare_values(&device_value, &requirement.value, &requirement.operator)
            }
            super::RequirementType::BehavioralScore => {
                let score_value = context.behavioral_score;
                self.compare_values(&score_value, &requirement.value, &requirement.operator)
            }
            super::RequirementType::HistoricalTrust => {
                let trust_ratio = if context.historical_trust.total_interactions > 0 {
                    context.historical_trust.successful_interactions as f64
                        / context.historical_trust.total_interactions as f64
                } else {
                    0.0
                };
                self.compare_values(&trust_ratio, &requirement.value, &requirement.operator)
            }
            super::RequirementType::TimeContext => {
                let time_value = format!("{:?}", context.environmental_factors.time_of_day);
                self.compare_values(&time_value, &requirement.value, &requirement.operator)
            }
            super::RequirementType::ThreatLevel => {
                let threat_value =
                    format!("{:?}", context.environmental_factors.current_threat_level);
                self.compare_values(&threat_value, &requirement.value, &requirement.operator)
            }
            // Add more requirement types as needed
            _ => true, // Default to allowing unknown requirements
        }
    }

    /// Compares an actual value against an expected value using a specified operator.
    ///
    /// # Arguments
    /// * `actual` - The actual value found in the context.
    /// * `expected` - The expected value defined in the policy.
    /// * `operator` - The operator to use for comparison.
    fn compare_values(
        &self,
        actual: &dyn std::fmt::Display,
        expected: &serde_json::Value,
        operator: &super::ComparisonOperator,
    ) -> bool {
        match operator {
            super::ComparisonOperator::Equals => {
                format!("{}", actual) == expected.as_str().unwrap_or("")
            }
            super::ComparisonOperator::NotEquals => {
                format!("{}", actual) != expected.as_str().unwrap_or("")
            }
            super::ComparisonOperator::GreaterThan => {
                if let (Some(actual_num), Some(expected_num)) =
                    (actual.to_string().parse::<f64>().ok(), expected.as_f64())
                {
                    actual_num > expected_num
                } else {
                    false
                }
            }
            super::ComparisonOperator::LessThan => {
                if let (Some(actual_num), Some(expected_num)) =
                    (actual.to_string().parse::<f64>().ok(), expected.as_f64())
                {
                    actual_num < expected_num
                } else {
                    false
                }
            }
            super::ComparisonOperator::GreaterThanOrEqual => {
                if let (Some(actual_num), Some(expected_num)) =
                    (actual.to_string().parse::<f64>().ok(), expected.as_f64())
                {
                    actual_num >= expected_num
                } else {
                    false
                }
            }
            super::ComparisonOperator::LessThanOrEqual => {
                if let (Some(actual_num), Some(expected_num)) =
                    (actual.to_string().parse::<f64>().ok(), expected.as_f64())
                {
                    actual_num <= expected_num
                } else {
                    false
                }
            }
            super::ComparisonOperator::Contains => {
                if let Some(expected_str) = expected.as_str() {
                    format!("{}", actual).contains(expected_str)
                } else {
                    false
                }
            }
            super::ComparisonOperator::NotContains => {
                if let Some(expected_str) = expected.as_str() {
                    !format!("{}", actual).contains(expected_str)
                } else {
                    false
                }
            }
            super::ComparisonOperator::In => {
                if let Some(expected_array) = expected.as_array() {
                    expected_array
                        .iter()
                        .any(|v| format!("{}", actual) == v.as_str().unwrap_or(""))
                } else {
                    false
                }
            }
            super::ComparisonOperator::NotIn => {
                if let Some(expected_array) = expected.as_array() {
                    !expected_array
                        .iter()
                        .any(|v| format!("{}", actual) == v.as_str().unwrap_or(""))
                } else {
                    false
                }
            }
        }
    }

    /// Checks if an adaptive control should be triggered based on the context.
    ///
    /// # Arguments
    /// * `context` - The current `TrustContext`.
    /// * `control` - The `AdaptiveControl` to evaluate.
    fn should_trigger_adaptive_control(
        &self,
        context: &TrustContext,
        control: &AdaptiveControl,
    ) -> bool {
        if !control.is_active {
            return false;
        }

        // Check trigger conditions
        for condition in &control.trigger_conditions {
            if self.evaluate_trigger_condition(context, condition) {
                return true;
            }
        }

        false
    }

    /// Evaluates a trigger condition for adaptive controls.
    ///
    /// # Arguments
    /// * `context` - The current `TrustContext`.
    /// * `condition` - The `TriggerCondition` to evaluate.
    fn evaluate_trigger_condition(
        &self,
        context: &TrustContext,
        condition: &super::TriggerCondition,
    ) -> bool {
        match condition.condition_type {
            super::ConditionType::FailedAttempts => {
                // Check recent failed attempts for this peer
                let recent_violations = self
                    .violations
                    .get(&context.peer_id)
                    .map(|v| {
                        v.iter()
                            .filter(|violation| {
                                violation.detected_at > Utc::now() - chrono::Duration::minutes(5)
                            })
                            .filter(|violation| {
                                matches!(
                                    violation.violation_type,
                                    ViolationType::TrustLevelInsufficient
                                )
                            })
                            .count()
                    })
                    .unwrap_or(0);

                if let Some(threshold) = condition.threshold.as_u64() {
                    recent_violations >= threshold as usize
                } else {
                    false
                }
            }
            super::ConditionType::AnomalousBehavior => {
                // Check behavioral score
                context.behavioral_score < 0.5
            }
            super::ConditionType::ThreatDetected => {
                // Check current threat level
                matches!(
                    context.environmental_factors.current_threat_level,
                    super::ThreatLevel::High | super::ThreatLevel::Critical
                )
            }
            // Add more condition types as needed
            _ => false,
        }
    }

    /// Calculates the severity of a policy violation based on the trust difference.
    ///
    /// # Arguments
    /// * `actual` - The subject's current `TrustLevel`.
    /// * `required` - The `TrustLevel` required by the policy.
    fn calculate_violation_severity(
        &self,
        actual: &TrustLevel,
        required: &TrustLevel,
    ) -> ViolationSeverity {
        let diff = *required as i8 - *actual as i8;
        match diff {
            1..=2 => ViolationSeverity::Low,
            3..=4 => ViolationSeverity::Medium,
            5..=6 => ViolationSeverity::High,
            _ => ViolationSeverity::Critical,
        }
    }

    /// Returns aggregation metrics for policy enforcement.
    pub fn get_statistics(&self) -> &PolicyStatistics {
        &self.statistics
    }

    /// Retrieves all recorded violations for a specific peer.
    ///
    /// # Arguments
    /// * `peer_id` - The `PeerId` to retrieve violations for.
    pub fn get_violations(&self, peer_id: &PeerId) -> Vec<&PolicyViolation> {
        self.violations
            .get(peer_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Clears the evaluation cache.
    pub fn clear_cache(&mut self) {
        self.evaluation_cache.clear();
        debug!("🗑️ Policy evaluation cache cleared");
    }

    /// Retrieves a reference to the active policy registry.
    pub fn get_policies(&self) -> &HashMap<String, ZeroTrustPolicy> {
        &self.policies
    }
}

impl Default for PolicyStatistics {
    fn default() -> Self {
        Self {
            total_evaluations: 0,
            policy_violations: 0,
            policies_enforced: 0,
            average_evaluation_time_ms: 0.0,
            most_violated_policies: Vec::new(),
            violation_trends: ViolationTrends {
                last_hour: 0,
                last_day: 0,
                last_week: 0,
                last_month: 0,
            },
        }
    }
}

impl Default for PolicyEvaluationResult {
    fn default() -> Self {
        Self {
            required_trust_level: TrustLevel::Unknown,
            confidence: 0.0,
            risk_score: 0.0,
            recommended_actions: Vec::new(),
            applied_policies: Vec::new(),
        }
    }
}
