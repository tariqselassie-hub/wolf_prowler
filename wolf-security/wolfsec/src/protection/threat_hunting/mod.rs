//! Threat Hunting Engine
//!
//! Advanced threat hunting with wolf pack hunting strategies.
//! Wolves proactively hunt threats using coordinated pack tactics.

pub mod automated;
pub mod correlation;
pub mod proactive;
pub mod strategies;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

/// central orchestrator for proactive and reactive threat identification
pub struct ThreatHuntingEngine {
    /// orchestrator for unattended, pattern-driven hunt operations
    automated_hunting: automated::AutomatedHunter,
    /// Registry of pre-defined hunting tactics and coordination logic
    hunting_strategies: strategies::HuntingStrategies,
    /// Logic for linking disparate findings into a unified threat narrative
    threat_correlation: correlation::ThreatCorrelator,
    /// active measures for neutralizing identified threats
    proactive_defense: proactive::ProactiveDefender,
    /// Operational parameters for the hunting ecosystem
    config: ThreatHuntingConfig,
    /// Aggregate telemetry for hunt performance and threat detections
    statistics: ThreatHuntingStats,
}

/// configuration for the threat hunting subsystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHuntingConfig {
    /// Temporal interval (seconds) between automated hunt cycles
    pub hunting_interval: u64,
    /// Limit of simultaneous active hunt operations
    pub max_concurrent_hunts: usize,
    /// sensitivity multiplier for threat identification (0.0 - 1.0)
    pub hunt_sensitivity: f64,
    /// True if the engine should automatically initiate proactive defense
    pub auto_response_enabled: bool,
    /// specific toggles for individual hunting strategies
    pub strategy_config: StrategyConfig,
}

/// Toggle configuration for specific hunting tactics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyConfig {
    /// enable/disable wolf pack coordinated leadership hunts
    pub wolf_pack_enabled: bool,
    /// enable/disable systematic territory boundary patrolling
    pub territory_patrol_enabled: bool,
    /// enable/disable inter-wolf communication during hunts
    pub pack_coordination_enabled: bool,
    /// enable/disable learning-based strategy adjustments
    pub adaptive_hunting_enabled: bool,
}

/// Aggregate performance and success telemetry for threat hunting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHuntingStats {
    /// total count of initiated hunt operations
    pub total_hunts: u64,
    /// count of hunts that reached successful completion
    pub successful_hunts: u64,
    /// global count of verified threats identified
    pub threats_detected: u64,
    /// distribution of hunts across different strategies
    pub hunts_by_strategy: HashMap<HuntingStrategy, u64>,
    /// mean latency for reaching hunt completion
    pub avg_hunt_duration_ms: f64,
    /// count of threats incorrectly flagged during hunts
    pub false_positives: u64,
    /// count of proactive measures initiated by the engine
    pub response_actions: u64,
    /// point in time of the most recent telemetry update
    pub last_update: DateTime<Utc>,
}

/// discrete, time-bound operation for identifying specific threats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHunt {
    /// Unique identifier for the hunt operation
    pub id: Uuid,
    /// human-readable display name for the hunt
    pub name: String,
    /// classification of the hunt trigger (Proactive, Reactive, etc.)
    pub hunt_type: HuntType,
    /// specific tactic employed during the hunt
    pub strategy: HuntingStrategy,
    /// current operational state of the hunt (InProgress, Completed, etc.)
    pub status: HuntStatus,
    /// list of identifiers for entities targeted during the search
    pub target_entities: Vec<String>,
    /// environmental constraints and search logic
    pub parameters: HuntParameters,
    /// finalized outcome and findings of the operation
    pub results: HuntResults,
    /// when the hunt was initially defined
    pub created_at: DateTime<Utc>,
    /// point in time when execution began
    pub started_at: Option<DateTime<Utc>>,
    /// point in time when execution reached a final state
    pub completed_at: Option<DateTime<Utc>>,
}

/// Hunt types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HuntType {
    /// Proactive hunt
    Proactive,
    /// Reactive hunt
    Reactive,
    /// Intelligence-driven hunt
    IntelligenceDriven,
    /// Pattern-based hunt
    PatternBased,
    /// Behavioral hunt
    Behavioral,
}

/// Hunting strategies with wolf-themed names
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HuntingStrategy {
    /// Alpha wolf leadership hunt
    AlphaLeadership,
    /// Pack coordination hunt
    PackCoordination,
    /// Territory patrol hunt
    TerritoryPatrol,
    /// Hunting party formation
    HuntingParty,
    /// Scouting reconnaissance
    ScoutingReconnaissance,
    /// Ambush tactics
    AmbushTactics,
    /// Pursuit hunting
    PursuitHunting,
    /// Adaptive hunting
    AdaptiveHunting,
}

/// Hunt status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HuntStatus {
    /// Hunt created
    Created,
    /// Hunt in progress
    InProgress,
    /// Hunt completed
    Completed,
    /// Hunt failed
    Failed,
    /// Hunt cancelled
    Cancelled,
}

/// logic and constraints governing a hunt search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntParameters {
    /// temporal boundaries for data analysis
    pub time_window: TimeWindow,
    /// specific cryptographic or behavioral signals to search for
    pub target_indicators: Vec<String>,
    /// regex or behavioral templates for identifying threats
    pub search_patterns: Vec<String>,
    /// sensitivity threshold for the specific hunt (0.0 - 1.0)
    pub sensitivity: f64,
    /// maximum number of findings to record per hunt
    pub max_results: usize,
    /// provider-specific or strategy-specific configurations
    pub custom_params: HashMap<String, serde_json::Value>,
}

/// outcome and findings of a finalized threat hunt operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntResults {
    /// collection of verified threats identified during the hunt
    pub threats_found: Vec<ThreatFinding>,
    /// new indicators of compromise (IoCs) discovered
    pub indicators_discovered: Vec<String>,
    /// new behavioral or network patterns identified
    pub patterns_identified: Vec<String>,
    /// total count of entities analyzed during the hunt
    pub entities_investigated: u64,
    /// volume of data ingested and analyzed (MB)
    pub data_analyzed_mb: f64,
    /// aggregate statistical certainty for all findings
    pub confidence: f64,
    /// narrative summary of the hunt's discoveries
    pub summary: String,
}

/// discrete identifier of a potential or verified security incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    /// unique identifier for the finding
    pub id: Uuid,
    /// classification of the threat (Malware, C2, etc.)
    pub threat_type: String,
    /// criticality of the finding (Pup, Alpha, etc.)
    pub severity: ThreatSeverity,
    /// statistical probability that the finding is valid
    pub confidence: f64,
    /// descriptive text detailing the finding circumstances
    pub description: String,
    /// list of identifiers for entities impacted by this threat
    pub affected_entities: Vec<String>,
    /// collection of raw data and signals supporting the finding
    pub evidence: Vec<Evidence>,
    /// proactive steps suggested for neutralization or remediation
    pub recommended_actions: Vec<String>,
    /// point in time when the finding was initially identified
    pub timestamp: DateTime<Utc>,
}

/// Threat severity with wolf-themed classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    /// Pup level - Low threat
    Pup = 0,
    /// Scout level - Informational
    Scout = 1,
    /// Hunter level - Medium threat
    Hunter = 2,
    /// Beta level - High threat
    Beta = 3,
    /// Alpha level - Critical threat
    Alpha = 4,
}

/// Evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence type
    pub evidence_type: String,
    /// Evidence value
    pub value: serde_json::Value,
    /// Source
    pub source: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Confidence
    pub confidence: f64,
}

/// Time window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_hours: u64,
}

/// Wolf pack hunting pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfPackHuntingPattern {
    /// Pattern ID
    pub id: String,
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Hunting strategy
    pub strategy: HuntingStrategy,
    /// Pack roles
    pub pack_roles: Vec<PackRole>,
    /// Success rate
    pub success_rate: f64,
    /// Last used
    pub last_used: DateTime<Utc>,
    /// Usage count
    pub usage_count: u64,
}

/// Pack roles in hunting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackRole {
    /// Alpha wolf - leads the hunt
    Alpha,
    /// Beta wolves - support and coordination
    Beta,
    /// Hunters - primary threat detection
    Hunter,
    /// Scouts - reconnaissance and intelligence
    Scout,
    /// Omega wolves - support and logistics
    Omega,
}

impl ThreatHuntingEngine {
    /// Initializes a new engine with the provided configuration and sub-modules.
    pub fn new(config: ThreatHuntingConfig) -> Result<Self> {
        info!("🎯 Initializing Threat Hunting Engine");

        let engine = Self {
            automated_hunting: automated::AutomatedHunter::new(config.clone())?,
            hunting_strategies: strategies::HuntingStrategies::new(config.clone())?,
            threat_correlation: correlation::ThreatCorrelator::new(config.clone())?,
            proactive_defense: proactive::ProactiveDefender::new(config.clone())?,
            config,
            statistics: ThreatHuntingStats::default(),
        };

        info!("✅ Threat Hunting Engine initialized successfully");
        Ok(engine)
    }

    /// Transitions the engine into an active state for unattended operations.
    pub async fn start_automated_hunting(&mut self) -> Result<()> {
        info!("🚀 Starting automated threat hunting");

        self.automated_hunting.start_hunting().await?;

        info!("✅ Automated hunting started");
        Ok(())
    }

    /// provisions a new hunt operation with specific constraints and targets.
    pub async fn create_hunt(
        &mut self,
        hunt_type: HuntType,
        strategy: HuntingStrategy,
        parameters: HuntParameters,
    ) -> Result<ThreatHunt> {
        debug!("🎯 Creating new threat hunt: {:?}", hunt_type);

        let hunt = ThreatHunt {
            id: Uuid::new_v4(),
            name: format!("Hunt-{:?}-{}", hunt_type, Uuid::new_v4()),
            hunt_type,
            strategy,
            status: HuntStatus::Created,
            target_entities: Vec::new(),
            parameters,
            results: HuntResults::default(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
        };

        self.statistics.total_hunts += 1;

        info!("✅ Created threat hunt: {}", hunt.id);
        Ok(hunt)
    }

    /// executes the hunt strategy and records any discovered findings.
    pub async fn execute_hunt(&mut self, mut hunt: ThreatHunt) -> Result<ThreatHunt> {
        debug!("🎯 Executing threat hunt: {}", hunt.id);

        hunt.status = HuntStatus::InProgress;
        hunt.started_at = Some(Utc::now());

        let start_time = std::time::Instant::now();

        // Execute based on strategy
        let results = match hunt.strategy {
            HuntingStrategy::AlphaLeadership => {
                self.hunting_strategies.alpha_leadership_hunt(&hunt).await?
            }
            HuntingStrategy::PackCoordination => {
                self.hunting_strategies
                    .pack_coordination_hunt(&hunt)
                    .await?
            }
            HuntingStrategy::TerritoryPatrol => {
                self.hunting_strategies.territory_patrol_hunt(&hunt).await?
            }
            HuntingStrategy::HuntingParty => {
                self.hunting_strategies.hunting_party_hunt(&hunt).await?
            }
            HuntingStrategy::ScoutingReconnaissance => {
                self.hunting_strategies
                    .scouting_reconnaissance_hunt(&hunt)
                    .await?
            }
            HuntingStrategy::AmbushTactics => {
                self.hunting_strategies.ambush_tactics_hunt(&hunt).await?
            }
            HuntingStrategy::PursuitHunting => {
                self.hunting_strategies.pursuit_hunting_hunt(&hunt).await?
            }
            HuntingStrategy::AdaptiveHunting => {
                self.hunting_strategies.adaptive_hunting_hunt(&hunt).await?
            }
        };

        hunt.results = results;
        hunt.status = HuntStatus::Completed;
        hunt.completed_at = Some(Utc::now());

        // Update statistics
        let hunt_duration = start_time.elapsed().as_millis() as f64;
        self.update_hunt_statistics(&hunt, hunt_duration);

        // Auto-response if enabled
        if self.config.auto_response_enabled && !hunt.results.threats_found.is_empty() {
            self.proactive_defense
                .respond_to_threats(&hunt.results.threats_found)
                .await?;
        }

        info!(
            "✅ Hunt {} completed: {} threats found",
            hunt.id,
            hunt.results.threats_found.len()
        );
        Ok(hunt)
    }

    /// identifies logical links between finding IDs using correlation logic.
    pub async fn correlate_threats(
        &mut self,
        hunts: &[ThreatHunt],
    ) -> Result<Vec<ThreatCorrelation>> {
        debug!("🔗 Correlating threats across {} hunts", hunts.len());

        let correlations = self.threat_correlation.correlate_threats(hunts).await?;

        info!("✅ Found {} threat correlations", correlations.len());
        Ok(correlations)
    }

    /// Retrieves the aggregate performance and detection telemetry.
    pub fn get_statistics(&self) -> &ThreatHuntingStats {
        &self.statistics
    }

    /// Update hunt statistics
    fn update_hunt_statistics(&mut self, hunt: &ThreatHunt, hunt_duration: f64) {
        if hunt.status == HuntStatus::Completed {
            self.statistics.successful_hunts += 1;
            self.statistics.threats_detected += hunt.results.threats_found.len() as u64;

            *self
                .statistics
                .hunts_by_strategy
                .entry(hunt.strategy.clone())
                .or_insert(0) += 1;

            // Update average hunt duration
            self.statistics.avg_hunt_duration_ms = (self.statistics.avg_hunt_duration_ms
                * (self.statistics.successful_hunts - 1) as f64
                + hunt_duration)
                / self.statistics.successful_hunts as f64;
        }

        self.statistics.last_update = Utc::now();
    }

    /// Get available hunting strategies
    pub fn get_available_strategies(&self) -> Vec<HuntingStrategy> {
        vec![
            HuntingStrategy::AlphaLeadership,
            HuntingStrategy::PackCoordination,
            HuntingStrategy::TerritoryPatrol,
            HuntingStrategy::HuntingParty,
            HuntingStrategy::ScoutingReconnaissance,
            HuntingStrategy::AmbushTactics,
            HuntingStrategy::PursuitHunting,
            HuntingStrategy::AdaptiveHunting,
        ]
    }

    /// Get strategy description
    pub fn get_strategy_description(&self, strategy: &HuntingStrategy) -> String {
        match strategy {
            HuntingStrategy::AlphaLeadership => {
                "Alpha wolf leads coordinated pack hunt with high-priority targets".to_string()
            }
            HuntingStrategy::PackCoordination => {
                "Multiple wolves coordinate to hunt complex threats across territories".to_string()
            }
            HuntingStrategy::TerritoryPatrol => {
                "Systematic patrol of wolf territories to detect intrusion".to_string()
            }
            HuntingStrategy::HuntingParty => {
                "Small group of wolves hunt specific threat patterns".to_string()
            }
            HuntingStrategy::ScoutingReconnaissance => {
                "Scout wolves gather intelligence on potential threats".to_string()
            }
            HuntingStrategy::AmbushTactics => {
                "Set strategic ambushes for known threat patterns".to_string()
            }
            HuntingStrategy::PursuitHunting => {
                "Persistent pursuit of fleeing or evasive threats".to_string()
            }
            HuntingStrategy::AdaptiveHunting => {
                "Adaptive hunting that learns from previous hunt results".to_string()
            }
        }
    }
}

/// logical link established between disparate threat findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCorrelation {
    /// Unique identifier for the correlation event
    pub id: Uuid,
    /// List of identifiers for the threats being linked
    pub correlated_threats: Vec<Uuid>,
    /// statistical probability that the threats are related
    pub correlation_score: f64,
    /// classification of the link (SameActor, SameTarget, etc.)
    pub correlation_type: CorrelationType,
    /// narrative detailing why the link was established
    pub description: String,
    /// point in time when the correlation was established
    pub timestamp: DateTime<Utc>,
}

/// Correlation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationType {
    /// Same actor
    SameActor,
    /// Same technique
    SameTechnique,
    /// Same timeline
    SameTimeline,
    /// Same target
    SameTarget,
    /// Pattern similarity
    PatternSimilarity,
}

impl Default for ThreatHuntingConfig {
    fn default() -> Self {
        Self {
            hunting_interval: 300, // 5 minutes
            max_concurrent_hunts: 10,
            hunt_sensitivity: 0.7,
            auto_response_enabled: true,
            strategy_config: StrategyConfig::default(),
        }
    }
}

impl Default for StrategyConfig {
    fn default() -> Self {
        Self {
            wolf_pack_enabled: true,
            territory_patrol_enabled: true,
            pack_coordination_enabled: true,
            adaptive_hunting_enabled: true,
        }
    }
}

impl Default for ThreatHuntingStats {
    fn default() -> Self {
        Self {
            total_hunts: 0,
            successful_hunts: 0,
            threats_detected: 0,
            hunts_by_strategy: HashMap::new(),
            avg_hunt_duration_ms: 0.0,
            false_positives: 0,
            response_actions: 0,
            last_update: Utc::now(),
        }
    }
}

impl Default for HuntResults {
    fn default() -> Self {
        Self {
            threats_found: Vec::new(),
            indicators_discovered: Vec::new(),
            patterns_identified: Vec::new(),
            entities_investigated: 0,
            data_analyzed_mb: 0.0,
            confidence: 0.0,
            summary: String::new(),
        }
    }
}
