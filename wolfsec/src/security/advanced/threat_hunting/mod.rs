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

/// Main threat hunting engine
pub struct ThreatHuntingEngine {
    /// Automated hunting
    automated_hunting: automated::AutomatedHunter,
    /// Hunting strategies
    hunting_strategies: strategies::HuntingStrategies,
    /// Threat correlation
    threat_correlation: correlation::ThreatCorrelator,
    /// Proactive defense
    proactive_defense: proactive::ProactiveDefender,
    /// Configuration
    config: ThreatHuntingConfig,
    /// Statistics
    statistics: ThreatHuntingStats,
}

/// Threat hunting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHuntingConfig {
    /// Hunting interval in seconds
    pub hunting_interval: u64,
    /// Maximum concurrent hunts
    pub max_concurrent_hunts: usize,
    /// Hunt sensitivity
    pub hunt_sensitivity: f64,
    /// Auto-response enabled
    pub auto_response_enabled: bool,
    /// Hunting strategies
    pub strategy_config: StrategyConfig,
}

/// Strategy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyConfig {
    /// Wolf pack strategies enabled
    pub wolf_pack_enabled: bool,
    /// Territory patrol enabled
    pub territory_patrol_enabled: bool,
    /// Pack coordination enabled
    pub pack_coordination_enabled: bool,
    /// Adaptive hunting enabled
    pub adaptive_hunting_enabled: bool,
}

/// Threat hunting statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHuntingStats {
    /// Total hunts initiated
    pub total_hunts: u64,
    /// Successful hunts
    pub successful_hunts: u64,
    /// Threats detected
    pub threats_detected: u64,
    /// Hunts by strategy
    pub hunts_by_strategy: HashMap<HuntingStrategy, u64>,
    /// Average hunt duration
    pub avg_hunt_duration_ms: f64,
    /// False positives
    pub false_positives: u64,
    /// Response actions taken
    pub response_actions: u64,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Threat hunt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHunt {
    /// Hunt ID
    pub id: Uuid,
    /// Hunt name
    pub name: String,
    /// Hunt type
    pub hunt_type: HuntType,
    /// Hunting strategy
    pub strategy: HuntingStrategy,
    /// Hunt status
    pub status: HuntStatus,
    /// Target entities
    pub target_entities: Vec<String>,
    /// Hunt parameters
    pub parameters: HuntParameters,
    /// Results
    pub results: HuntResults,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Started timestamp
    pub started_at: Option<DateTime<Utc>>,
    /// Completed timestamp
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

/// Hunt parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntParameters {
    /// Time window
    pub time_window: TimeWindow,
    /// Target indicators
    pub target_indicators: Vec<String>,
    /// Search patterns
    pub search_patterns: Vec<String>,
    /// Sensitivity level
    pub sensitivity: f64,
    /// Max results
    pub max_results: usize,
    /// Custom parameters
    pub custom_params: HashMap<String, serde_json::Value>,
}

/// Hunt results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntResults {
    /// Threats found
    pub threats_found: Vec<ThreatFinding>,
    /// Indicators discovered
    pub indicators_discovered: Vec<String>,
    /// Patterns identified
    pub patterns_identified: Vec<String>,
    /// Entities investigated
    pub entities_investigated: u64,
    /// Data analyzed
    pub data_analyzed_mb: f64,
    /// Hunt confidence
    pub confidence: f64,
    /// Hunt summary
    pub summary: String,
}

/// Threat finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    /// Finding ID
    pub id: Uuid,
    /// Threat type
    pub threat_type: String,
    /// Threat severity
    pub severity: ThreatSeverity,
    /// Confidence score
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Affected entities
    pub affected_entities: Vec<String>,
    /// Evidence
    pub evidence: Vec<Evidence>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
    /// Timestamp
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
    /// Create new threat hunting engine
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

    /// Start automated hunting
    pub async fn start_automated_hunting(&mut self) -> Result<()> {
        info!("🚀 Starting automated threat hunting");

        self.automated_hunting.start_hunting().await?;

        info!("✅ Automated hunting started");
        Ok(())
    }

    /// Create new threat hunt
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

    /// Execute threat hunt
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

    /// Correlate threats across hunts
    pub async fn correlate_threats(
        &mut self,
        hunts: &[ThreatHunt],
    ) -> Result<Vec<ThreatCorrelation>> {
        debug!("🔗 Correlating threats across {} hunts", hunts.len());

        let correlations = self.threat_correlation.correlate_threats(hunts).await?;

        info!("✅ Found {} threat correlations", correlations.len());
        Ok(correlations)
    }

    /// Get hunting statistics
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

/// Threat correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCorrelation {
    /// Correlation ID
    pub id: Uuid,
    /// Correlated threats
    pub correlated_threats: Vec<Uuid>,
    /// Correlation score
    pub correlation_score: f64,
    /// Correlation type
    pub correlation_type: CorrelationType,
    /// Description
    pub description: String,
    /// Timestamp
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
