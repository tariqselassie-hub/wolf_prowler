//! Threat Intelligence Module
//!
//! Advanced threat intelligence with wolf pack collective defense.
//! Wolves share intelligence about threats across the pack for collective protection.

/// Threat feeds
pub mod feeds;
/// Threat indicators
pub mod indicators;
/// Threat scoring
pub mod scoring;
/// Intelligence sharing
pub mod sharing;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

 // Use libp2p's PeerId directly

/// Re-export main components
pub use feeds::ThreatFeedManager;
pub use indicators::IndicatorManager;
pub use scoring::ThreatScoringEngine;
pub use sharing::WolfPackIntelligenceSharing;

/// Main threat intelligence manager
pub struct ThreatIntelligenceManager {
    /// Feed manager
    feed_manager: ThreatFeedManager,
    /// Indicator manager
    indicator_manager: IndicatorManager,
    /// Scoring engine
    scoring_engine: ThreatScoringEngine,
    /// Intelligence sharing
    intelligence_sharing: WolfPackIntelligenceSharing,
    /// Configuration
    config: ThreatIntelligenceConfig,
    /// Statistics
    statistics: ThreatIntelligenceStats,
}

/// Threat intelligence configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceConfig {
    /// Feed update interval in seconds
    pub feed_update_interval: u64,
    /// Maximum indicators to keep
    pub max_indicators: usize,
    /// Threat score thresholds
    pub thresholds: ThreatThresholds,
    /// Sharing configuration
    pub sharing_config: SharingConfig,
}

/// Threat thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatThresholds {
    /// Low threat threshold
    pub low_threshold: f64,
    /// Medium threat threshold
    pub medium_threshold: f64,
    /// High threat threshold
    pub high_threshold: f64,
    /// Critical threat threshold
    pub critical_threshold: f64,
}

/// Sharing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingConfig {
    /// Enable intelligence sharing
    pub enabled: bool,
    /// Sharing frequency in seconds
    pub sharing_frequency: u64,
    /// Minimum confidence for sharing
    pub min_confidence: f64,
    /// Trusted packs for sharing
    pub trusted_packs: Vec<String>,
}

/// Threat intelligence statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceStats {
    /// Total indicators collected
    pub total_indicators: u64,
    /// Indicators by severity
    pub indicators_by_severity: HashMap<ThreatSeverity, u64>,
    /// Indicators by type
    pub indicators_by_type: HashMap<IndicatorType, u64>,
    /// Feed statistics
    pub feed_stats: HashMap<String, FeedStats>,
    /// Sharing statistics
    pub sharing_stats: SharingStats,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Feed statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedStats {
    /// Name of the feed
    pub feed_name: String,
    /// Total indicators collected from feed
    pub indicators_collected: u64,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
    /// Success rate (0.0-1.0)
    pub success_rate: f64,
    /// Average latency in milliseconds
    pub average_latency_ms: f64,
}

/// Sharing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingStats {
    /// Total indicators shared
    pub indicators_shared: u64,
    /// Total indicators received
    pub indicators_received: u64,
    /// Number of connected packs
    pub packs_connected: usize,
    /// Last share timestamp
    pub last_share: DateTime<Utc>,
}

/// Threat indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// Unique identifier
    pub id: Uuid,
    /// Indicator type
    pub indicator_type: IndicatorType,
    /// Indicator value
    pub value: String,
    /// Threat severity
    pub severity: ThreatSeverity,
    /// Confidence score (0.0-1.0)
    pub confidence: f64,
    /// Threat score (0.0-1.0)
    pub threat_score: f64,
    /// Source feed
    pub source_feed: String,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Description
    pub description: String,
    /// Associated threats
    pub associated_threats: Vec<String>,
    /// Mitigation recommendations
    pub mitigation: Vec<String>,
    /// Tags
    pub tags: Vec<String>,
    /// Active status
    pub active: bool,
    /// Source of the indicator
    pub source: String,
}

/// Indicator types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    /// IP address
    IPAddress,
    /// Domain name
    Domain,
    /// URL
    URL,
    /// File hash
    FileHash,
    /// Email address
    Email,
    /// Certificate hash
    Certificate,
    /// User agent
    UserAgent,
    /// Registry key
    RegistryKey,
    /// File name
    FileName,
    /// Process name
    ProcessName,
    /// Network signature
    NetworkSignature,
    /// YARA rule
    YARARule,
    /// Custom indicator
    Custom(String),
}

/// Threat severity levels with wolf-themed classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Threat intelligence report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceReport {
    /// Report ID
    pub id: Uuid,
    /// Report timestamp
    pub timestamp: DateTime<Utc>,
    /// Report type
    pub report_type: ReportType,
    /// Threat indicators
    pub indicators: Vec<ThreatIndicator>,
    /// Threat actors
    pub threat_actors: Vec<ThreatActor>,
    /// Campaigns
    pub campaigns: Vec<ThreatCampaign>,
    /// TTPs (Tactics, Techniques, Procedures)
    pub ttps: Vec<TTP>,
    /// Summary
    pub summary: String,
    /// Confidence score
    pub confidence: f64,
    /// Overall threat level
    pub threat_level: ThreatSeverity,
}

/// Report types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportType {
    /// Daily report
    Daily,
    /// Weekly report
    Weekly,
    /// Monthly report
    Monthly,
    /// Incident report
    Incident,
    /// Campaign report
    Campaign,
    /// Threat actor report
    ThreatActor,
}

/// Threat actor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    /// Unique actor ID
    pub actor_id: String,
    /// Actor name
    pub name: String,
    /// Known aliases
    pub aliases: Vec<String>,
    /// Description
    pub description: String,
    /// Known capabilities
    pub capabilities: Vec<String>,
    /// Motivations
    pub motivations: Vec<String>,
    /// Known indicators associated with actor
    pub known_indicators: Vec<String>,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Attribution confidence (0.0-1.0)
    pub attribution_confidence: f64,
}

/// Threat campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCampaign {
    /// Campaign ID
    pub campaign_id: String,
    /// Campaign name
    pub name: String,
    /// Description
    pub description: String,
    /// Associated threat actors
    pub threat_actors: Vec<String>,
    /// Campaign timeline
    pub timeline: CampaignTimeline,
    /// Target industries
    pub target_industries: Vec<String>,
    /// Target geographies
    pub target_geographies: Vec<String>,
    /// Tactics used
    pub tactics: Vec<String>,
    /// Techniques used
    pub techniques: Vec<String>,
    /// Procedures used
    pub procedures: Vec<String>,
    /// Associated indicators
    pub indicators: Vec<String>,
    /// Campaign status
    pub status: CampaignStatus,
}

/// Campaign timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTimeline {
    /// Start date
    pub start_date: DateTime<Utc>,
    /// End date (optional)
    pub end_date: Option<DateTime<Utc>>,
    /// Key events
    pub key_events: Vec<CampaignEvent>,
}

/// Campaign event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: String,
    /// Description
    pub description: String,
    /// Impact description
    pub impact: String,
}

/// Campaign status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CampaignStatus {
    /// Currently active
    Active,
    /// Dormant/Inactive
    Dormant,
    /// Concluded
    Concluded,
    /// Unknown status
    Unknown,
}

/// TTP (Tactics, Techniques, Procedures)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TTP {
    /// Tactic ID (e.g., TA0001)
    pub tactic_id: String,
    /// Tactic name
    pub tactic_name: String,
    /// Technique ID (e.g., T1566)
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Procedure ID
    pub procedure_id: String,
    /// Procedure name
    pub procedure_name: String,
    /// Description
    pub description: String,
    /// Detection methods
    pub detection_methods: Vec<String>,
    /// Mitigation methods
    pub mitigation_methods: Vec<String>,
}

impl ThreatIntelligenceManager {
    /// Create new threat intelligence manager
    pub fn new(config: ThreatIntelligenceConfig) -> Result<Self> {
        info!("🌐 Initializing Threat Intelligence Manager");

        let manager = Self {
            feed_manager: ThreatFeedManager::new(config.clone())?,
            indicator_manager: IndicatorManager::new(config.clone())?,
            scoring_engine: ThreatScoringEngine::new(config.clone())?,
            intelligence_sharing: WolfPackIntelligenceSharing::new(config.sharing_config.clone())?,
            config,
            statistics: ThreatIntelligenceStats::default(),
        };

        info!("✅ Threat Intelligence Manager initialized successfully");
        Ok(manager)
    }

    /// Start threat intelligence collection
    pub async fn start_collection(&mut self) -> Result<()> {
        info!("🚀 Starting threat intelligence collection");

        // Start feed collection
        self.feed_manager.start_collection().await?;

        // Start intelligence sharing
        if self.config.sharing_config.enabled {
            self.intelligence_sharing.start_sharing().await?;
        }

        info!("✅ Threat intelligence collection started");
        Ok(())
    }

    /// Process new threat indicators
    pub async fn process_indicators(
        &mut self,
        indicators: Vec<ThreatIndicator>,
    ) -> Result<Vec<ThreatIndicator>> {
        debug!("📊 Processing {} threat indicators", indicators.len());

        let mut processed_indicators = Vec::new();

        for mut indicator in indicators {
            // Score the indicator
            indicator.threat_score = self.scoring_engine.score_indicator(&indicator).await?;

            // Store the indicator
            self.indicator_manager
                .add_indicator(indicator.clone())
                .await?;

            // Update statistics
            self.update_statistics(&indicator);

            processed_indicators.push(indicator);
        }

        // Share intelligence if enabled
        if self.config.sharing_config.enabled && !processed_indicators.is_empty() {
            self.intelligence_sharing
                .share_indicators(&processed_indicators)
                .await?;
        }

        debug!(
            "✅ Processed {} threat indicators",
            processed_indicators.len()
        );
        Ok(processed_indicators)
    }

    /// Query threat indicators
    pub async fn query_indicators(&self, query: &ThreatQuery) -> Result<Vec<ThreatIndicator>> {
        self.indicator_manager.query_indicators(query).await
    }

    /// Generate threat intelligence report
    pub async fn generate_report(
        &self,
        report_type: ReportType,
    ) -> Result<ThreatIntelligenceReport> {
        debug!("📋 Generating {:?} threat intelligence report", report_type);

        let indicators = self.indicator_manager.get_all_indicators().await?;
        let threat_level = self.calculate_overall_threat_level(&indicators);
        let confidence = self.calculate_report_confidence(&indicators);

        let report = ThreatIntelligenceReport {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            report_type,
            indicators: indicators.clone(),
            threat_actors: Vec::new(), // Would be populated from threat actor database
            campaigns: Vec::new(),     // Would be populated from campaign database
            ttps: Vec::new(),          // Would be populated from TTP database
            summary: format!(
                "Threat intelligence report with {} indicators",
                indicators.len()
            ),
            confidence,
            threat_level,
        };

        info!(
            "✅ Generated threat intelligence report: {} indicators",
            indicators.len()
        );
        Ok(report)
    }

    /// Get statistics
    pub fn get_statistics(&self) -> &ThreatIntelligenceStats {
        &self.statistics
    }

    /// Update statistics
    fn update_statistics(&mut self, indicator: &ThreatIndicator) {
        self.statistics.total_indicators += 1;

        *self
            .statistics
            .indicators_by_severity
            .entry(indicator.severity.clone())
            .or_insert(0) += 1;

        *self
            .statistics
            .indicators_by_type
            .entry(indicator.indicator_type.clone())
            .or_insert(0) += 1;

        self.statistics.last_update = Utc::now();
    }

    /// Calculate overall threat level
    fn calculate_overall_threat_level(&self, indicators: &[ThreatIndicator]) -> ThreatSeverity {
        if indicators.is_empty() {
            return ThreatSeverity::Pup;
        }

        let total_score: f64 = indicators.iter().map(|i| i.threat_score).sum();
        let average_score = total_score / indicators.len() as f64;

        if average_score >= 0.8 {
            ThreatSeverity::Alpha
        } else if average_score >= 0.6 {
            ThreatSeverity::Beta
        } else if average_score >= 0.4 {
            ThreatSeverity::Hunter
        } else if average_score >= 0.2 {
            ThreatSeverity::Scout
        } else {
            ThreatSeverity::Pup
        }
    }

    /// Calculate report confidence
    fn calculate_report_confidence(&self, indicators: &[ThreatIndicator]) -> f64 {
        if indicators.is_empty() {
            return 0.0;
        }

        let total_confidence: f64 = indicators.iter().map(|i| i.confidence).sum();
        total_confidence / indicators.len() as f64
    }
}

/// Threat query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatQuery {
    /// Filter by indicator types
    pub indicator_types: Option<Vec<IndicatorType>>,
    /// Filter by severities
    pub severities: Option<Vec<ThreatSeverity>>,
    /// Minimum confidence score
    pub confidence_min: Option<f64>,
    /// Minimum threat score
    pub threat_score_min: Option<f64>,
    /// Time range filter
    pub time_range: Option<TimeRange>,
    /// Filter by source feeds
    pub source_feeds: Option<Vec<String>>,
    /// Filter by tags
    pub tags: Option<Vec<String>>,
    /// Text search in value/description
    pub text_search: Option<String>,
    /// Limit results
    pub limit: Option<usize>,
}

/// Time range for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    /// Start time
    pub start: DateTime<Utc>,
    /// End time
    pub end: DateTime<Utc>,
}

impl Default for ThreatIntelligenceConfig {
    fn default() -> Self {
        Self {
            feed_update_interval: 300, // 5 minutes
            max_indicators: 100000,
            thresholds: ThreatThresholds::default(),
            sharing_config: SharingConfig::default(),
        }
    }
}

impl Default for ThreatThresholds {
    fn default() -> Self {
        Self {
            low_threshold: 0.2,
            medium_threshold: 0.4,
            high_threshold: 0.7,
            critical_threshold: 0.9,
        }
    }
}

impl Default for SharingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sharing_frequency: 600, // 10 minutes
            min_confidence: 0.7,
            trusted_packs: Vec::new(),
        }
    }
}

impl Default for ThreatIntelligenceStats {
    fn default() -> Self {
        Self {
            total_indicators: 0,
            indicators_by_severity: HashMap::new(),
            indicators_by_type: HashMap::new(),
            feed_stats: HashMap::new(),
            sharing_stats: SharingStats::default(),
            last_update: Utc::now(),
        }
    }
}

impl Default for SharingStats {
    fn default() -> Self {
        Self {
            indicators_shared: 0,
            indicators_received: 0,
            packs_connected: 0,
            last_share: Utc::now(),
        }
    }
}
