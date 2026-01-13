//! Threat Detection Module
//!
//! Migrated from src/core/security.rs
//! Security management for threat detection and response with wolf-themed architecture

use anyhow::Result;
use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Threat detection and response manager
///
/// This manager monitors peer behavior, detects threats, and coordinates
/// pack-wide security responses using wolf-themed threat detection.
pub struct ThreatDetectionManager {
    /// Known peers and their trust levels
    peers: HashMap<PeerId, PeerInfo>,
    /// Current security events
    events: Vec<SecurityEvent>,
    /// Active threats
    threats: Vec<Threat>,
    /// Configuration
    config: ThreatDetectionConfig,
    /// Metrics collector
    metrics: SecurityMetrics,
}

/// Information about a peer in the pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Trust level (0.0 to 1.0) - wolf pack trust hierarchy
    pub trust_level: f64,
    /// Reputation score in the pack
    pub reputation: i32,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Connection count
    pub connection_count: u32,
    /// Security flags
    pub flags: PeerFlags,
}

/// Security flags for peers with wolf-themed roles
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerFlags {
    /// Peer is verified (alpha wolf)
    pub verified: bool,
    /// Peer has been suspicious (lone wolf behavior)
    pub suspicious: bool,
    /// Peer is blocked (exiled from pack)
    pub blocked: bool,
    /// Peer is part of pack (pack member)
    pub pack_member: bool,
}

/// Security event in the wolf pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event ID
    pub id: String,
    /// Event type
    pub event_type: SecurityEventType,
    /// Source peer
    pub source: Option<PeerId>,
    /// Target peer
    pub target: Option<PeerId>,
    /// Severity level
    pub severity: ThreatSeverity,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Description
    pub description: String,
    /// Additional data
    pub data: HashMap<String, String>,
}

/// Types of security events with wolf-themed naming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    /// New wolf joins the pack
    PeerConnected,
    /// Wolf leaves the pack
    PeerDisconnected,
    /// Suspicious wolf behavior detected
    SuspiciousActivity,
    /// Authentication failure (unknown wolf)
    AuthFailure,
    /// Invalid howl signature
    InvalidSignature,
    /// Howl rate limit exceeded
    RateLimitExceeded,
    /// Pack coordination howl
    PackCoordination,
    /// Threat alert to the pack
    ThreatAlert,
    /// Howl communication
    HowlCommunication,
    /// Territory breach
    TerritoryBreach,
    /// Pack hunting pattern
    PackHunting,
    /// Lone wolf detected
    LoneWolfActivity,
}

/// Threat severity levels with pack hierarchy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    /// Pup level - minimal concern
    Low,
    /// Scout level - needs attention
    Medium,
    /// Hunter level - serious concern
    High,
    /// Alpha level - critical threat
    Critical,
}

/// Threat information with wolf-themed classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Threat ID
    pub id: String,
    /// Threat type
    pub threat_type: ThreatType,
    /// Source peer (if known)
    pub source: Option<PeerId>,
    /// Severity
    pub severity: ThreatSeverity,
    /// Status
    pub status: ThreatStatus,
    /// Detection time
    pub detected_at: DateTime<Utc>,
    /// Last updated
    pub updated_at: DateTime<Utc>,
    /// Description
    pub description: String,
    /// Recommended actions for the pack
    pub actions: Vec<String>,
}

/// Types of threats with wolf-themed classifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    /// Malicious wolf in the pack
    MaliciousPeer,
    /// Sybil attack (multiple fake wolves)
    SybilAttack,
    /// Howl flooding (message spamming)
    MessageFlooding,
    /// Wolf impersonation
    Impersonation,
    /// Pack network partition
    NetworkPartition,
    /// Pack infiltration by rival pack
    PackInfiltration,
    /// Territory invasion
    TerritoryInvasion,
    /// Alpha challenge
    AlphaChallenge,
    /// Unknown threat
    Unknown,
}

/// Threat status with pack response phases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatStatus {
    /// Active threat to the pack
    Active,
    /// Pack is investigating
    Investigating,
    /// Threat contained by pack
    Contained,
    /// Threat resolved
    Resolved,
    /// False alarm
    FalsePositive,
}

/// Threat detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectionConfig {
    /// Threshold for threat detection
    pub threat_threshold: f64,
    /// Enable automatic threat response
    pub auto_response: bool,
    /// Pack coordination enabled
    pub pack_coordination: bool,
    /// Maximum connection rate per peer
    pub max_connection_rate: u32,
    /// Message rate limit (howls per minute)
    pub message_rate_limit: u32,
    /// Trust decay rate per hour
    pub trust_decay_rate: f64,
    /// Enable pack hunting patterns
    pub enable_pack_hunting: bool,
    /// Territory monitoring enabled
    pub territory_monitoring: bool,
}

/// Security metrics for the pack
#[derive(Debug, Clone, Default)]
pub struct SecurityMetrics {
    /// Total events
    pub total_events: u64,
    /// Threats detected
    pub threats_detected: u64,
    /// Peers blocked (exiled)
    pub peers_blocked: u64,
    /// Pack coordinations
    pub pack_coordinations: u64,
    /// Average trust level in pack
    pub avg_trust_level: f64,
    /// Territory breaches
    pub territory_breaches: u64,
    /// Lone wolf sightings
    pub lone_wolf_sightings: u64,
}

impl ThreatDetectionManager {
    /// Create a new threat detection manager
    pub fn new(config: ThreatDetectionConfig) -> Self {
        Self {
            peers: HashMap::new(),
            events: Vec::new(),
            threats: Vec::new(),
            config,
            metrics: SecurityMetrics::default(),
        }
    }

    /// Handle a new peer joining the pack
    pub fn handle_peer_connected(&mut self, peer_id: PeerId) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4().to_string(),
            event_type: SecurityEventType::PeerConnected,
            source: Some(peer_id),
            target: None,
            severity: ThreatSeverity::Low,
            timestamp: Utc::now(),
            description: format!("New wolf joined the pack: {}", peer_id),
            data: HashMap::new(),
        };

        self.add_event(event.clone())?;

        // Initialize peer info if not exists
        if !self.peers.contains_key(&peer_id) {
            let peer_info = PeerInfo {
                peer_id,
                trust_level: 0.5, // Start with neutral trust
                reputation: 0,
                last_seen: Utc::now(),
                connection_count: 1,
                flags: PeerFlags::default(),
            };
            self.peers.insert(peer_id, peer_info);
        } else {
            // Update existing peer
            if let Some(peer_info) = self.peers.get_mut(&peer_id) {
                peer_info.connection_count += 1;
                peer_info.last_seen = Utc::now();
            }
        }

        Ok(())
    }

    /// Handle peer leaving the pack
    pub fn handle_peer_disconnected(&mut self, peer_id: PeerId) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4().to_string(),
            event_type: SecurityEventType::PeerDisconnected,
            source: Some(peer_id),
            target: None,
            severity: ThreatSeverity::Low,
            timestamp: Utc::now(),
            description: format!("Wolf left the pack: {}", peer_id),
            data: HashMap::new(),
        };

        self.add_event(event)
    }

    /// Handle suspicious wolf behavior
    pub fn handle_suspicious_activity(
        &mut self,
        peer_id: PeerId,
        description: String,
    ) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4().to_string(),
            event_type: SecurityEventType::SuspiciousActivity,
            source: Some(peer_id),
            target: None,
            severity: ThreatSeverity::Medium,
            timestamp: Utc::now(),
            description: description.clone(),
            data: HashMap::new(),
        };

        self.add_event(event.clone())?;

        // Decrease trust level
        if let Some(peer_info) = self.peers.get_mut(&peer_id) {
            peer_info.trust_level = (peer_info.trust_level - 0.1).max(0.0);
            peer_info.flags.suspicious = true;

            // Check if threshold reached
            if peer_info.trust_level < self.config.threat_threshold {
                self.create_threat(peer_id, ThreatType::MaliciousPeer, description)?;
            }
        }

        Ok(())
    }

    /// Handle authentication failure (unknown wolf)
    pub fn handle_auth_failure(&mut self, peer_id: PeerId, reason: String) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4().to_string(),
            event_type: SecurityEventType::AuthFailure,
            source: Some(peer_id),
            target: None,
            severity: ThreatSeverity::High,
            timestamp: Utc::now(),
            description: format!("Authentication failed for wolf {}: {}", peer_id, reason),
            data: HashMap::from([("reason".to_string(), reason)]),
        };

        self.add_event(event.clone())?;

        // Significantly decrease trust
        if let Some(peer_info) = self.peers.get_mut(&peer_id) {
            peer_info.trust_level = (peer_info.trust_level - 0.3).max(0.0);
            peer_info.reputation = peer_info.reputation.saturating_sub(10);
        }

        Ok(())
    }

    /// Handle pack coordination howl
    pub fn handle_pack_coordination(&mut self, peer_id: PeerId, message: String) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4().to_string(),
            event_type: SecurityEventType::PackCoordination,
            source: Some(peer_id),
            target: None,
            severity: ThreatSeverity::Low,
            timestamp: Utc::now(),
            description: format!("Pack coordination howl from {}: {}", peer_id, message),
            data: HashMap::from([("message".to_string(), message)]),
        };

        self.add_event(event.clone())?;

        // Mark as pack member if trusted
        if let Some(peer_info) = self.peers.get_mut(&peer_id) {
            if peer_info.trust_level > 0.7 {
                peer_info.flags.pack_member = true;
                self.metrics.pack_coordinations += 1;
            }
        }

        Ok(())
    }

    /// Handle territory breach
    pub fn handle_territory_breach(&mut self, peer_id: PeerId, location: String) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4().to_string(),
            event_type: SecurityEventType::TerritoryBreach,
            source: Some(peer_id),
            target: None,
            severity: ThreatSeverity::Medium,
            timestamp: Utc::now(),
            description: format!("Territory breach by wolf {} at {}", peer_id, location),
            data: HashMap::from([("location".to_string(), location)]),
        };

        self.add_event(event.clone())?;
        self.metrics.territory_breaches += 1;

        // Decrease trust for territory violations
        if let Some(peer_info) = self.peers.get_mut(&peer_id) {
            peer_info.trust_level = (peer_info.trust_level - 0.15).max(0.0);
        }

        Ok(())
    }

    /// Handle lone wolf activity
    pub fn handle_lone_wolf_activity(&mut self, peer_id: PeerId, activity: String) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4().to_string(),
            event_type: SecurityEventType::LoneWolfActivity,
            source: Some(peer_id),
            target: None,
            severity: ThreatSeverity::Medium,
            timestamp: Utc::now(),
            description: format!("Lone wolf activity detected from {}: {}", peer_id, activity),
            data: HashMap::from([("activity".to_string(), activity)]),
        };

        self.add_event(event.clone())?;
        self.metrics.lone_wolf_sightings += 1;

        Ok(())
    }

    /// Add a security event
    fn add_event(&mut self, event: SecurityEvent) -> Result<()> {
        self.events.push(event.clone());
        self.metrics.total_events += 1;

        // Keep only recent events (last 1000)
        if self.events.len() > 1000 {
            self.events.remove(0);
        }

        Ok(())
    }

    /// Create a new threat
    fn create_threat(
        &mut self,
        source: PeerId,
        threat_type: ThreatType,
        description: String,
    ) -> Result<()> {
        let threat = Threat {
            id: Uuid::new_v4().to_string(),
            threat_type,
            source: Some(source),
            severity: ThreatSeverity::High,
            status: ThreatStatus::Active,
            detected_at: Utc::now(),
            updated_at: Utc::now(),
            description,
            actions: vec![
                "Monitor wolf activity".to_string(),
                "Alert pack members".to_string(),
                "Consider exile if threat persists".to_string(),
                "Coordinate pack defense".to_string(),
            ],
        };

        self.threats.push(threat.clone());
        self.metrics.threats_detected += 1;

        // Auto-response if enabled
        if self.config.auto_response {
            self.respond_to_threat(&threat)?;
        }

        Ok(())
    }

    /// Respond to a threat with pack coordination
    fn respond_to_threat(&mut self, threat: &Threat) -> Result<()> {
        match threat.threat_type {
            ThreatType::MaliciousPeer => {
                if let Some(peer_id) = threat.source {
                    if let Some(peer_info) = self.peers.get_mut(&peer_id) {
                        peer_info.flags.blocked = true;
                        self.metrics.peers_blocked += 1;
                    }
                }
            }
            ThreatType::MessageFlooding => {
                // Implement howl rate limiting
            }
            ThreatType::SybilAttack => {
                // Implement sybil detection
            }
            ThreatType::TerritoryInvasion => {
                // Coordinate pack defense
            }
            _ => {}
        }
        Ok(())
    }

    /// Get peer information
    pub fn get_peer_info(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Get recent events
    pub fn get_recent_events(&self, limit: usize) -> &[SecurityEvent] {
        let start = self.events.len().saturating_sub(limit);
        &self.events[start..]
    }

    /// Get active threats
    pub fn get_active_threats(&self) -> &[Threat] {
        &self.threats
    }

    /// Get security metrics
    pub fn get_metrics(&self) -> &SecurityMetrics {
        &self.metrics
    }

    /// Update trust levels based on time (wolf pack dynamics)
    pub fn update_trust_levels(&mut self) {
        let now = Utc::now();
        let decay_rate = self.config.trust_decay_rate / 3600.0; // Per second

        for peer_info in self.peers.values_mut() {
            let hours_elapsed = (now - peer_info.last_seen).num_seconds() as f64 / 3600.0;
            let decay = decay_rate * hours_elapsed;
            peer_info.trust_level = (peer_info.trust_level - decay).max(0.0);
        }

        // Update average trust level
        if !self.peers.is_empty() {
            let total_trust: f64 = self.peers.values().map(|p| p.trust_level).sum();
            self.metrics.avg_trust_level = total_trust / self.peers.len() as f64;
        }
    }

    /// Get pack status summary
    pub fn get_pack_status(&self) -> PackStatus {
        let total_wolves = self.peers.len();
        let trusted_wolves = self.peers.values().filter(|p| p.trust_level > 0.7).count();
        let suspicious_wolves = self.peers.values().filter(|p| p.flags.suspicious).count();
        let blocked_wolves = self.peers.values().filter(|p| p.flags.blocked).count();
        let pack_members = self.peers.values().filter(|p| p.flags.pack_member).count();

        PackStatus {
            total_wolves,
            trusted_wolves,
            suspicious_wolves,
            blocked_wolves,
            pack_members,
            active_threats: self.threats.len(),
            pack_health: if total_wolves > 0 {
                (trusted_wolves as f64 / total_wolves as f64) * 100.0
            } else {
                0.0
            },
        }
    }
}

/// Pack status summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackStatus {
    /// Total wolves in pack
    pub total_wolves: usize,
    /// Trusted wolves
    pub trusted_wolves: usize,
    /// Suspicious wolves
    pub suspicious_wolves: usize,
    /// Blocked wolves (exiled)
    pub blocked_wolves: usize,
    /// Pack members
    pub pack_members: usize,
    /// Active threats
    pub active_threats: usize,
    /// Overall pack health percentage
    pub pack_health: f64,
}

impl Default for ThreatDetectionConfig {
    fn default() -> Self {
        Self {
            threat_threshold: 0.3,
            auto_response: true,
            pack_coordination: true,
            max_connection_rate: 10,
            message_rate_limit: 100,
            trust_decay_rate: 0.01, // 1% per hour
            enable_pack_hunting: true,
            territory_monitoring: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_detection_manager_creation() {
        let config = ThreatDetectionConfig::default();
        let manager = ThreatDetectionManager::new(config);

        assert_eq!(manager.peers.len(), 0);
        assert_eq!(manager.events.len(), 0);
        assert_eq!(manager.threats.len(), 0);
    }

    #[test]
    fn test_peer_connection_handling() {
        let mut manager = ThreatDetectionManager::new(ThreatDetectionConfig::default());
        let peer_id = PeerId::random();

        manager.handle_peer_connected(peer_id).unwrap();

        assert_eq!(manager.peers.len(), 1);
        assert_eq!(manager.events.len(), 1);
        assert!(manager.peers.contains_key(&peer_id));

        let peer_info = manager.get_peer_info(&peer_id).unwrap();
        assert_eq!(peer_info.connection_count, 1);
        assert_eq!(peer_info.trust_level, 0.5);
    }

    #[test]
    fn test_suspicious_activity_handling() {
        let mut manager = ThreatDetectionManager::new(ThreatDetectionConfig::default());
        let peer_id = PeerId::random();

        // First add peer
        manager.handle_peer_connected(peer_id).unwrap();

        // Handle suspicious activity
        manager
            .handle_suspicious_activity(peer_id, "Unusual howling pattern detected".to_string())
            .unwrap();

        let peer_info = manager.get_peer_info(&peer_id).unwrap();
        assert_eq!(peer_info.trust_level, 0.4); // Decreased by 0.1
        assert!(peer_info.flags.suspicious);
    }

    #[test]
    fn test_auth_failure_handling() {
        let mut manager = ThreatDetectionManager::new(ThreatDetectionConfig::default());
        let peer_id = PeerId::random();

        manager.handle_peer_connected(peer_id).unwrap();
        manager
            .handle_auth_failure(peer_id, "Invalid howl signature".to_string())
            .unwrap();

        let peer_info = manager.get_peer_info(&peer_id).unwrap();
        assert_eq!(peer_info.trust_level, 0.2); // Decreased by 0.3
        assert_eq!(peer_info.reputation, -10);
    }

    #[test]
    fn test_pack_coordination() {
        let mut manager = ThreatDetectionManager::new(ThreatDetectionConfig::default());
        let peer_id = PeerId::random();

        manager.handle_peer_connected(peer_id).unwrap();

        // Increase trust level first
        if let Some(peer_info) = manager.peers.get_mut(&peer_id) {
            peer_info.trust_level = 0.8;
        }

        manager
            .handle_pack_coordination(peer_id, "Hunting formation requested".to_string())
            .unwrap();

        let peer_info = manager.get_peer_info(&peer_id).unwrap();
        assert!(peer_info.flags.pack_member);
        assert_eq!(manager.metrics.pack_coordinations, 1);
    }

    #[test]
    fn test_territory_breach() {
        let mut manager = ThreatDetectionManager::new(ThreatDetectionConfig::default());
        let peer_id = PeerId::random();

        manager.handle_peer_connected(peer_id).unwrap();
        manager
            .handle_territory_breach(peer_id, "Northern boundary".to_string())
            .unwrap();

        assert_eq!(manager.metrics.territory_breaches, 1);

        let peer_info = manager.get_peer_info(&peer_id).unwrap();
        assert_eq!(peer_info.trust_level, 0.35); // Decreased by 0.15
    }

    #[test]
    fn test_lone_wolf_activity() {
        let mut manager = ThreatDetectionManager::new(ThreatDetectionConfig::default());
        let peer_id = PeerId::random();

        manager.handle_peer_connected(peer_id).unwrap();
        manager
            .handle_lone_wolf_activity(peer_id, "Solo hunting detected".to_string())
            .unwrap();

        assert_eq!(manager.metrics.lone_wolf_sightings, 1);
    }

    #[test]
    fn test_trust_level_decay() {
        let mut manager = ThreatDetectionManager::new(ThreatDetectionConfig::default());
        let peer_id = PeerId::random();

        manager.handle_peer_connected(peer_id).unwrap();

        // Simulate time passing
        std::thread::sleep(Duration::from_millis(10));

        manager.update_trust_levels();

        // Trust should have decayed slightly
        let peer_info = manager.get_peer_info(&peer_id).unwrap();
        assert!(peer_info.trust_level < 0.5);
    }

    #[test]
    fn test_pack_status() {
        let mut manager = ThreatDetectionManager::new(ThreatDetectionConfig::default());

        // Add multiple peers
        for _ in 0..5 {
            let peer_id = PeerId::random();
            manager.handle_peer_connected(peer_id).unwrap();
        }

        let status = manager.get_pack_status();
        assert_eq!(status.total_wolves, 5);
        assert_eq!(status.active_threats, 0);
        assert!(status.pack_health > 0.0);
    }

    #[test]
    fn test_threat_severity_ordering() {
        assert!(ThreatSeverity::Critical > ThreatSeverity::High);
        assert!(ThreatSeverity::High > ThreatSeverity::Medium);
        assert!(ThreatSeverity::Medium > ThreatSeverity::Low);
    }
}
