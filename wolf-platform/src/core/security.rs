//! Security management for Wolf Prowler

use anyhow::Result;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Security manager for threat detection and response
pub struct SecurityManager {
    /// Known peers and their trust levels
    peers: HashMap<PeerId, PeerInfo>,
    /// Current security events
    events: Vec<SecurityEvent>,
    /// Active threats
    threats: Vec<Threat>,
    /// Configuration
    config: SecurityConfig,
    /// Metrics collector
    metrics: SecurityMetrics,
}

/// Information about a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Trust level (0.0 to 1.0)
    pub trust_level: f64,
    /// Reputation score
    pub reputation: i32,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Connection count
    pub connection_count: u32,
    /// Security flags
    pub flags: PeerFlags,
}

/// Security flags for peers
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerFlags {
    /// Peer is verified
    pub verified: bool,
    /// Peer has been suspicious
    pub suspicious: bool,
    /// Peer is blocked
    pub blocked: bool,
    /// Peer is part of pack
    pub pack_member: bool,
}

/// Security event
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
    pub severity: Severity,
    /// Timestamp
    pub timestamp: Instant,
    /// Description
    pub description: String,
    /// Additional data
    pub data: HashMap<String, String>,
}

/// Types of security events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    /// Connection established
    PeerConnected,
    /// Connection lost
    PeerDisconnected,
    /// Suspicious activity detected
    SuspiciousActivity,
    /// Authentication failure
    AuthFailure,
    /// Message signature invalid
    InvalidSignature,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Pack coordination request
    PackCoordination,
    /// Threat alert
    ThreatAlert,
    /// Howl communication
    HowlCommunication,
}

/// Severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Threat information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Threat ID
    pub id: String,
    /// Threat type
    pub threat_type: ThreatType,
    /// Source peer (if known)
    pub source: Option<PeerId>,
    /// Severity
    pub severity: Severity,
    /// Status
    pub status: ThreatStatus,
    /// Detection time
    pub detected_at: Instant,
    /// Last updated
    pub updated_at: Instant,
    /// Description
    pub description: String,
    /// Recommended actions
    pub actions: Vec<String>,
}

/// Types of threats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    /// Malicious peer
    MaliciousPeer,
    /// Sybil attack
    SybilAttack,
    /// Message flooding
    MessageFlooding,
    /// Impersonation
    Impersonation,
    /// Network partition
    NetworkPartition,
    /// Pack infiltration
    PackInfiltration,
    /// Unknown threat
    Unknown,
}

/// Threat status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatStatus {
    /// Active threat
    Active,
    /// Being investigated
    Investigating,
    /// Contained
    Contained,
    /// Resolved
    Resolved,
    /// False positive
    FalsePositive,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Threshold for threat detection
    pub threat_threshold: f64,
    /// Enable automatic threat response
    pub auto_response: bool,
    /// Pack coordination enabled
    pub pack_coordination: bool,
    /// Maximum connection rate per peer
    pub max_connection_rate: u32,
    /// Message rate limit
    pub message_rate_limit: u32,
    /// Trust decay rate per hour
    pub trust_decay_rate: f64,
}

/// Security metrics
#[derive(Debug, Clone, Default)]
pub struct SecurityMetrics {
    /// Total events
    pub total_events: u64,
    /// Threats detected
    pub threats_detected: u64,
    /// Peers blocked
    pub peers_blocked: u64,
    /// Pack coordinations
    pub pack_coordinations: u64,
    /// Average trust level
    pub avg_trust_level: f64,
}

impl SecurityManager {
    /// Create a new security manager
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            peers: HashMap::new(),
            events: Vec::new(),
            threats: Vec::new(),
            config,
            metrics: SecurityMetrics::default(),
        }
    }

    /// Handle a new peer connection
    pub fn handle_peer_connected(&mut self, peer_id: PeerId) -> Result<()> {
        let event = SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: SecurityEventType::PeerConnected,
            source: Some(peer_id),
            target: None,
            severity: Severity::Low,
            timestamp: Instant::now(),
            description: format!("New peer connected: {}", peer_id),
            data: HashMap::new(),
        };

        self.add_event(event.clone())?;

        // Initialize peer info if not exists
        if !self.peers.contains_key(&peer_id) {
            let peer_info = PeerInfo {
                peer_id,
                trust_level: 0.5, // Start with neutral trust
                reputation: 0,
                last_seen: Instant::now(),
                connection_count: 1,
                flags: PeerFlags::default(),
            };
            self.peers.insert(peer_id, peer_info);
        } else {
            // Update existing peer
            if let Some(peer_info) = self.peers.get_mut(&peer_id) {
                peer_info.connection_count += 1;
                peer_info.last_seen = Instant::now();
            }
        }

        Ok(())
    }

    /// Handle peer disconnection
    pub fn handle_peer_disconnected(&mut self, peer_id: PeerId) -> Result<()> {
        let event = SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: SecurityEventType::PeerDisconnected,
            source: Some(peer_id),
            target: None,
            severity: Severity::Low,
            timestamp: Instant::now(),
            description: format!("Peer disconnected: {}", peer_id),
            data: HashMap::new(),
        };

        self.add_event(event)
    }

    /// Handle suspicious activity
    pub fn handle_suspicious_activity(
        &mut self,
        peer_id: PeerId,
        description: String,
    ) -> Result<()> {
        let event = SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: SecurityEventType::SuspiciousActivity,
            source: Some(peer_id),
            target: None,
            severity: Severity::Medium,
            timestamp: Instant::now(),
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

    /// Handle authentication failure
    pub fn handle_auth_failure(&mut self, peer_id: PeerId, reason: String) -> Result<()> {
        let event = SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: SecurityEventType::AuthFailure,
            source: Some(peer_id),
            target: None,
            severity: Severity::High,
            timestamp: Instant::now(),
            description: format!("Authentication failed for {}: {}", peer_id, reason),
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

    /// Handle pack coordination
    pub fn handle_pack_coordination(&mut self, peer_id: PeerId, message: String) -> Result<()> {
        let event = SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: SecurityEventType::PackCoordination,
            source: Some(peer_id),
            target: None,
            severity: Severity::Low,
            timestamp: Instant::now(),
            description: format!("Pack coordination from {}: {}", peer_id, message),
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
            id: uuid::Uuid::new_v4().to_string(),
            threat_type,
            source: Some(source),
            severity: Severity::High,
            status: ThreatStatus::Active,
            detected_at: Instant::now(),
            updated_at: Instant::now(),
            description,
            actions: vec![
                "Monitor peer activity".to_string(),
                "Consider blocking if threat persists".to_string(),
                "Alert pack members".to_string(),
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

    /// Respond to a threat
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
                // Implement rate limiting
            }
            ThreatType::SybilAttack => {
                // Implement sybil detection
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

    /// Update trust levels based on time
    pub fn update_trust_levels(&mut self) {
        let now = Instant::now();
        let decay_rate = self.config.trust_decay_rate / 3600.0; // Per second

        for peer_info in self.peers.values_mut() {
            let hours_elapsed = now.duration_since(peer_info.last_seen).as_secs() as f64 / 3600.0;
            let decay = decay_rate * hours_elapsed;
            peer_info.trust_level = (peer_info.trust_level - decay).max(0.0);
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            threat_threshold: 0.3,
            auto_response: true,
            pack_coordination: true,
            max_connection_rate: 10,
            message_rate_limit: 100,
            trust_decay_rate: 0.01, // 1% per hour
        }
    }
}
