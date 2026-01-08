//! Shared State Machine
//!
//! Defines the replicated state shared across all nodes in the cluster.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use chrono::{DateTime, Utc};

use crate::consensus::proposals::Proposal;
use crate::PeerId;

/// Shared state replicated across the cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedState {
    /// Distributed threat database
    pub threats: HashMap<String, ThreatEntry>,
    
    /// Synchronized firewall rules
    pub firewall_rules: Vec<FirewallRule>,
    
    /// Peer trust scores
    pub trust_scores: HashMap<PeerId, TrustScore>,
    
    /// Territory mapping (discovered devices)
    pub territory: HashMap<IpAddr, DeviceInfo>,
    
    /// Last applied log index
    pub last_applied: u64,
}

impl SharedState {
    /// Create new empty state
    #[must_use]
    pub fn new() -> Self {
        Self {
            threats: HashMap::new(),
            firewall_rules: Vec::new(),
            trust_scores: HashMap::new(),
            territory: HashMap::new(),
            last_applied: 0,
        }
    }

    /// Apply a proposal to the state machine
    ///
    /// # Errors
    /// Returns an error if the proposal cannot be applied (currently always returns Ok).
    pub fn apply(&mut self, proposal: Proposal) -> Result<()> {
        match proposal {
            Proposal::AddThreat { threat, proposer } => {
                tracing::info!(
                    "Node {} proposed threat: {} ({})",
                    proposer,
                    threat.id,
                    threat.ip
                );
                
                // Merge if exists, otherwise insert
                self.threats
                    .entry(threat.id.clone())
                    .and_modify(|existing| {
                        if !existing.detected_by.contains(&proposer) {
                            existing.detected_by.push(proposer);
                        }
                        existing.last_seen = threat.last_seen;
                    })
                    .or_insert(threat);
            }
            
            Proposal::AddFirewallRule { rule, proposer } => {
                tracing::info!("Node {} proposed firewall rule", proposer);
                self.firewall_rules.push(rule);
            }
            
            Proposal::UpdateTrustScore { peer_id, score, proposer } => {
                tracing::debug!("Node {} updated trust score for {:?}", proposer, peer_id);
                self.trust_scores.insert(
                    peer_id,
                    TrustScore {
                        score,
                        last_updated: Utc::now(),
                        updated_by: proposer,
                    },
                );
            }
            
            Proposal::AddDevice { device, proposer } => {
                tracing::debug!("Node {} added device: {}", proposer, device.ip);
                self.territory.insert(device.ip, device);
            }
            
            Proposal::RemoveThreat { threat_id, proposer } => {
                tracing::info!("Node {} removed threat: {}", proposer, threat_id);
                self.threats.remove(&threat_id);
            }
        }
        
        Ok(())
    }

    /// Get threat count
    #[must_use]
    pub fn threat_count(&self) -> usize {
        self.threats.len()
    }

    /// Get firewall rule count
    #[must_use]
    pub fn firewall_rule_count(&self) -> usize {
        self.firewall_rules.len()
    }

    /// Get territory device count
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.territory.len()
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

/// Threat entry in distributed database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    /// Unique identifier for the threat.
    pub id: String,
    /// IP address associated with the threat.
    pub ip: IpAddr,
    /// Severity level of the threat.
    pub severity: ThreatSeverity,
    /// List of node IDs that detected this threat.
    pub detected_by: Vec<u64>,
    /// Timestamp when the threat was first seen.
    pub first_seen: DateTime<Utc>,
    /// Timestamp when the threat was last seen.
    pub last_seen: DateTime<Utc>,
    /// Whether the threat has been blocked by the firewall.
    pub blocked: bool,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatSeverity {
    /// Low severity threat.
    Low,
    /// Medium severity threat.
    Medium,
    /// High severity threat.
    High,
    /// Critical severity threat.
    Critical,
}

/// Firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Action to take on matching traffic.
    pub action: FirewallAction,
    /// Optional source IP to match.
    pub source_ip: Option<IpAddr>,
    /// Optional destination IP to match.
    pub destination_ip: Option<IpAddr>,
    /// Optional destination port to match.
    pub port: Option<u16>,
    /// Rationale for the firewall rule.
    pub reason: String,
}

/// Firewall action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirewallAction {
    /// Permit the traffic.
    Allow,
    /// Block the traffic.
    Block,
    /// Allow the traffic but record the event.
    Log,
}

/// Trust score for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Numerical trust score value.
    pub score: f64,
    /// Timestamp when the score was last updated.
    pub last_updated: DateTime<Utc>,
    /// ID of the node that last updated this score.
    pub updated_by: u64,
}

/// Device information for territory mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// IP address of the discovered device.
    pub ip: IpAddr,
    /// Optional hostname of the device.
    pub hostname: Option<String>,
    /// Optional MAC address of the device.
    pub mac_address: Option<String>,
    /// Classified type of the device.
    pub device_type: String,
    /// Timestamp when the device was first discovered.
    pub first_seen: DateTime<Utc>,
    /// Timestamp when the device was last seen online.
    pub last_seen: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_state_creation() {
        let state = SharedState::new();
        assert_eq!(state.threat_count(), 0);
        assert_eq!(state.firewall_rule_count(), 0);
        assert_eq!(state.device_count(), 0);
    }

    #[test]
    fn test_apply_add_threat() {
        let mut state = SharedState::new();
        
        let threat = ThreatEntry {
            id: "threat-1".to_string(),
            ip: "192.168.1.100".parse().unwrap(),
            severity: ThreatSeverity::High,
            detected_by: vec![1],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            blocked: false,
        };

        let proposal = Proposal::AddThreat {
            threat: threat.clone(),
            proposer: 1,
        };

        state.apply(proposal).unwrap();
        assert_eq!(state.threat_count(), 1);
        assert!(state.threats.contains_key("threat-1"));
    }

    #[test]
    fn test_apply_add_firewall_rule() {
        let mut state = SharedState::new();
        
        let rule = FirewallRule {
            action: FirewallAction::Block,
            source_ip: Some("192.168.1.100".parse().unwrap()),
            destination_ip: None,
            port: None,
            reason: "Test block".to_string(),
        };

        let proposal = Proposal::AddFirewallRule {
            rule: rule.clone(),
            proposer: 1,
        };

        state.apply(proposal).unwrap();
        assert_eq!(state.firewall_rule_count(), 1);
    }
}
