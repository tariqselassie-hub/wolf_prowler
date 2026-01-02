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
    pub fn threat_count(&self) -> usize {
        self.threats.len()
    }

    /// Get firewall rule count
    pub fn firewall_rule_count(&self) -> usize {
        self.firewall_rules.len()
    }

    /// Get territory device count
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
    pub id: String,
    pub ip: IpAddr,
    pub severity: ThreatSeverity,
    pub detected_by: Vec<u64>,  // Node IDs
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub blocked: bool,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub action: FirewallAction,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub reason: String,
}

/// Firewall action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirewallAction {
    Allow,
    Block,
    Log,
}

/// Trust score for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub score: f64,
    pub last_updated: DateTime<Utc>,
    pub updated_by: u64,  // Node ID
}

/// Device information for territory mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub device_type: String,
    pub first_seen: DateTime<Utc>,
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
