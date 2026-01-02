//! Proposal Types
//!
//! Defines the types of changes that can be proposed to the cluster.

use serde::{Deserialize, Serialize};

use crate::consensus::state::{DeviceInfo, FirewallRule, ThreatEntry};
use crate::PeerId;

/// Proposal types that can be submitted to the cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Proposal {
    /// Add or update a threat in the distributed database
    AddThreat {
        threat: ThreatEntry,
        proposer: u64,
    },
    
    /// Add a firewall rule to be synchronized across all nodes
    AddFirewallRule {
        rule: FirewallRule,
        proposer: u64,
    },
    
    /// Update peer trust score
    UpdateTrustScore {
        peer_id: PeerId,
        score: f64,
        proposer: u64,
    },
    
    /// Add discovered device to territory map
    AddDevice {
        device: DeviceInfo,
        proposer: u64,
    },
    
    /// Remove threat (e.g., false positive)
    RemoveThreat {
        threat_id: String,
        proposer: u64,
    },
}

impl Proposal {
    /// Get the proposer node ID
    pub fn proposer(&self) -> u64 {
        match self {
            Proposal::AddThreat { proposer, .. } => *proposer,
            Proposal::AddFirewallRule { proposer, .. } => *proposer,
            Proposal::UpdateTrustScore { proposer, .. } => *proposer,
            Proposal::AddDevice { proposer, .. } => *proposer,
            Proposal::RemoveThreat { proposer, .. } => *proposer,
        }
    }

    /// Get a human-readable description of the proposal
    pub fn description(&self) -> String {
        match self {
            Proposal::AddThreat { threat, .. } => {
                format!("Add threat: {} ({})", threat.id, threat.ip)
            }
            Proposal::AddFirewallRule { rule, .. } => {
                format!("Add firewall rule: {:?}", rule.action)
            }
            Proposal::UpdateTrustScore { peer_id, score, .. } => {
                format!("Update trust score for {:?}: {:.2}", peer_id, score)
            }
            Proposal::AddDevice { device, .. } => {
                format!("Add device: {}", device.ip)
            }
            Proposal::RemoveThreat { threat_id, .. } => {
                format!("Remove threat: {}", threat_id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::state::{ThreatEntry, ThreatSeverity};
    use chrono::Utc;

    #[test]
    fn test_proposal_proposer() {
        let threat = ThreatEntry {
            id: "test".to_string(),
            ip: "192.168.1.1".parse().unwrap(),
            severity: ThreatSeverity::High,
            detected_by: vec![1],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            blocked: false,
        };

        let proposal = Proposal::AddThreat {
            threat,
            proposer: 42,
        };

        assert_eq!(proposal.proposer(), 42);
    }

    #[test]
    fn test_proposal_description() {
        let threat = ThreatEntry {
            id: "threat-123".to_string(),
            ip: "192.168.1.100".parse().unwrap(),
            severity: ThreatSeverity::Critical,
            detected_by: vec![1],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            blocked: false,
        };

        let proposal = Proposal::AddThreat {
            threat,
            proposer: 1,
        };

        let desc = proposal.description();
        assert!(desc.contains("threat-123"));
        assert!(desc.contains("192.168.1.100"));
    }
}
