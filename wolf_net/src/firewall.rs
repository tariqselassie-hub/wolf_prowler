use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Main Firewall Manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalFirewall {
    /// Active firewall rules.
    pub rules: Vec<FirewallRule>,
    /// Default policy when no rules match.
    pub policy: FirewallPolicy,
    /// Master switch for the firewall.
    pub enabled: bool,
}

impl InternalFirewall {
    /// Creates a new `InternalFirewall` instance with default policy.
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            policy: FirewallPolicy::Default,
            enabled: true,
        }
    }

    /// Add a new rule to the firewall
    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
    }

    /// Remove rules by port (simple convenience method)
    pub fn remove_rule_by_port(&mut self, port: u16) {
        self.rules.retain(|rule| match rule.target {
            RuleTarget::Port(p) => p != port,
            _ => true,
        });
    }

    /// Set the default policy
    pub fn set_policy(&mut self, policy: FirewallPolicy) {
        self.policy = policy;
    }

    /// Check if a packet should be allowed based on current rules
    /// Returns true if allowed, false if denied
    pub fn check_access(
        &self,
        target: &RuleTarget,
        protocol: &Protocol,
        direction: &TrafficDirection,
    ) -> bool {
        if !self.enabled {
            return true;
        }

        // Iterate through rules to find a match
        for rule in &self.rules {
            if rule.matches(target, protocol, direction) {
                match rule.action {
                    Action::Allow => return true,
                    Action::Deny => return false,
                }
            }
        }

        // If no rule matches, fallback to default policy
        match self.policy {
            FirewallPolicy::Default | FirewallPolicy::AllowAll => true,
            FirewallPolicy::DenyAll => false,
        }
    }
}

impl Default for InternalFirewall {
    fn default() -> Self {
        Self::new()
    }
}

/// Default policy when no specific rule matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallPolicy {
    /// Context‑dependent default (usually Allow).
    Default,
    /// Allow all traffic that doesn't match a Deny rule.
    AllowAll,
    /// Deny all traffic that doesn't match an Allow rule.
    DenyAll,
}

/// A single firewall rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Human‑readable name for the rule.
    pub name: String,
    /// The target of this rule (Port, IP, PeerID, or Any).
    pub target: RuleTarget,
    /// The protocol this rule applies to.
    pub protocol: Protocol,
    /// The action to take on a match.
    pub action: Action,
    /// The traffic direction this rule applies to.
    pub direction: TrafficDirection,
}

impl FirewallRule {
    /// Creates a new `FirewallRule` with the specified parameters.
    pub fn new(
        name: impl Into<String>,
        target: RuleTarget,
        protocol: Protocol,
        action: Action,
        direction: TrafficDirection,
    ) -> Self {
        Self {
            name: name.into(),
            target,
            protocol,
            action,
            direction,
        }
    }

    /// Check if this rule applies to the given traffic
    pub fn matches(
        &self,
        target: &RuleTarget,
        protocol: &Protocol,
        direction: &TrafficDirection,
    ) -> bool {
        // Check direction
        if self.direction != TrafficDirection::Both && self.direction != *direction {
            return false;
        }

        // Check protocol
        if self.protocol != Protocol::Any && self.protocol != *protocol {
            return false;
        }

        // Check target (Port, IP, PeerID)
        // Simple equality for now, could be range or subnet later
        if self.target != RuleTarget::Any && self.target != *target {
            return false;
        }

        true
    }
}

/// Specific target for the rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleTarget {
    /// Applies to any target.
    Any,
    /// Applies to a specific network port.
    Port(u16),
    /// Applies to a specific IP address.
    Ip(IpAddr),
    /// Applies to a specific peer identifier.
    PeerId(String),
}

/// Action to take on match
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Permit the traffic.
    Allow,
    /// Block the traffic.
    Deny,
}

/// Network Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    /// Any supported protocol.
    Any,
    /// Transmission Control Protocol.
    TCP,
    /// User Datagram Protocol.
    UDP,
    /// Internet Control Message Protocol.
    ICMP,
    /// Custom Wolf application protocol.
    WolfProto,
}

/// Traffic Direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficDirection {
    /// Incoming traffic.
    Inbound,
    /// Outgoing traffic.
    Outbound,
    /// Both directions.
    Both,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let mut manager = InternalFirewall::new();
        // Default is usually allow/true in my impl for now
        assert!(manager.check_access(&RuleTarget::Any, &Protocol::Any, &TrafficDirection::Inbound));

        manager.set_policy(FirewallPolicy::DenyAll);
        assert!(!manager.check_access(
            &RuleTarget::Any,
            &Protocol::Any,
            &TrafficDirection::Inbound
        ));
    }

    #[test]
    fn test_deny_peer_id() {
        let mut manager = InternalFirewall::new();
        let peer_id = "12D3KooWPjceQrSwdWXPyxfrR8mgjtr3G5Qw4h5z4"; // Example PeerID

        // Add deny rule
        manager.add_rule(FirewallRule::new(
            "Deny Malicious Peer",
            RuleTarget::PeerId(peer_id.to_string()),
            Protocol::Any,
            Action::Deny,
            TrafficDirection::Inbound,
        ));

        // Check access for that peer
        let target = RuleTarget::PeerId(peer_id.to_string());
        assert!(!manager.check_access(&target, &Protocol::WolfProto, &TrafficDirection::Inbound));

        // Check access for another peer (should fall through to default Allow)
        let safe_peer = RuleTarget::PeerId("12D3KooWOtherPeer".to_string());
        assert!(manager.check_access(&safe_peer, &Protocol::WolfProto, &TrafficDirection::Inbound));
    }

    #[test]
    fn test_direction_matching() {
        let mut manager = InternalFirewall::new();
        manager.set_policy(FirewallPolicy::AllowAll); // Default allow

        // Deny OUTBOUND specifically
        manager.add_rule(FirewallRule::new(
            "Deny Outbound",
            RuleTarget::Any,
            Protocol::Any,
            Action::Deny,
            TrafficDirection::Outbound,
        ));

        // Inbound should pass (no match, default allow)
        assert!(manager.check_access(&RuleTarget::Any, &Protocol::Any, &TrafficDirection::Inbound));

        // Outbound should fail (rule match)
        assert!(!manager.check_access(
            &RuleTarget::Any,
            &Protocol::Any,
            &TrafficDirection::Outbound
        ));
    }
}
