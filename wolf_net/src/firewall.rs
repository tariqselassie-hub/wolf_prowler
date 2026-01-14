use chrono::{DateTime, Utc};
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
            policy: FirewallPolicy::DenyAll, // Implicit deny-by-default
            enabled: true,
        }
    }

    /// Add a new rule to the firewall
    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
        // Sort by priority (lower number = higher priority)
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Remove rules by port (simple convenience method)
    pub fn remove_rule_by_port(&mut self, port: u16) {
        self.rules.retain(|rule| match &rule.target {
            RuleTarget::Port(p) => p != &port,
            RuleTarget::PortRange(start, end) => !(port >= *start && port <= *end),
            _ => true,
        });
    }

    /// Remove expired rules
    pub fn cleanup_expired_rules(&mut self) -> usize {
        let before = self.rules.len();
        self.rules.retain(|rule| !rule.is_expired());
        before - self.rules.len()
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

        // Iterate through rules (already sorted by priority) to find a match
        for rule in &self.rules {
            // Skip expired rules
            if rule.is_expired() {
                continue;
            }

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
    /// Priority (0 = highest, 255 = lowest). Lower values evaluated first.
    pub priority: u8,
    /// When this rule was created.
    pub created_at: DateTime<Utc>,
    /// Optional expiration time for temporary rules.
    pub expires_at: Option<DateTime<Utc>>,
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
            priority: 128, // Default medium priority
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    /// Creates a new rule with custom priority.
    pub fn with_priority(
        name: impl Into<String>,
        target: RuleTarget,
        protocol: Protocol,
        action: Action,
        direction: TrafficDirection,
        priority: u8,
    ) -> Self {
        Self {
            name: name.into(),
            target,
            protocol,
            action,
            direction,
            priority,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    /// Creates a temporary rule with TTL.
    pub fn with_ttl(
        name: impl Into<String>,
        target: RuleTarget,
        protocol: Protocol,
        action: Action,
        direction: TrafficDirection,
        ttl_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            name: name.into(),
            target,
            protocol,
            action,
            direction,
            priority: 128,
            created_at: now,
            expires_at: Some(now + chrono::Duration::seconds(ttl_seconds)),
        }
    }

    /// Check if this rule has expired.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expiry) => Utc::now() > expiry,
            None => false,
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

        // Check target using the enhanced matching logic
        self.target.matches(target)
    }
}

/// Specific target for the rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleTarget {
    /// Applies to any target.
    Any,
    /// Applies to a specific network port.
    Port(u16),
    /// Applies to a port range (inclusive).
    PortRange(u16, u16),
    /// Applies to a specific IP address.
    Ip(IpAddr),
    /// Applies to an IP subnet (CIDR notation: address + prefix length).
    IpSubnet(IpAddr, u8),
    /// Applies to a specific peer identifier.
    PeerId(String),
    /// Applies to multiple peer identifiers.
    PeerGroup(Vec<String>),
}

impl RuleTarget {
    /// Check if this target matches another target.
    pub fn matches(&self, other: &RuleTarget) -> bool {
        match (self, other) {
            (RuleTarget::Any, _) => true,
            (RuleTarget::Port(p1), RuleTarget::Port(p2)) => p1 == p2,
            (RuleTarget::PortRange(start, end), RuleTarget::Port(p)) => p >= start && p <= end,
            (RuleTarget::Ip(ip1), RuleTarget::Ip(ip2)) => ip1 == ip2,
            (RuleTarget::IpSubnet(subnet, prefix), RuleTarget::Ip(ip)) => {
                Self::ip_in_subnet(ip, subnet, *prefix)
            }
            (RuleTarget::PeerId(id1), RuleTarget::PeerId(id2)) => id1 == id2,
            (RuleTarget::PeerGroup(group), RuleTarget::PeerId(id)) => group.contains(id),
            _ => false,
        }
    }

    /// Check if an IP is within a subnet.
    fn ip_in_subnet(ip: &IpAddr, subnet: &IpAddr, prefix_len: u8) -> bool {
        use std::net::IpAddr;

        match (ip, subnet) {
            (IpAddr::V4(ip), IpAddr::V4(subnet)) => {
                let ip_bits = u32::from(*ip);
                let subnet_bits = u32::from(*subnet);
                let mask = !0u32 << (32 - prefix_len);
                (ip_bits & mask) == (subnet_bits & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(subnet)) => {
                let ip_bits = u128::from(*ip);
                let subnet_bits = u128::from(*subnet);
                let mask = !0u128 << (128 - prefix_len);
                (ip_bits & mask) == (subnet_bits & mask)
            }
            _ => false,
        }
    }
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
