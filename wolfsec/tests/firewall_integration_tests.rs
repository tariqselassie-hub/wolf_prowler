//! Integration tests for the Wolf Prowler firewall system.
//!
//! Tests implicit deny-by-default policy, priority system, TTL, and advanced matching.

use std::net::IpAddr;
use wolf_net::firewall::{Action, FirewallRule, Protocol, RuleTarget, TrafficDirection};
use wolfsec::protection::network_security::{SecurityManager, HIGH_SECURITY};

#[tokio::test]
async fn test_implicit_deny_by_default() {
    let manager = SecurityManager::new("test_node".to_string(), HIGH_SECURITY);
    manager.initialize().await.unwrap();

    // After initialization with essential rules, Wolf Protocol should be allowed
    assert!(
        !manager
            .should_block(
                &RuleTarget::Any,
                &Protocol::WolfProto,
                &TrafficDirection::Inbound
            )
            .await,
        "Wolf Protocol should be whitelisted"
    );

    // But other protocols should be blocked by default
    assert!(
        manager
            .should_block(
                &RuleTarget::Port(8080),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "Non-whitelisted traffic should be blocked by default"
    );
}

#[tokio::test]
async fn test_firewall_priority_system() {
    let manager = SecurityManager::new("test_node".to_string(), HIGH_SECURITY);

    // Add low priority deny rule
    let deny_rule = FirewallRule::with_priority(
        "Deny All TCP",
        RuleTarget::Any,
        Protocol::TCP,
        Action::Deny,
        TrafficDirection::Inbound,
        200, // Low priority
    );
    manager.add_firewall_rule(deny_rule).await;

    // Add high priority allow rule for specific port
    let allow_rule = FirewallRule::with_priority(
        "Allow Port 8080",
        RuleTarget::Port(8080),
        Protocol::TCP,
        Action::Allow,
        TrafficDirection::Inbound,
        10, // High priority
    );
    manager.add_firewall_rule(allow_rule).await;

    // High priority allow should override low priority deny
    assert!(
        !manager
            .should_block(
                &RuleTarget::Port(8080),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "High priority allow should take precedence"
    );

    // Other ports should still be denied
    assert!(
        manager
            .should_block(
                &RuleTarget::Port(9090),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "Other ports should be denied by low priority rule"
    );
}

#[tokio::test]
async fn test_port_range_matching() {
    let manager = SecurityManager::new("test_node".to_string(), HIGH_SECURITY);

    // Allow port range 8000-9000
    let rule = FirewallRule::new(
        "Allow Port Range",
        RuleTarget::PortRange(8000, 9000),
        Protocol::TCP,
        Action::Allow,
        TrafficDirection::Inbound,
    );
    manager.add_firewall_rule(rule).await;

    // Ports within range should be allowed
    assert!(
        !manager
            .should_block(
                &RuleTarget::Port(8500),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "Port 8500 should be in range 8000-9000"
    );

    // Ports outside range should be blocked
    assert!(
        manager
            .should_block(
                &RuleTarget::Port(7999),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "Port 7999 should be outside range"
    );
}

#[tokio::test]
async fn test_ip_subnet_matching() {
    let manager = SecurityManager::new("test_node".to_string(), HIGH_SECURITY);

    // Allow subnet 192.168.1.0/24
    let subnet: IpAddr = "192.168.1.0".parse().unwrap();
    let rule = FirewallRule::new(
        "Allow Local Subnet",
        RuleTarget::IpSubnet(subnet, 24),
        Protocol::TCP,
        Action::Allow,
        TrafficDirection::Inbound,
    );
    manager.add_firewall_rule(rule).await;

    // IP within subnet should be allowed
    let ip_in_subnet: IpAddr = "192.168.1.100".parse().unwrap();
    assert!(
        !manager
            .should_block(
                &RuleTarget::Ip(ip_in_subnet),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "192.168.1.100 should be in 192.168.1.0/24"
    );

    // IP outside subnet should be blocked
    let ip_outside: IpAddr = "192.168.2.100".parse().unwrap();
    assert!(
        manager
            .should_block(
                &RuleTarget::Ip(ip_outside),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "192.168.2.100 should be outside 192.168.1.0/24"
    );
}

#[tokio::test]
async fn test_rule_expiration() {
    let manager = SecurityManager::new("test_node".to_string(), HIGH_SECURITY);

    // Add temporary rule with 1 second TTL
    let temp_rule = FirewallRule::with_ttl(
        "Temporary Allow",
        RuleTarget::Port(8080),
        Protocol::TCP,
        Action::Allow,
        TrafficDirection::Inbound,
        1, // 1 second TTL
    );
    manager.add_firewall_rule(temp_rule).await;

    // Should be allowed immediately
    assert!(
        !manager
            .should_block(
                &RuleTarget::Port(8080),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "Should be allowed before expiration"
    );

    // Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Should be blocked after expiration
    assert!(
        manager
            .should_block(
                &RuleTarget::Port(8080),
                &Protocol::TCP,
                &TrafficDirection::Inbound
            )
            .await,
        "Should be blocked after expiration"
    );
}

#[tokio::test]
async fn test_peer_group_matching() {
    let manager = SecurityManager::new("test_node".to_string(), HIGH_SECURITY);

    // Allow specific peer group
    let trusted_peers = vec![
        "peer1".to_string(),
        "peer2".to_string(),
        "peer3".to_string(),
    ];
    let rule = FirewallRule::new(
        "Allow Trusted Peers",
        RuleTarget::PeerGroup(trusted_peers),
        Protocol::WolfProto,
        Action::Allow,
        TrafficDirection::Inbound,
    );
    manager.add_firewall_rule(rule).await;

    // Trusted peer should be allowed
    assert!(
        !manager
            .should_block(
                &RuleTarget::PeerId("peer2".to_string()),
                &Protocol::WolfProto,
                &TrafficDirection::Inbound
            )
            .await,
        "Trusted peer should be allowed"
    );

    // Untrusted peer should be blocked
    assert!(
        manager
            .should_block(
                &RuleTarget::PeerId("peer99".to_string()),
                &Protocol::WolfProto,
                &TrafficDirection::Inbound
            )
            .await,
        "Untrusted peer should be blocked"
    );
}

#[tokio::test]
async fn test_firewall_management() {
    let manager = SecurityManager::new("test_node".to_string(), HIGH_SECURITY);
    manager.initialize().await.unwrap();

    // Get initial stats
    let stats = manager.get_firewall_stats().await;
    assert!(stats.enabled, "Firewall should be enabled");
    let initial_rules = stats.total_rules;

    // Add a rule
    let rule = FirewallRule::new(
        "Test Rule",
        RuleTarget::Port(8080),
        Protocol::TCP,
        Action::Allow,
        TrafficDirection::Inbound,
    );
    manager.add_firewall_rule(rule).await;

    // Verify rule was added
    let stats = manager.get_firewall_stats().await;
    assert_eq!(stats.total_rules, initial_rules + 1, "Rule should be added");

    // Remove rule by port
    manager.remove_firewall_rule_by_port(8080).await;

    // Verify rule was removed
    let stats = manager.get_firewall_stats().await;
    assert_eq!(stats.total_rules, initial_rules, "Rule should be removed");
}
