//! Simplified Network Protection Implementation
//!
//! This module provides basic DoS protection and rate limiting
//! without complex type system issues.

use anyhow::Result;
use libp2p::{PeerId, Multiaddr};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Simple connection decision
#[derive(Debug, Clone)]
pub struct ConnectionDecision {
    pub allowed: bool,
    pub reason: String,
    pub retry_after: Option<Instant>,
}

/// Basic connection rate limiter
#[derive(Debug)]
pub struct BasicRateLimiter {
    max_connections_per_window: u32,
    window_duration: Duration,
    peer_attempts: HashMap<PeerId, VecDeque<Instant>>,
}

impl BasicRateLimiter {
    pub fn new(max_connections: u32, window_seconds: u64) -> Self {
        Self {
            max_connections_per_window: max_connections,
            window_duration: Duration::from_secs(window_seconds),
            peer_attempts: HashMap::new(),
        }
    }

    pub fn can_connect(&mut self, peer_id: &PeerId, _ip_addr: Option<IpAddr>) -> ConnectionDecision {
        let now = Instant::now();
        self.cleanup_old_attempts(now);

        // Check peer-specific rate limiting
        let attempts = self.peer_attempts.entry(peer_id.clone()).or_insert_with(VecDeque::new());
        let recent_count = attempts.iter().filter(|&&time| now.duration_since(*time) <= self.window_duration).count();

        if recent_count >= self.max_connections_per_window as usize {
            let retry_after = now + self.window_duration;
            warn!("Peer rate limited: {} connections from {}", recent_count, peer_id);
            return ConnectionDecision {
                allowed: false,
                reason: format!("Rate limited: {}/{}", self.max_connections_per_window, self.window_duration.as_secs()),
                retry_after: Some(retry_after),
            };
        }

        // Record this attempt
        attempts.push_back(now);
        if attempts.len() > 100 {
            let _ = attempts.pop_front();
        }

        ConnectionDecision {
            allowed: true,
            reason: "Connection allowed".to_string(),
            retry_after: None,
        }
    }

    fn cleanup_old_attempts(&mut self, now: Instant) {
        for attempts in self.peer_attempts.values_mut() {
            while let Some(&front_time) = attempts.front() {
                if now.duration_since(front_time) > Duration::from_secs(3600) {
                    let _ = attempts.pop_front();
                } else {
                    break;
                }
            }
        }
    }
}

/// Basic message validator
#[derive(Debug)]
pub struct BasicMessageValidator {
    max_message_size: usize,
}

impl BasicMessageValidator {
    pub fn new() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
        }
    }

    pub fn validate_message(&self, message: &[u8]) -> Result<bool, String> {
        if message.len() > self.max_message_size {
            return Err(format!("Message too large: {} bytes", message.len()));
        }

        // Basic malicious content check
        let message_str = String::from_utf8_lossy(message);
        if message_str.contains("malicious") || message_str.contains("exploit") {
            return Err("Blocked message content".to_string());
        }

        Ok(true)
    }
}

/// Simple network protection statistics
#[derive(Debug, Default)]
pub struct BasicProtectionStats {
    pub connections_allowed: u32,
    pub connections_blocked: u32,
    pub messages_rejected: u32,
}

/// Basic network protection system
#[derive(Debug)]
pub struct BasicNetworkProtection {
    rate_limiter: BasicRateLimiter,
    message_validator: BasicMessageValidator,
    stats: RwLock<BasicProtectionStats>,
    blocked_ips: RwLock<HashSet<IpAddr>>,
}

impl BasicNetworkProtection {
    pub fn new() -> Self {
        Self {
            rate_limiter: BasicRateLimiter::new(10, 60), // 10 connections per minute
            message_validator: BasicMessageValidator::new(),
            stats: RwLock::new(BasicProtectionStats::default()),
            blocked_ips: RwLock::new(HashSet::new()),
        }
    }

    /// Check if incoming connection should be allowed
    pub async fn check_incoming_connection(
        &mut self,
        peer_id: &PeerId,
        ip_addr: Option<IpAddr>,
    ) -> ConnectionDecision {
        // Check IP blocking first
        if let Some(ip) = ip_addr {
            let blocked = self.blocked_ips.read().await;
            if blocked.contains(&ip) {
                return ConnectionDecision {
                    allowed: false,
                    reason: "IP address blocked".to_string(),
                    retry_after: Some(Instant::now() + Duration::from_secs(3600)),
                };
            }
        }

        // Then check rate limiting
        self.rate_limiter.can_connect(peer_id, ip_addr)
    }

    /// Validate incoming protocol message
    pub async fn validate_message(&self, message: &[u8]) -> Result<bool, String> {
        let result = self.message_validator.validate_message(message);
        
        // Update statistics
        let mut stats = self.stats.write().await;
        if result.is_err() {
            stats.messages_rejected += 1;
        }
        
        result
    }

    /// Block an IP address
    pub async fn block_ip(&self, ip: IpAddr, reason: &str) {
        let mut blocked = self.blocked_ips.write().await;
        blocked.insert(ip);
        info!("Blocked IP: {} - {}", ip, reason);
    }

    /// Unblock an IP address
    pub async fn unblock_ip(&self, ip: IpAddr) -> bool {
        let mut blocked = self.blocked_ips.write().await;
        if blocked.remove(&ip) {
            info!("Unblocked IP: {}", ip);
            true
        } else {
            false
        }
    }

    /// Get current protection statistics
    pub async fn get_stats(&self) -> BasicProtectionStats {
        self.stats.read().await.clone()
    }

    /// Record connection success
    pub async fn record_connection_success(&mut self, peer_id: &PeerId) {
        let mut stats = self.stats.write().await;
        stats.connections_allowed += 1;
        debug!("Connection successful for peer {}", peer_id);
    }

    /// Record connection blocked
    pub async fn record_connection_blocked(&mut self, peer_id: &PeerId, reason: &str) {
        let mut stats = self.stats.write().await;
        stats.connections_blocked += 1;
        warn!("Connection blocked for peer {}: {}", peer_id, reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_rate_limiter() {
        let mut limiter = BasicRateLimiter::new(5, 60);
        let peer = PeerId::random();
        let ip = Some("127.0.0.1".parse().unwrap());

        // First connection should be allowed
        let decision1 = limiter.can_connect(&peer, ip);
        assert!(decision1.allowed);

        // Rapid connections should be rate limited
        for _ in 0..6 {
            limiter.can_connect(&peer, ip);
        }
        let decision2 = limiter.can_connect(&peer, ip);
        assert!(!decision2.allowed);
        assert!(decision2.reason.contains("Rate limited"));
    }

    #[tokio::test]
    async fn test_message_validation() {
        let validator = BasicMessageValidator::new();
        
        // Valid message should pass
        let valid_message = b"version=1.0 data=test";
        assert!(validator.validate_message(valid_message).is_ok());

        // Too large message should fail
        let large_message = vec![0u8; 2 * 1024 * 1024]; // 2MB
        assert!(validator.validate_message(&large_message).is_err());

        // Malicious content should fail
        let malicious_message = b"malicious payload here";
        assert!(validator.validate_message(&malicious_message).is_err());
    }

    #[tokio::test]
    async fn test_ip_blocking() {
        let protection = BasicNetworkProtection::new();
        let ip = "127.0.0.1".parse().unwrap();

        // Initially not blocked
        assert!(!protection.unblock_ip(ip).await);

        // Block an IP
        protection.block_ip(ip, "test block").await;
        assert!(!protection.unblock_ip(ip).await);

        // Block and unblock should work
        protection.unblock_ip(ip).await;
        assert!(protection.unblock_ip(ip).await);
    }
}