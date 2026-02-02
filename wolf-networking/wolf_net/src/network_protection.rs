//! Network DoS Protection and Rate Limiting
//!
//! This module provides comprehensive protection against network attacks including:
//! - Connection rate limiting per peer
//! - Connection validation and authentication
//! - Circuit breaker patterns for protection
//! - Protocol message validation
//! - DoS detection and mitigation

use anyhow::Result;
use libp2p::{PeerId, Multiaddr};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Connection rate limiter to prevent DoS attacks
#[derive(Debug, Clone)]
pub struct ConnectionRateLimiter {
    /// Maximum connections per time window
    max_connections_per_window: u32,
    /// Time window for rate limiting
    window_duration: Duration,
    /// Connection attempts per peer
    peer_attempts: HashMap<PeerId, VecDeque<Instant>>,
    /// Total connection counts per peer
    peer_counts: HashMap<PeerId, u32>,
    /// Global connection attempts for DoS detection
    global_attempts: VecDeque<Instant>,
}

impl ConnectionRateLimiter {
    /// Create new rate limiter
    pub fn new(max_connections: u32, window_seconds: u64) -> Self {
        Self {
            max_connections_per_window: max_connections,
            window_duration: Duration::from_secs(window_seconds),
            peer_attempts: HashMap::new(),
            peer_counts: HashMap::new(),
            global_attempts: VecDeque::new(),
        }
    }

    /// Check if peer is allowed to connect
    pub fn can_connect(&mut self, peer_id: &PeerId, ip_addr: Option<IpAddr>) -> ConnectionDecision {
        let now = Instant::now();

        // Clean old attempts
        self.cleanup_old_attempts(now);

        // Check global DoS protection
        if self.is_global_dos_detected(now) {
            return ConnectionDecision {
                allowed: false,
                reason: "Global DoS attack detected".to_string(),
                retry_after: Some(now + Duration::from_secs(300)), // 5 minutes
            };
        }

        // Check peer-specific rate limiting
        if let Some(retry_after) = self.check_peer_rate_limit(peer_id, now) {
            return ConnectionDecision {
                allowed: false,
                reason: format!("Peer rate limited: {}/{}", self.max_connections_per_window, self.window_duration.as_secs()),
                retry_after: Some(retry_after),
            };
        }

        // Check IP-based blocking
        if let Some(ip) = ip_addr {
            if let Some(reason) = self.check_ip_blocking(ip) {
                return ConnectionDecision {
                    allowed: false,
                    reason,
                    retry_after: Some(now + Duration::from_secs(3600)), // 1 hour
                };
            }
        }

        // Record this attempt
        self.record_connection_attempt(peer_id, now);

        ConnectionDecision {
            allowed: true,
            reason: "Connection allowed".to_string(),
            retry_after: None,
        }
    }

    /// Check for global DoS patterns
    fn is_global_dos_detected(&self, now: Instant) -> bool {
        // Keep only recent attempts (last 10 seconds)
        let recent_count = self.global_attempts
            .iter()
            .filter(|&&time| now.duration_since(*time) <= Duration::from_secs(10))
            .count();

        // Alert on high connection rate
        if recent_count > 100 {
            warn!("Global DoS attack detected: {} connections in 10 seconds", recent_count);
            return true;
        }

        false
    }

    /// Check peer-specific rate limits
    fn check_peer_rate_limit(&mut self, peer_id: &PeerId, now: Instant) -> Option<Instant> {
        let attempts = self.peer_attempts.entry(peer_id.clone()).or_insert_with(VecDeque::new());
        let count = self.peer_counts.entry(peer_id.clone()).or_insert(0);

        // Count recent attempts within window
        let recent_count = attempts
            .iter()
            .filter(|&&time| now.duration_since(*time) <= self.window_duration)
            .count();

        if recent_count >= self.max_connections_per_window as usize {
            let retry_after = now + self.window_duration;
            warn!("Peer rate limited: {} connections from {}", recent_count, peer_id);
            return Some(retry_after);
        }

        None
    }

    /// Check IP-based blocking rules
    fn check_ip_blocking(&self, ip: IpAddr) -> Option<String> {
        // Private network blocks (if configured)
        if ip.is_private() && self.should_block_private_networks() {
            return Some("Private network IP blocked".to_string());
        }

        // Known malicious IP patterns
        let ip_str = ip.to_string();
        if self.matches_malicious_patterns(&ip_str) {
            return Some("Known malicious IP pattern".to_string());
        }

        None
    }

    /// Check if private networks should be blocked
    fn should_block_private_networks(&self) -> bool {
        // In production, you might want to block private network IPs
        // This is configurable based on your security policy
        false // Allow private networks for now
    }

    /// Match against known malicious patterns
    fn matches_malicious_patterns(&self, ip: &str) -> bool {
        let malicious_patterns = [
            // Known Tor exit nodes
            "10.0.0.0/8", // Example pattern
            // Add other patterns as discovered
        ];

        malicious_patterns.iter().any(|pattern| ip.starts_with(pattern))
    }

    /// Record a connection attempt
    fn record_connection_attempt(&mut self, peer_id: &PeerId, now: Instant) {
        let attempts = self.peer_attempts.entry(peer_id.clone()).or_insert_with(VecDeque::new());
        attempts.push_back(now);
        self.global_attempts.push_back(now);

        // Keep only recent attempts
        if attempts.len() > 100 {
            let _ = attempts.pop_front();
        }
        if self.global_attempts.len() > 1000 {
            let _ = self.global_attempts.pop_front();
        }
    }

    /// Clean old connection attempts
    fn cleanup_old_attempts(&mut self, now: Instant) {
        // Clean peer attempts
        for attempts in self.peer_attempts.values_mut() {
            while let Some(&front_time) = attempts.front() {
                if now.duration_since(front_time) > Duration::from_secs(3600) {
                    let _ = attempts.pop_front();
                } else {
                    break;
                }
            }
        }

        // Clean global attempts
        while let Some(&front_time) = self.global_attempts.front() {
            if now.duration_since(front_time) > Duration::from_secs(3600) {
                let _ = self.global_attempts.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Connection decision with reason and retry timing
#[derive(Debug, Clone)]
pub struct ConnectionDecision {
    pub allowed: bool,
    pub reason: String,
    pub retry_after: Option<Instant>,
}

/// Protocol message validator
#[derive(Debug, Clone)]
pub struct MessageValidator {
    /// Maximum message size
    max_message_size: usize,
    /// Required message fields
    required_fields: Vec<String>,
    /// Blocked message types
    blocked_message_types: Vec<String>,
}

impl MessageValidator {
    /// Create new message validator
    pub fn new() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            required_fields: vec!["version".to_string(), "timestamp".to_string()],
            blocked_message_types: vec!["malicious".to_string(), "exploit".to_string()],
        }
    }

    /// Validate incoming protocol message
    pub fn validate_message(&self, message: &[u8]) -> Result<bool, String> {
        // Check size limits
        if message.len() > self.max_message_size {
            return Err(format!("Message too large: {} bytes", message.len()));
        }

        // Check for blocked patterns
        let message_str = String::from_utf8_lossy(message);
        for blocked_type in &self.blocked_message_types {
            if message_str.contains(blocked_type) {
                return Err(format!("Blocked message type: {}", blocked_type));
            }
        }

        // Validate required fields (simplified)
        for field in &self.required_fields {
            if !message_str.contains(field) {
                return Err(format!("Missing required field: {}", field));
            }
        }

        Ok(true)
    }
}

/// Circuit breaker for connection protection
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    /// Failure threshold
    failure_threshold: u32,
    /// Success threshold for recovery
    success_threshold: u32,
    /// Current state
    state: CircuitBreakerState,
    /// Current failure count
    failure_count: u32,
    /// Current success count
    success_count: u32,
    /// Last state change time
    last_state_change: Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerState {
    Closed,    // Normal operation
    Open,      // Failing, blocking requests
    HalfOpen,   // Testing recovery
}

impl CircuitBreaker {
    /// Create new circuit breaker
    pub fn new(failure_threshold: u32, success_threshold: u32) -> Self {
        Self {
            failure_threshold,
            success_threshold,
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            success_count: 0,
            last_state_change: Instant::now(),
        }
    }

    /// Check if connection should be allowed
    pub fn allow_request(&mut self) -> bool {
        let now = Instant::now();

        match self.state {
            CircuitBreakerState::Open => {
                // Check if enough time has passed to try recovery
                if now.duration_since(self.last_state_change) > Duration::from_secs(60) {
                    self.state = CircuitBreakerState::HalfOpen;
                    self.failure_count = 0;
                    self.success_count = 0;
                    self.last_state_change = now;
                    info!("Circuit breaker transitioning to half-open");
                    true
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => {
                // Allow limited requests to test recovery
                true
            }
            CircuitBreakerState::Closed => {
                // Normal operation, allow requests
                if self.failure_count > 0 {
                    self.state = CircuitBreakerState::Open;
                    self.last_state_change = now;
                    error!("Circuit breaker opened due to {} failures", self.failure_count);
                    false
                } else {
                    true
                }
            }
        }
    }

    /// Record a successful request
    pub fn record_success(&mut self) {
        self.success_count += 1;
        
        // If in half-open state, close the circuit after enough successes
        if self.state == CircuitBreakerState::HalfOpen && self.success_count >= self.success_threshold {
            self.state = CircuitBreakerState::Closed;
            self.failure_count = 0;
            self.success_count = 0;
            self.last_state_change = Instant::now();
            info!("Circuit breaker closed after successful recovery");
        }
    }

    /// Record a failed request
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        
        // If too many failures, open the circuit
        if self.failure_count >= self.failure_threshold && self.state == CircuitBreakerState::Closed {
            self.state = CircuitBreakerState::Open;
            self.last_state_change = Instant::now();
            error!("Circuit breaker opened after {} failures", self.failure_count);
        }
    }
}

/// Comprehensive network protection system
#[derive(Debug, Clone)]
pub struct NetworkProtection {
    /// Connection rate limiter
    rate_limiter: ConnectionRateLimiter,
    /// Message validator
    message_validator: MessageValidator,
    /// Circuit breaker for global protection
    circuit_breaker: CircuitBreaker,
    /// Blocked IPs list
    blocked_ips: HashMap<IpAddr, String>,
    /// Protection statistics
    stats: RwLock<ProtectionStats>,
}

#[derive(Debug, Clone, Default)]
pub struct ProtectionStats {
    pub connections_blocked: u32,
    pub connections_allowed: u32,
    pub messages_rejected: u32,
    pub circuit_breaker_opens: u32,
    pub dos_attempts_detected: u32,
}

impl NetworkProtection {
    /// Create new network protection system
    pub fn new() -> Self {
        Self {
            rate_limiter: ConnectionRateLimiter::new(10, 60), // 10 connections per minute
            message_validator: MessageValidator::new(),
            circuit_breaker: CircuitBreaker::new(5, 10), // 5 failures opens, 10 successes closes
            blocked_ips: HashMap::new(),
            stats: RwLock::new(ProtectionStats::default()),
        }
    }

    /// Check if incoming connection should be allowed
    pub fn check_incoming_connection(
        &mut self,
        peer_id: &PeerId,
        ip_addr: Option<IpAddr>,
    ) -> ConnectionDecision {
        // Check circuit breaker first
        if !self.circuit_breaker.allow_request() {
            let mut stats = self.stats.write();
            stats.circuit_breaker_opens += 1;
            warn!("Circuit breaker blocking connection from {}", peer_id);
            return ConnectionDecision {
                allowed: false,
                reason: "Circuit breaker active".to_string(),
                retry_after: Some(Instant::now() + Duration::from_secs(60)),
            };
        }

        // Check rate limiting
        let decision = self.rate_limiter.can_connect(peer_id, ip_addr);
        
        // Update statistics
        let mut stats = self.stats.write();
        if decision.allowed {
            stats.connections_allowed += 1;
        } else {
            stats.connections_blocked += 1;
        }

        decision
    }

    /// Validate incoming protocol message
    pub fn validate_message(&self, message: &[u8]) -> Result<bool, String> {
        let result = self.message_validator.validate_message(message);
        
        // Update statistics
        let mut stats = self.stats.write();
        if result.is_err() {
            stats.messages_rejected += 1;
            warn!("Message rejected: {}", result.unwrap_err());
        }
        
        result
    }

    /// Record connection success
    pub fn record_connection_success(&mut self, peer_id: &PeerId) {
        self.circuit_breaker.record_success();
        
        let mut stats = self.stats.write();
        debug!("Connection successful for peer {}", peer_id);
    }

    /// Record connection failure
    pub fn record_connection_failure(&mut self, peer_id: &PeerId, reason: &str) {
        self.circuit_breaker.record_failure();
        
        let mut stats = self.stats.write();
        error!("Connection failed for peer {}: {}", peer_id, reason);
    }

    /// Block an IP address
    pub fn block_ip(&mut self, ip: IpAddr, reason: &str) {
        self.blocked_ips.insert(ip, reason.to_string());
        info!("Blocked IP: {} - {}", ip, reason);
    }

    /// Unblock an IP address
    pub fn unblock_ip(&mut self, ip: IpAddr) {
        if let Some(reason) = self.blocked_ips.remove(&ip) {
            info!("Unblocked IP: {} - was blocked: {}", ip, reason);
        }
    }

    /// Get current protection statistics
    pub async fn get_stats(&self) -> ProtectionStats {
        self.stats.read().await.clone()
    }

    /// Add known malicious IP
    pub fn add_malicious_ip(&mut self, ip: IpAddr, reason: &str) {
        self.block_ip(ip, reason);
        warn!("Added malicious IP to blocklist: {} - {}", ip, reason);
    }

    /// Check if IP is blocked
    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains_key(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_connection_rate_limiter() {
        let mut limiter = ConnectionRateLimiter::new(5, 60);
        let peer = PeerId::random();
        let ip = Some("127.0.0.1".parse().unwrap());

        // First connection should be allowed
        let decision1 = limiter.can_connect(&peer, ip);
        assert!(decision1.allowed);

        // Rapid connections should be rate limited
        for _ in 0..6 {
            let decision = limiter.can_connect(&peer, ip);
            if decision.allowed {
                break;
            }
        }

        let decision2 = limiter.can_connect(&peer, ip);
        assert!(!decision2.allowed);
        assert!(decision2.reason.contains("rate limited"));
    }

    #[test]
    fn test_message_validator() {
        let validator = MessageValidator::new();
        
        // Valid message should pass
        let valid_message = b"version=1.0 timestamp=123456 data=test";
        assert!(validator.validate_message(valid_message).is_ok());

        // Too large message should fail
        let large_message = vec![0u8; 2 * 1024 * 1024]; // 2MB
        assert!(validator.validate_message(&large_message).is_err());

        // Message with blocked content should fail
        let blocked_message = b"malicious payload here";
        assert!(validator.validate_message(blocked_message).is_err());
    }

    #[test]
    fn test_circuit_breaker() {
        let mut breaker = CircuitBreaker::new(3, 5);

        // Should allow requests initially
        assert!(breaker.allow_request());
        assert_eq!(breaker.state, CircuitBreakerState::Closed);

        // Should open after threshold failures
        for _ in 0..3 {
            breaker.record_failure();
        }
        assert!(!breaker.allow_request());
        assert_eq!(breaker.state, CircuitBreakerState::Open);

        // Should close after threshold successes
        for _ in 0..5 {
            breaker.record_success();
        }
        assert!(breaker.allow_request());
        assert_eq!(breaker.state, CircuitBreakerState::Closed);
    }
}