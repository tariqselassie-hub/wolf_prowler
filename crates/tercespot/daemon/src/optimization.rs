//! TersecPot System Optimizations
//!
//! This module contains performance, security, and maintainability optimizations
//! for the TersecPot system.

use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, LruCache, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tokio::time::sleep;
use zeroize::Zeroize;

/// High-priority optimizations for the TersecPot system

/// 1. Memory-Safe Pending Command Manager
#[derive(Debug)]
pub struct PendingCommandManager {
    commands: HashMap<u64, PendingCommand>,
    max_pending: usize,
    cleanup_interval: Duration,
    last_cleanup: Instant,
}

impl PendingCommandManager {
    pub fn new(max_pending: usize) -> Self {
        Self {
            commands: HashMap::new(),
            max_pending,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            last_cleanup: Instant::now(),
        }
    }

    pub fn insert(&mut self, seq: u64, cmd: PendingCommand) -> Option<PendingCommand> {
        if self.commands.len() >= self.max_pending {
            self.cleanup_old_commands();
        }
        self.commands.insert(seq, cmd)
    }

    pub fn get(&self, seq: &u64) -> Option<&PendingCommand> {
        self.commands.get(seq)
    }

    pub fn remove(&mut self, seq: &u64) -> Option<PendingCommand> {
        self.commands.remove(seq)
    }

    fn cleanup_old_commands(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) > self.cleanup_interval {
            self.commands
                .retain(|_, cmd| now.duration_since(cmd.created_at) < self.cleanup_interval);
            self.last_cleanup = now;
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingCommand {
    pub seq: u64,
    pub ts: u64,
    pub cmd: String,
    pub ciphertext: Vec<u8>,
    pub signatures: Vec<PendingSignature>,
    pub created_at: Instant,
}

#[derive(Debug, Clone)]
pub struct PendingSignature {
    pub key_hex: String,
    pub signature: [u8; 2420], // ML-DSA-44 signature size
    pub timestamp: u64,
}

/// 2. Secure Memory Management
#[derive(Debug)]
pub struct SecurePrivateKey {
    key_data: Secret<Vec<u8>>,
}

impl SecurePrivateKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            key_data: Secret::new(data),
        }
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.key_data.expose_secret()
    }
}

impl Drop for SecurePrivateKey {
    fn drop(&mut self) {
        // Zeroize is automatically called when Secret is dropped
    }
}

/// 3. Input Validation and Rate Limiting
#[derive(Debug, Clone)]
pub struct RateLimiter {
    timestamps: VecDeque<Instant>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            timestamps: VecDeque::new(),
            max_requests,
            window: Duration::from_secs(window_seconds),
        }
    }

    pub fn is_allowed(&mut self) -> bool {
        let now = Instant::now();

        // Remove old timestamps
        while let Some(first) = self.timestamps.front() {
            if now.duration_since(*first) > self.window {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }

        // Check if we're under the limit
        if self.timestamps.len() < self.max_requests {
            self.timestamps.push_back(now);
            true
        } else {
            false
        }
    }
}

/// 4. Async Audit Logger with Batching
#[derive(Debug)]
pub struct BatchAuditLogger {
    tx: mpsc::UnboundedSender<AuditEntry>,
    batch_size: usize,
    flush_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub command_hash: String,
    pub encrypted_command: Vec<u8>,
    pub status: AuditStatus,
    pub emergency_mode: bool,
}

#[derive(Debug, Clone)]
pub enum AuditStatus {
    Success,
    Failed(String),
    Rejected(String),
}

impl BatchAuditLogger {
    pub fn new(batch_size: usize, flush_interval_ms: u64) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let flush_interval = Duration::from_millis(flush_interval_ms);

        let handle = tokio::spawn(async move {
            let mut batch = Vec::new();
            let mut last_flush = Instant::now();

            loop {
                tokio::select! {
                    Some(entry) = rx.recv() => {
                        batch.push(entry);

                        if batch.len() >= batch_size ||
                           last_flush.elapsed() >= flush_interval {
                            Self::flush_batch(&mut batch).await;
                            last_flush = Instant::now();
                        }
                    }
                    _ = sleep(flush_interval) => {
                        if !batch.is_empty() {
                            Self::flush_batch(&mut batch).await;
                            last_flush = Instant::now();
                        }
                    }
                }
            }
        });

        (
            Self {
                tx,
                batch_size,
                flush_interval,
            },
            handle,
        )
    }

    async fn flush_batch(batch: &mut Vec<AuditEntry>) {
        if batch.is_empty() {
            return;
        }

        // In a real implementation, this would write to syslog or database
        for entry in batch.drain(..) {
            let _ = Self::write_audit_entry(&entry).await;
        }
    }

    async fn write_audit_entry(entry: &AuditEntry) -> io::Result<()> {
        let audit_data = serde_json::to_string(entry)?;
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let filename = format!("audit_log_{}.json", timestamp);
        let path = PathBuf::from("/tmp/tersecpot_audit").join(filename);

        fs::write(path, audit_data)?;
        Ok(())
    }

    pub fn log_command_execution(
        &self,
        command: &str,
        status: AuditStatus,
        emergency_mode: bool,
    ) -> io::Result<()> {
        let command_hash = Self::calculate_sha256(command.as_bytes());
        let encrypted_command = Self::encrypt_command(command)?;

        let entry = AuditEntry {
            timestamp: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            command_hash,
            encrypted_command,
            status,
            emergency_mode,
        };

        self.tx
            .send(entry)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Audit logger channel closed"))
    }

    fn calculate_sha256(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        format!("{:x}", result)
    }

    fn encrypt_command(command: &str) -> io::Result<Vec<u8>> {
        let key = b"optimization_key_2023";
        let mut result = Vec::with_capacity(command.len());

        for (i, byte) in command.as_bytes().iter().enumerate() {
            let key_byte = key[i % key.len()];
            result.push(byte ^ key_byte);
        }

        Ok(result)
    }
}

/// 5. Configuration Manager with Validation
#[derive(Debug, Clone)]
pub struct TersecConfig {
    pub postbox_path: String,
    pub threshold_m: usize,
    pub max_pending_commands: usize,
    pub audit_batch_size: usize,
    pub audit_flush_interval_ms: u64,
    pub rate_limit_max_requests: usize,
    pub rate_limit_window_seconds: u64,
    pub max_command_length: usize,
    pub max_file_size: usize,
}

impl TersecConfig {
    pub fn default() -> Self {
        Self {
            postbox_path: "/tmp/tersecpot".to_string(),
            threshold_m: 1,
            max_pending_commands: 1000,
            audit_batch_size: 100,
            audit_flush_interval_ms: 5000,
            rate_limit_max_requests: 100,
            rate_limit_window_seconds: 60,
            max_command_length: 1024,
            max_file_size: 1024 * 1024, // 1MB
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.threshold_m == 0 {
            return Err("Threshold M must be greater than 0".to_string());
        }
        if self.max_pending_commands == 0 {
            return Err("Max pending commands must be greater than 0".to_string());
        }
        if self.audit_batch_size == 0 {
            return Err("Audit batch size must be greater than 0".to_string());
        }
        if self.rate_limit_max_requests == 0 {
            return Err("Rate limit max requests must be greater than 0".to_string());
        }
        if self.max_command_length == 0 {
            return Err("Max command length must be greater than 0".to_string());
        }
        if self.max_file_size == 0 {
            return Err("Max file size must be greater than 0".to_string());
        }
        Ok(())
    }
}

/// 6. Performance Metrics Collector
#[derive(Debug)]
pub struct MetricsCollector {
    command_count: Arc<RwLock<u64>>,
    error_count: Arc<RwLock<u64>>,
    audit_count: Arc<RwLock<u64>>,
    start_time: Instant,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            command_count: Arc::new(RwLock::new(0)),
            error_count: Arc::new(RwLock::new(0)),
            audit_count: Arc::new(RwLock::new(0)),
            start_time: Instant::now(),
        }
    }

    pub async fn increment_commands(&self) {
        let mut count = self.command_count.write().await;
        *count += 1;
    }

    pub async fn increment_errors(&self) {
        let mut count = self.error_count.write().await;
        *count += 1;
    }

    pub async fn increment_audits(&self) {
        let mut count = self.audit_count.write().await;
        *count += 1;
    }

    pub async fn get_metrics(&self) -> Metrics {
        let commands = *self.command_count.read().await;
        let errors = *self.error_count.read().await;
        let audits = *self.audit_count.read().await;
        let uptime = self.start_time.elapsed();

        Metrics {
            commands,
            errors,
            audits,
            uptime_seconds: uptime.as_secs(),
            error_rate: if commands > 0 {
                errors as f64 / commands as f64
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug)]
pub struct Metrics {
    pub commands: u64,
    pub errors: u64,
    pub audits: u64,
    pub uptime_seconds: u64,
    pub error_rate: f64,
}

/// 7. Health Check System
#[derive(Debug)]
pub struct HealthChecker {
    config: Arc<TersecConfig>,
    metrics: Arc<MetricsCollector>,
}

impl HealthChecker {
    pub fn new(config: Arc<TersecConfig>, metrics: Arc<MetricsCollector>) -> Self {
        Self { config, metrics }
    }

    pub async fn check_health(&self) -> HealthStatus {
        let metrics = self.metrics.get_metrics().await;

        let mut status = HealthStatus::Healthy;

        // Check error rate
        if metrics.error_rate > 0.1 {
            // 10% error rate threshold
            status = HealthStatus::Degraded;
        }

        // Check uptime
        if metrics.uptime_seconds < 60 {
            status = HealthStatus::Starting;
        }

        // Check audit lag (simplified)
        if metrics.audits < metrics.commands / 2 {
            status = HealthStatus::Degraded;
        }

        status
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Starting,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_pending_command_manager() {
        let mut manager = PendingCommandManager::new(2);

        let cmd1 = PendingCommand {
            seq: 1,
            ts: 1000,
            cmd: "test1".to_string(),
            ciphertext: vec![1, 2, 3],
            signatures: vec![],
            created_at: Instant::now(),
        };

        let cmd2 = PendingCommand {
            seq: 2,
            ts: 2000,
            cmd: "test2".to_string(),
            ciphertext: vec![4, 5, 6],
            signatures: vec![],
            created_at: Instant::now(),
        };

        manager.insert(1, cmd1.clone());
        manager.insert(2, cmd2.clone());

        assert_eq!(manager.get(&1).unwrap().cmd, "test1");
        assert_eq!(manager.get(&2).unwrap().cmd, "test2");

        // Should trigger cleanup when adding a third item
        let cmd3 = PendingCommand {
            seq: 3,
            ts: 3000,
            cmd: "test3".to_string(),
            ciphertext: vec![7, 8, 9],
            signatures: vec![],
            created_at: Instant::now(),
        };

        manager.insert(3, cmd3);

        // One of the old commands should be removed
        assert!(manager.get(&1).is_none() || manager.get(&2).is_none());
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(2, 1);

        assert!(limiter.is_allowed());
        assert!(limiter.is_allowed());
        assert!(!limiter.is_allowed()); // Should be rate limited
    }

    #[test]
    fn test_config_validation() {
        let mut config = TersecConfig::default();
        config.threshold_m = 0;

        assert!(config.validate().is_err());

        config.threshold_m = 1;
        assert!(config.validate().is_ok());
    }
}
