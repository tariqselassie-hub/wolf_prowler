//! Peer discovery for Wolf Prowler
//!
//! This module handles peer discovery mechanisms and services.

pub use crate::config::DiscoveryConfig;
use crate::peer::{PeerId, PeerInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

/// Discovery service for finding and managing peers
pub struct DiscoveryService {
    /// Service configuration
    config: DiscoveryConfig,
    /// Known peers
    known_peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    /// Discovery methods
    methods: Vec<Arc<dyn DiscoveryMethod>>,
    /// Running state
    running: bool,
    /// Channel to notify about discovered peers
    event_tx: mpsc::Sender<PeerInfo>,
    /// Channel to signal shutdown
    shutdown_tx: Option<mpsc::Sender<()>>,
}

/// Discovery method trait
#[async_trait::async_trait]
pub trait DiscoveryMethod: Send + Sync {
    /// Discover peers
    async fn discover_peers(&self) -> anyhow::Result<Vec<PeerInfo>>;

    /// Get method name
    fn name(&self) -> &'static str;
}

/// mDNS discovery method
pub struct MdnsDiscovery {
    enabled: bool,
}

impl MdnsDiscovery {
    /// Creates a new `MdnsDiscovery` instance.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

#[async_trait::async_trait]
impl DiscoveryMethod for MdnsDiscovery {
    async fn discover_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        // mDNS is handled by the libp2p Swarm behavior (see swarm.rs)
        Ok(Vec::new())
    }

    fn name(&self) -> &'static str {
        "mDNS"
    }
}

/// DHT discovery method
pub struct DhtDiscovery {
    enabled: bool,
}

impl DhtDiscovery {
    /// Creates a new `DhtDiscovery` instance.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

#[async_trait::async_trait]
impl DiscoveryMethod for DhtDiscovery {
    async fn discover_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        // DHT is handled by the libp2p Swarm behavior (see swarm.rs)
        Ok(Vec::new())
    }

    fn name(&self) -> &'static str {
        "DHT"
    }
}

/// Active port scanning discovery
pub struct ActiveScanDiscovery {
    enabled: bool,
    #[allow(dead_code)]
    ports: Vec<u16>,
}

impl ActiveScanDiscovery {
    /// Creates a new `ActiveScanDiscovery` instance.
    #[must_use]
    pub const fn new(enabled: bool, ports: Vec<u16>) -> Self {
        Self { enabled, ports }
    }
}

#[async_trait::async_trait]
impl DiscoveryMethod for ActiveScanDiscovery {
    async fn discover_peers(&self) -> anyhow::Result<Vec<PeerInfo>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        // Active scan requires handshake to obtain PeerId, which is not implemented here.
        Ok(Vec::new())
    }

    fn name(&self) -> &'static str {
        "ActiveScan"
    }
}

impl DiscoveryService {
    /// Create new discovery service
    pub fn new(config: DiscoveryConfig) -> anyhow::Result<(Self, mpsc::Receiver<PeerInfo>)> {
        let (tx, rx) = mpsc::channel(100);
        let mut methods: Vec<Arc<dyn DiscoveryMethod>> = Vec::new();

        if config.enable_mdns {
            methods.push(Arc::new(MdnsDiscovery::new(true)));
        }

        if config.enable_dht {
            methods.push(Arc::new(DhtDiscovery::new(true)));
        }

        if config.enable_active_scan {
            methods.push(Arc::new(ActiveScanDiscovery::new(
                true,
                config.scan_ports.clone(),
            )));
        }

        Ok((
            Self {
                config,
                known_peers: Arc::new(RwLock::new(HashMap::new())),
                methods,
                shutdown_tx: None,
                running: false,
                event_tx: tx,
            },
            rx,
        ))
    }

    /// Start the discovery service
    pub fn start(&mut self) -> anyhow::Result<()> {
        if self.running {
            return Ok(());
        }

        info!("🔍 Starting discovery service...");
        self.running = true;

        let methods = self.methods.clone();
        let config = self.config.clone();
        let known_peers = self.known_peers.clone();
        let event_tx = self.event_tx.clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Start discovery loop
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.discovery_interval_secs));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        debug!("Running discovery cycle...");

                        for method in &methods {
                            match method.discover_peers().await {
                                Ok(discovered_peers) => {
                                    info!(
                                        "{} discovered {} peers",
                                        method.name(),
                                        discovered_peers.len()
                                    );

                                    let mut known_peers = known_peers.write().await;
                                    for peer in discovered_peers {
                                        let peer_id = peer.peer_id.clone();
                                        known_peers.insert(peer_id, peer.clone());

                                        // Notify listeners
                                        if (event_tx.send(peer).await).is_err() {
                                            error!("Failed to send discovery event to channel");
                                        }
                                    }

                                    // Enforce maximum peer limit
                                    if known_peers.len() > config.max_peers {
                                        // Remove oldest peers (simplified)
                                        let excess = known_peers.len().saturating_sub(config.max_peers);
                                        let keys_to_remove: Vec<PeerId> =
                                            known_peers.keys().take(excess).cloned().collect();

                                        for key in keys_to_remove {
                                            known_peers.remove(&key);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Discovery error in {}: {}", method.name(), e);
                                }
                            }
                        }

                        // Cleanup stale peers
                        {
                            let mut known_peers_guard = known_peers.write().await;
                            let now = chrono::Utc::now();
                            let mut stale_peers = Vec::new();

                            for (peer_id, peer_info) in known_peers_guard.iter() {
                                let timeout = Duration::from_secs(config.peer_timeout_secs);
                                let chrono_timeout = chrono::Duration::from_std(timeout)
                                    .unwrap_or_else(|_| chrono::Duration::try_seconds(i64::try_from(config.peer_timeout_secs).unwrap_or(3600)).unwrap_or_else(|| chrono::Duration::seconds(3600)));
                                if now.signed_duration_since(peer_info.last_seen) > chrono_timeout
                                {
                                    stale_peers.push(peer_id.clone());
                                }
                            }

                            for peer_id in stale_peers {
                                known_peers_guard.remove(&peer_id);
                                debug!("Removed stale peer: {}", peer_id);
                            }
                            drop(known_peers_guard);
                        }

                        info!(
                            "Discovery cycle complete. {} known peers",
                            known_peers.read().await.len()
                        );
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Discovery loop received shutdown signal");
                        break;
                    }
                }
            }
        });

        info!("✅ Discovery service started");
        Ok(())
    }

    /// Stop the discovery service
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if !self.running {
            return Ok(());
        }

        info!("🛑 Stopping discovery service...");
        self.running = false;

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        info!("✅ Discovery service stopped");
        Ok(())
    }

    /// Get all known peers
    pub async fn get_known_peers(&self) -> Vec<PeerInfo> {
        self.known_peers.read().await.values().cloned().collect()
    }

    /// Get peer by ID
    pub async fn get_peer(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.known_peers.read().await.get(peer_id).cloned()
    }

    /// Add a peer manually
    pub async fn add_peer(&self, peer_info: PeerInfo) {
        self.known_peers
            .write()
            .await
            .insert(peer_info.peer_id.clone(), peer_info);
    }

    /// Remove a peer
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        self.known_peers.write().await.remove(peer_id);
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.known_peers.read().await.len()
    }

    /// Get a handle to the known peers map.
    pub fn get_known_peers_handle(&self) -> Arc<RwLock<HashMap<PeerId, PeerInfo>>> {
        self.known_peers.clone()
    }
}

impl From<DiscoveryConfig> for DiscoveryService {
    #[allow(clippy::expect_used)]
    fn from(config: DiscoveryConfig) -> Self {
        let (service, _) = Self::new(config).expect("Failed to create DiscoveryService");
        service
    }
}

impl DiscoveryService {
    #[allow(clippy::expect_used)]
    pub fn run_daemon(config: DiscoveryConfig) -> anyhow::Result<()> {
        let (mut service, _rx) = Self::new(config)?;
        service.start()?;
        info!("Discovery Service running in background thread...");
        // In a real daemon, you'd likely have a way to keep the service running
        // and handle shutdown signals. For this example, we'll just return Ok.
        // The spawned task will continue running until explicitly stopped or the process exits.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discovery_creation() {
        let config = DiscoveryConfig::default();
        let service = DiscoveryService::new(config).map(|(s, _)| s);
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_discovery() {
        let discovery = MdnsDiscovery::new(true);
        let peers = discovery.discover_peers().await.unwrap();
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn test_dht_discovery() {
        let discovery = DhtDiscovery::new(true);
        let peers = discovery.discover_peers().await.unwrap();
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn test_discovery_shutdown() {
        let mut config = DiscoveryConfig::default();
        // Set a short interval so the loop runs frequently
        config.discovery_interval_secs = 1;

        let (mut service, _rx) = DiscoveryService::new(config).expect("Failed to create service");

        // Start the service
        service.start().expect("Failed to start service");

        // Let it run for a short duration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop the service
        service.stop().await.expect("Failed to stop service");
    }
}
