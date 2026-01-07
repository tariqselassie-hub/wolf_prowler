use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use crate::api::{NodeCommand, WolfNodeControl};
// use crate::behavior::WolfEvent; // Removed unused
use crate::discovery::DiscoveryService;
use crate::hub_orchestration::{HubConfig, HubOrchestration};
use crate::swarm::{SwarmCommand, SwarmConfig};
use crate::SwarmManager;
use crate::WolfConfig;
// These modules are implied by the system architecture
use crate::firewall::InternalFirewall;
use crate::peer::{EntityInfo, PeerId, PeerInfo};
use crate::reporting_service::{ReportingService, TelemetryEvent};
use crate::wolf_pack::coordinator::CoordinatorMsg;
use crate::wolf_pack::state::{WolfRole, WolfState};

/// Top-level manager to clean up main.rs initialization
pub struct WolfNode {
    pub swarm: SwarmManager,
    pub discovery: DiscoveryService,
    pub discovery_rx: Option<mpsc::Receiver<PeerInfo>>,
    pub reporting: Option<ReportingService>,
    // Centralized access to the firewall
    pub hub_orchestration: Option<HubOrchestration>,
    pub reporting_tx: Option<tokio::sync::mpsc::Sender<TelemetryEvent>>,
    pub command_tx: mpsc::Sender<NodeCommand>,
    pub command_rx: mpsc::Receiver<NodeCommand>,
    pub firewall: Arc<RwLock<InternalFirewall>>,
    pub metrics: Arc<RwLock<HashMap<PeerId, EntityInfo>>>,
    pub coordinator_tx: Option<mpsc::Sender<CoordinatorMsg>>,
    pub wolf_state: Arc<RwLock<WolfState>>,
    pub auth_token: Arc<RwLock<Option<String>>>,
    background_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl WolfNode {
    /// Initializes all subsystems based on config
    pub async fn new(config: WolfConfig) -> Result<Self> {
        let firewall = Arc::new(RwLock::new(InternalFirewall::new()));
        let metrics = Arc::new(RwLock::new(HashMap::new()));
        let auth_token_storage = Arc::new(RwLock::new(None));

        let (discovery, discovery_rx) = DiscoveryService::new(config.discovery.clone())?;
        let swarm = Self::init_swarm(&config)?;
        let (command_tx, command_rx) = mpsc::channel(100);

        let coordinator_tx = swarm.hunt_coordinator_sender();
        let wolf_state = swarm.get_wolf_state().await?;

        // Set initial role from config (defaulting to Scout if not specified)
        // Note: In a production system, this might be loaded from persistent storage
        {
            let mut state = wolf_state.write().await;
            state.role = WolfRole::Scout;
        }

        // 3. Initialize SaaS-related services
        let (reporting, hub_orchestration, reporting_tx) =
            Self::init_saas_services(&config, auth_token_storage.clone()).await;

        Ok(Self {
            swarm,
            discovery,
            discovery_rx: Some(discovery_rx),
            reporting,
            firewall,
            hub_orchestration,
            reporting_tx,
            command_tx,
            command_rx,
            metrics,
            coordinator_tx: Some(coordinator_tx),
            wolf_state,
            auth_token: auth_token_storage,
            background_tasks: Vec::new(),
        })
    }

    /// Helper to initialize the SwarmManager
    fn init_swarm(config: &WolfConfig) -> Result<SwarmManager> {
        let mut swarm_config = SwarmConfig::default();
        if config.network.listen_port > 0 {
            if let Ok(addr) = format!("/ip4/0.0.0.0/tcp/{}", config.network.listen_port).parse() {
                swarm_config.listen_addresses = vec![addr];
            }
        }

        // Propagate identity seed if present
        if let Some(seed) = &config.network.identity_seed {
            swarm_config.identity_seed = Some(seed.clone());
        }

        SwarmManager::new(swarm_config)
    }

    /// Helper to initialize SaaS-related services
    async fn init_saas_services(
        config: &WolfConfig,
        auth_token: Arc<RwLock<Option<String>>>,
    ) -> (
        Option<ReportingService>,
        Option<HubOrchestration>,
        Option<mpsc::Sender<TelemetryEvent>>,
    ) {
        if !config.network.enable_saas_features {
            return (None, None, None);
        }

        let (tx_events, rx_events) = mpsc::channel(100);

        let reporting = Some(ReportingService::new(
            config.network.hub_url.clone(),
            config.network.org_id.clone(),
            rx_events,
            auth_token.clone(),
        ));

        let hub_config = HubConfig {
            hub_url: config.network.hub_url.clone(),
            api_key: config.network.api_key.clone(),
            agent_id: config.network.agent_id.clone(),
            headless: config.network.headless_mode,
        };

        let hub_orchestration = Some(HubOrchestration::new(hub_config, auth_token));

        (reporting, hub_orchestration, Some(tx_events))
    }

    /// Returns a handle to control the WolfNode from other threads/components
    pub fn get_control(&self) -> WolfNodeControl {
        WolfNodeControl::new(self.command_tx.clone())
    }

    /// Helper method to send telemetry events via the reporting channel.
    pub async fn send_telemetry(&self, event: TelemetryEvent) {
        if let Some(tx) = &self.reporting_tx {
            if let Err(e) = tx.send(event).await {
                tracing::error!("Failed to send telemetry event: {}", e);
            }
        }
    }

    /// Processes a single command
    async fn handle_command(&mut self, command: NodeCommand) {
        match command {
            NodeCommand::Shutdown => {
                tracing::info!("Shutdown command received");
            }
            NodeCommand::ConnectPeer(addr_str) => {
                if let Ok(addr) = addr_str.parse() {
                    // Fix: Use dial_addr for multiaddr
                    if let Err(e) = self.swarm.dial_addr(addr).await {
                        tracing::error!("Failed to dial peer: {}", e);
                    }
                } else {
                    tracing::error!("Invalid multiaddr: {}", addr_str);
                }
            }
            NodeCommand::DisconnectPeer(peer_id_str) => {
                let peer_id = crate::peer::PeerId::from_string(peer_id_str.clone());
                if let Err(e) = self
                    .swarm
                    .command_sender()
                    .send(SwarmCommand::DisconnectPeer { peer_id })
                    .await
                {
                    tracing::error!("Failed to disconnect peer: {}", e);
                }
            }
            NodeCommand::Broadcast(msg) => {
                if let Err(e) = self
                    .swarm
                    .command_sender()
                    .send(SwarmCommand::Broadcast(msg))
                    .await
                {
                    tracing::error!("Failed to broadcast message: {}", e);
                }
            }
            NodeCommand::SendDirect { peer_id, data: _ } => {
                // Direct requests require wrapping in WolfRequest
                let _pid = crate::peer::PeerId::from_string(peer_id.clone());
                // Direct requests require wrapping in WolfRequest, skipping for now as explicit command needed
                tracing::warn!("Direct message not yet fully implemented in WolfNode handler");
            }
            NodeCommand::UpdateFirewall(req) => {
                let mut fw = self.firewall.write().await;
                if let Some(enabled) = req.enabled {
                    fw.enabled = enabled;
                }
                if let Some(policy) = req.policy {
                    fw.set_policy(policy);
                }
            }
            NodeCommand::Coordinator(msg) => {
                if let Some(tx) = &self.coordinator_tx {
                    if let Err(e) = tx.send(msg).await {
                        tracing::error!("Failed to forward command to HuntCoordinator: {}", e);
                    }
                }
            }
        }
    }

    /// Starts the main event loop
    pub async fn run(&mut self) -> Result<()> {
        // 1. Start Background Services
        if let Some(mut reporting) = self.reporting.take() {
            let handle = tokio::task::spawn(async move {
                reporting.run().await;
            });
            self.background_tasks.push(handle);
        }

        if let Some(hub) = self.hub_orchestration.take() {
            println!("Initializing Hub Orchestration loop...");
            let handle = tokio::task::spawn(async move {
                if let Err(e) = hub.run().await {
                    tracing::error!("Hub Orchestration failed: {}", e);
                }
            });
            self.background_tasks.push(handle);
        }

        // 2. Start Discovery Service
        println!("Starting Discovery Service...");
        self.discovery.start().await?;

        // Swarm Listener already started in SwarmManager::new

        // 4. Main Event Loop (Simplified: Swarm logic is handled in SwarmManager background task)
        println!("Starting Wolf Prowler Node...");

        let mut discovery_rx = self
            .discovery_rx
            .take()
            .expect("Discovery receiver already taken");
        let mut dht_sync_interval = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = dht_sync_interval.tick() => {
                    self.sync_discovery_to_dht().await;
                }
                Some(peer) = discovery_rx.recv() => {
                    self.handle_discovered_peer(peer).await;
                }
                command = self.command_rx.recv() => {
                    match command {
                        Some(NodeCommand::Shutdown) => break,
                        Some(cmd) => self.handle_command(cmd).await,
                        None => break,
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    break;
                }
            }
        }

        self.perform_shutdown().await
    }

    /// Performs a graceful shutdown of all subsystems
    async fn perform_shutdown(&mut self) -> Result<()> {
        println!("Shutdown signal received. Stopping Wolf Node...");

        // 1. Stop Discovery Service
        let _ = self.discovery.stop().await;

        // 2. Stop Swarm Manager (this also stops the swarm event loop)
        let _ = self.swarm.stop().await;

        // 3. Close channels to stop background actors (ReportingService, HuntCoordinator)
        self.reporting_tx.take();
        self.coordinator_tx.take();

        // 4. Join background tasks. We use abort() for tasks that might be stuck in sleep (HubOrchestration).
        for handle in self.background_tasks.drain(..) {
            handle.abort();
            let _ = handle.await;
        }

        Ok(())
    }

    /// Handles a newly discovered peer
    async fn handle_discovered_peer(&self, peer: PeerInfo) {
        let _peer_id = peer.peer_id.as_libp2p();
        for addr in peer.addresses {
            let _multiaddr = crate::utils::socketaddr_to_multiaddr(addr);
            // self.swarm.add_address_to_dht(&peer_id, multiaddr);
            tracing::debug!("Would add address to DHT: {:?}", _multiaddr);
        }

        // Initialize metrics for new peer
        let mut metrics_lock = self.metrics.write().await;
        if !metrics_lock.contains_key(&peer.peer_id) {
            let entity_info = crate::peer::EntityInfo::new(crate::peer::EntityId::new(
                peer.peer_id.clone(),
                crate::peer::DeviceId::default(),
                crate::peer::ServiceId::default(),
                crate::peer::SystemId::default(),
            ));
            metrics_lock.insert(peer.peer_id, entity_info);
        }
    }

    /// Syncs discovered peers to the Swarm's DHT
    async fn sync_discovery_to_dht(&mut self) {
        let peers = self.discovery.get_known_peers().await;
        let mut count = 0;
        for peer in peers {
            let peer_id = peer.peer_id.clone();
            for addr in peer.addresses {
                let multiaddr = crate::utils::socketaddr_to_multiaddr(addr);
                if let Err(e) = self.swarm.add_address(peer_id.clone(), multiaddr).await {
                    tracing::error!("Failed to sync address to swarm: {}", e);
                } else {
                    count += 1;
                }
            }
        }
        if count > 0 {
            tracing::debug!("Synced {} peer addresses from Discovery to DHT", count);
        }
    }
}
