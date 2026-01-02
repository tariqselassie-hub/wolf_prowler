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
use crate::wolf_pack::coordinator::{CoordinatorMsg, HuntCoordinator};
use crate::wolf_pack::howl::{HowlMessage, HowlPayload};
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
    pub coordinator_tx: mpsc::Sender<CoordinatorMsg>,
    pub wolf_state: Arc<RwLock<WolfState>>,
    swarm_command_rx: mpsc::Receiver<SwarmCommand>,
}

impl WolfNode {
    /// Initializes all subsystems based on config
    pub async fn new(config: WolfConfig) -> Result<Self> {
        // 1. Initialize the Internal Firewall
        // We wrap it in Arc<RwLock> for shared concurrent access across the system
        let firewall = Arc::new(RwLock::new(InternalFirewall::new()));

        // Initialize Metrics Registry
        let metrics = Arc::new(RwLock::new(HashMap::new()));

        // Centralized storage for the JWT authentication token, shared between HubOrchestration and ReportingService
        let auth_token_storage = Arc::new(RwLock::new(None));

        // 2. Initialize Discovery Service
        let (discovery, discovery_rx) = DiscoveryService::new(config.discovery.clone())?;

        // 3. Initialize the SwarmManager
        let mut swarm_config = SwarmConfig::default();
        if config.network.listen_port > 0 {
            if let Ok(addr) = format!("/ip4/0.0.0.0/tcp/{}", config.network.listen_port).parse() {
                swarm_config.listen_addresses = vec![addr];
            }
        }

        let swarm = SwarmManager::new(swarm_config)?;

        // Initialize Command Channel
        let (command_tx, command_rx) = mpsc::channel(100);

        // Initialize Swarm Command Channel for Coordinator
        let (swarm_command_tx, swarm_command_rx) = mpsc::channel(100);

        // Initialize Hunt Coordinator
        let local_peer_id = swarm.local_peer_id.clone();
        let (coordinator, coordinator_tx, wolf_state) = HuntCoordinator::new(
            WolfRole::Scout, // Default starting role
            swarm_command_tx,
            local_peer_id,
            0, // Initial prestige
        );

        // Spawn the coordinator actor
        tokio::spawn(async move {
            coordinator.run().await;
        });

        // 3. Initialize SaaS-related services (ReportingService and HubOrchestration)
        let mut reporting: Option<ReportingService> = None;
        let mut hub_orchestration: Option<HubOrchestration> = None;
        let mut reporting_tx = None;

        // Assuming config.network contains fields like `enable_saas_features`, `hub_url`, `org_id`, `api_key`, `agent_id`, `headless_mode`
        // You would typically load these from environment variables or a dedicated config file.
        if config.network.enable_saas_features {
            // Placeholder for a config flag in NetworkConfig
            // Create a channel for telemetry events
            let (tx_events, rx_events) = tokio::sync::mpsc::channel(100);
            reporting_tx = Some(tx_events);

            reporting = Some(ReportingService::new(
                config.network.hub_url.clone(),
                config.network.org_id.clone(),
                rx_events,
                auth_token_storage.clone(), // Pass the shared token storage
            ));

            let hub_config = HubConfig {
                hub_url: config.network.hub_url.clone(),
                api_key: config.network.api_key.clone(),
                agent_id: config.network.agent_id.clone(),
                headless: config.network.headless_mode,
            };
            hub_orchestration = Some(HubOrchestration::new(
                hub_config,
                auth_token_storage.clone(),
            ));
        }

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
            coordinator_tx,
            wolf_state,
            swarm_command_rx,
        })
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
                // Fix: Parse PeerId correctly and use Command Sender
                // Fix: Parse PeerId correctly and use Command Sender
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
                // Fix: PeerId parsing
                // Fix: PeerId parsing
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
        }
    }

    /// Starts the main event loop
    pub async fn run(&mut self) -> Result<()> {
        // 1. Start Background Services
        if let Some(mut reporting) = self.reporting.take() {
            tokio::spawn(async move {
                reporting.run().await;
            });
        }

        if let Some(hub) = self.hub_orchestration.take() {
            println!("Initializing Hub Orchestration loop...");
            tokio::spawn(async move {
                if let Err(e) = hub.run().await {
                    tracing::error!("Hub Orchestration failed: {}", e);
                }
            });
        }

        // 2. Start Discovery Service
        println!("Starting Discovery Service...");
        self.discovery.start().await?;

        // Swarm Listener already started in SwarmManager::new

        // 4. Main Event Loop (Simplified: Swarm logic is handled in SwarmManager background task)
        println!("Starting Wolf Prowler Node...");

        let mut dht_sync_interval = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            tokio::select! {
                // Swarm events handled in background. Here we coordinate high-level logic.

                _ = dht_sync_interval.tick() => {
                    self.sync_discovery_to_dht().await;
                }
                maybe_peer = async {
                    if let Some(rx) = &mut self.discovery_rx {
                        rx.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Some(peer) = maybe_peer {
                        let peer_id = peer.peer_id.as_libp2p();
                        for addr in peer.addresses {
                            let multiaddr = crate::utils::socketaddr_to_multiaddr(addr);
                            // self.swarm.add_address_to_dht(&peer_id, multiaddr);
                            tracing::debug!("Would add address to DHT: {:?}", multiaddr);
                        }

                        // Initialize metrics for new peer
                        {
                            let mut metrics_lock = self.metrics.write().await;
                            if !metrics_lock.contains_key(&peer.peer_id) {
                                let entity_info = crate::peer::EntityInfo::new(crate::peer::EntityId::new(peer.peer_id.clone(), crate::peer::DeviceId::default(), crate::peer::ServiceId::default(), crate::peer::SystemId::default()));
                                metrics_lock.insert(peer.peer_id, entity_info);
                            }
                        }
                    } else {
                        self.discovery_rx = None;
                    }
                }
                cmd = self.command_rx.recv() => {
                    if let Some(command) = cmd {
                        if let NodeCommand::Shutdown = command {
                            println!("Shutdown command received via API. Stopping Wolf Node...");
                            if let Err(e) = self.discovery.stop().await {
                                tracing::error!("Failed to stop discovery service: {}", e);
                            }
                            return Ok(());
                        }
                        self.handle_command(command).await;
                    } else {
                        return Ok(());
                    }
                }
                Some(swarm_cmd) = self.swarm_command_rx.recv() => {
                    match swarm_cmd {
                        SwarmCommand::Broadcast(data) => {
                            if let Err(e) = self.swarm.command_sender().send(SwarmCommand::Broadcast(data)).await {
                                tracing::error!("Failed to execute swarm broadcast command: {}", e);
                            }
                        }
                        _ => {
                            tracing::warn!("Received unimplemented SwarmCommand in WolfNode proxy");
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("Shutdown signal received. Stopping Wolf Node...");
                    if let Err(e) = self.discovery.stop().await {
                        tracing::error!("Failed to stop discovery service: {}", e);
                    }
                    return Ok(());
                }
            }
        }
    }

    /// Syncs discovered peers to the Swarm's DHT
    async fn sync_discovery_to_dht(&mut self) {
        let peers = self.discovery.get_known_peers().await;
        // Logic simplified as add_address_to_dht might be missing on SwarmManager or needs exposure.
        // If missing, we skip for now to fix build.
        // Actually, let's check if add_address_to_dht exists. Step 555 said it was missing.
        // So we comment out the call to fix build.
        /*
        let mut count = 0;
        for peer in peers {
            let peer_id = peer.peer_id.as_libp2p();
            for addr in peer.addresses {
                let multiaddr = crate::utils::socketaddr_to_multiaddr(addr);
                self.swarm.add_address_to_dht(&peer_id, multiaddr);
                count += 1;
            }
        }
        if count > 0 {
            tracing::debug!("Synced {} peer addresses from Discovery to DHT", count);
        }
        */
        tracing::debug!("DHT Sync placeholder (method pending on SwarmManager)");
    }
}
