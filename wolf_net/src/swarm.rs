//! Swarm management for Wolf Prowler
//!
//! This module handles the libp2p swarm and network operations.

use crate::behavior::WolfBehaviorEvent;
use crate::encrypted_handler::EncryptedMessageHandler;
use crate::encryption::MessageEncryption;
use crate::metrics_simple;
use crate::peer::PeerId;
use crate::WolfBehavior;
use async_trait::async_trait;
use futures::StreamExt;
use libp2p::{
    gossipsub, identity, noise, swarm::SwarmEvent, tcp, yamux, Multiaddr, PeerId as Libp2pPeerId,
    SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, warn};
use wolf_den::SecurityLevel;
use x25519_dalek::PublicKey as X25519PublicKey;

/// Connection state for a peer

#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Remote Peer ID
    pub peer_id: PeerId,
    /// Connection start time
    pub connected_since: Instant,
    /// Last seen time
    pub last_seen: Instant,
    /// Protocol version
    pub protocol_version: Option<String>,
    /// Agent version
    pub agent_version: Option<String>,
}

/// Network metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Total messages sent
    pub total_messages_sent: u64,
    /// Total messages received
    pub total_messages_received: u64,
    /// Total bytes sent
    pub total_bytes_sent: u64,
    /// Total bytes received
    pub total_bytes_received: u64,
    /// Connection attempts count
    pub connection_attempts: u64,
    /// Connection failures count
    pub connection_failures: u64,
    /// Active connections count
    pub active_connections: usize,
    /// Unique peers seen count
    pub unique_peers_seen: usize,
    #[serde(skip)]
    /// Last network activity timestamp
    pub last_activity: Option<Instant>,
    // Additional fields for API
    /// Connected peers count
    pub connected_peers: usize,
    /// Known peers count
    pub known_peers: usize,
    /// Average latency in ms
    pub average_latency: f64,
    /// Total data transferred in bytes
    pub total_data_transferred: u64,
    /// Transfer rate in bytes/sec
    pub transfer_rate: f64,
    /// Active streams count
    pub active_streams: usize,
    /// Network health score (0.0 - 1.0)
    pub network_health: f64,
}

use crate::message::Message;

/// Commands to send to the swarm event loop.
#[derive(Debug)]
pub enum SwarmCommand {
    /// Send a message to a specific peer
    SendMessage {
        /// Target peer
        target: PeerId,
        /// Message content
        message: Message,
    },
    /// Publish a message to a pubsub topic
    PublishMessage {
        /// Topic name
        topic: String,
        /// Message content
        message: Message,
    },
    /// Broadcast a Howl message (P2P Protocol)
    BroadcastHowl {
        /// Howl message
        message: crate::wolf_pack::howl::HowlMessage,
    },
    /// General broadcast (bytes)
    Broadcast(Vec<u8>),
    /// Dial a peer directly
    Dial {
        /// Peer ID
        peer_id: PeerId,
        /// Address
        addr: Multiaddr,
    },
    /// Dial an address
    DialAddr {
        /// Address
        addr: Multiaddr,
    },
    /// Request current stats
    GetStats {
        /// Responder channel
        responder: oneshot::Sender<SwarmStats>,
    },
    /// Request list of listeners
    GetListeners {
        /// Responder channel
        responder: oneshot::Sender<Vec<Multiaddr>>,
    },
    /// Check if peer is connected
    IsConnected {
        /// Peer ID to check
        peer_id: PeerId,
        /// Responder
        responder: oneshot::Sender<bool>,
    },
    /// Prune idle connections
    CheckConnections {
        /// Max idle time
        max_idle_time: Duration,
        /// Responder
        responder: oneshot::Sender<Vec<PeerId>>,
    },
    /// Initiate shutdown
    Shutdown,
    /// Send a WolfRequest
    SendRequest {
        /// Target peer
        target: PeerId,
        /// Request object
        request: crate::protocol::WolfRequest,
        /// Responder
        responder: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Block a peer
    BlockPeer {
        /// Peer to block
        peer_id: PeerId,
    },
    /// Block an IP address in the internal firewall
    BlockIp {
        /// IP to block
        ip: String,
    },
    /// Disconnect a peer
    DisconnectPeer {
        /// Peer to disconnect
        peer_id: PeerId,
    },
    /// Send an encrypted request
    SendEncryptedRequest {
        /// Target peer
        target: PeerId,
        /// Request
        request: crate::protocol::WolfRequest,
        /// Responder
        responder: oneshot::Sender<anyhow::Result<()>>,
    },
    /// List known peers
    ListPeers {
        /// Responder
        responder: oneshot::Sender<Vec<crate::peer::EntityInfo>>,
    },
    /// Get peer info
    GetPeerInfo {
        /// Peer ID
        peer_id: PeerId,
        /// Responder
        responder: oneshot::Sender<Option<crate::peer::EntityInfo>>,
    },
    /// Send a consensus message to the network
    ConsensusMessage(crate::consensus::network::RaftNetworkMessage),
    /// Get Wolf Pack state
    GetWolfState {
        /// Responder
        responder: oneshot::Sender<Arc<tokio::sync::RwLock<crate::wolf_pack::state::WolfState>>>,
    },
    /// Omega: Force Rank
    OmegaForceRank {
        /// Target peer
        target: PeerId,
        /// New role
        role: crate::wolf_pack::state::WolfRole,
    },
    /// Omega: Force Prestige
    OmegaForcePrestige {
        /// Target peer
        target: PeerId,
        /// Prestige delta
        change: i32,
    },
    /// Add a peer address to the swarm without dialing
    AddAddress {
        /// Peer ID
        peer_id: PeerId,
        /// Address
        addr: Multiaddr,
    },
}

/// Trait for reporting reputation-impacting events.
/// This allows SwarmManager to notify the reputation system without a direct dependency.
#[async_trait]
pub trait ReputationReporter: Send + Sync + std::fmt::Debug {
    /// Report a reputation event
    async fn report_event(&self, peer_id: &str, category: &str, impact: f64, description: String);
}

/// Swarm manager for handling libp2p operations
pub struct SwarmManager {
    /// Local peer ID
    pub local_peer_id: PeerId,
    /// Configuration
    #[allow(dead_code)]
    config: SwarmConfig,
    /// Running state
    running: bool,
    /// Sender for commands to the swarm event loop
    command_sender: mpsc::Sender<SwarmCommand>,
    /// Active connections
    active_connections: Arc<Mutex<HashMap<Libp2pPeerId, PeerConnection>>>,
    /// Network metrics
    metrics: Arc<Mutex<NetworkMetrics>>,
    /// Peer registry for status tracking and discovery
    #[allow(dead_code)]
    peer_registry: Arc<Mutex<HashMap<crate::peer::PeerId, crate::peer::EntityInfo>>>,
    /// Shutdown signal sender
    shutdown_sender: Option<oneshot::Sender<()>>,
    /// Swarm handle
    swarm_handle: Option<tokio::task::JoinHandle<()>>,
    /// Encrypted message handler
    pub encrypted_handler: Arc<EncryptedMessageHandler>,
    /// Firewall manager
    pub firewall: Arc<tokio::sync::RwLock<crate::firewall::InternalFirewall>>,
    /// Consensus manager
    pub consensus: Arc<tokio::sync::RwLock<Option<crate::consensus::manager::ConsensusManager>>>,
    /// Hunt Coordinator sender for wolf pack operations
    hunt_coordinator_sender: mpsc::Sender<crate::wolf_pack::coordinator::CoordinatorMsg>,
    /// Shared wolf pack state
    wolf_state: Arc<tokio::sync::RwLock<crate::wolf_pack::state::WolfState>>,
    /// Reputation reporter hook
    pub reputation_reporter: Option<Arc<dyn ReputationReporter>>,
}

/// Swarm configuration
#[derive(Debug, Clone)]
pub struct SwarmConfig {
    /// Listen addresses
    pub listen_addresses: Vec<Multiaddr>,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Maximum connections
    pub max_connections: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Enable mDNS discovery
    pub enable_mdns: bool,
    /// Enable DHT discovery
    pub enable_dht: bool,
    /// Path to the keypair file
    pub keypair_path: PathBuf,
    /// Channel for sending security events
    pub security_event_sender: Option<mpsc::UnboundedSender<crate::event::SecurityEvent>>,
    /// Reputation reporter hook
    pub reputation_reporter: Option<Arc<dyn ReputationReporter>>,
    /// Deterministic identity seed
    pub identity_seed: Option<String>,
    /// Initial consensus peers (PeerIds) for Raft cluster bootstrapping
    pub initial_consensus_peers: Vec<PeerId>,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        let mut path = std::env::temp_dir();
        path.push("wolf_prowler_swarm.key");

        Self {
            listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            bootstrap_peers: Vec::new(),
            max_connections: 50,
            enable_mdns: true,
            enable_dht: true,
            connection_timeout: Duration::from_secs(20),
            keypair_path: path,
            security_event_sender: None,
            reputation_reporter: None,
            identity_seed: None,
            initial_consensus_peers: Vec::new(),
        }
    }
}

impl SwarmConfig {
    /// Validates the configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_connections == 0 {
            return Err(anyhow::anyhow!("max_connections must be greater than 0"));
        }

        if self.connection_timeout.as_secs() == 0 {
            return Err(anyhow::anyhow!("connection_timeout must be greater than 0"));
        }

        for addr in &self.listen_addresses {
            if !addr.to_string().starts_with("/ip4/") && !addr.to_string().starts_with("/ip6/") {
                return Err(anyhow::anyhow!(
                    "Invalid listen address format: {}. Must start with /ip4/ or /ip6/",
                    addr
                ));
            }
        }

        Ok(())
    }
}

impl SwarmManager {
    /// Initializes a new SwarmManager
    ///
    /// # Errors
    /// Returns an error if:
    /// - Keypair cannot be loaded or generated
    /// - Network transport cannot be created
    /// - Swarm cannot be initialized
    pub fn command_sender(&self) -> mpsc::Sender<SwarmCommand> {
        self.command_sender.clone()
    }

    /// Returns a sender handle to the HuntCoordinator
    pub fn hunt_coordinator_sender(
        &self,
    ) -> mpsc::Sender<crate::wolf_pack::coordinator::CoordinatorMsg> {
        self.hunt_coordinator_sender.clone()
    }

    /// Initializes a new SwarmManager
    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::too_many_lines)]
    pub fn new(config: SwarmConfig) -> anyhow::Result<Self> {
        info!("Initializing SwarmManager with config: {:?}", config);
        config.validate()?;

        let (command_sender, mut command_receiver) = mpsc::channel(100);
        let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();

        // Initialize metrics and connection tracking
        let metrics = Arc::new(Mutex::new(NetworkMetrics::default()));
        let active_connections = Arc::new(Mutex::new(HashMap::new()));
        let peer_registry = Arc::new(Mutex::new(HashMap::new()));

        // Initialize Firewall
        let firewall = Arc::new(tokio::sync::RwLock::new(
            crate::firewall::InternalFirewall::new(),
        ));

        // Load or create a new identity with improved error handling
        let local_key = if let Some(seed) = &config.identity_seed {
            info!("🌱 Generating deterministic identity from seed: {}", seed);
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&seed, &mut hasher);
            let seed_u64 = std::hash::Hasher::finish(&hasher);

            // Generate deterministic keypair (using seed as RNG seed would be better, but for now simple deterministic generation)
            // Note: In production we'd use a CSPRNG. For simulation, this is sufficient to get consistent PeerIDs.
            let mut bytes = [0u8; 32];
            let seed_bytes = seed_u64.to_le_bytes();
            #[allow(clippy::cast_possible_truncation)]
            for i in 0..32 {
                bytes[i] = seed_bytes[i % 8].wrapping_add(i as u8);
            }

            identity::Keypair::ed25519_from_bytes(bytes)
                .map_err(|e| anyhow::anyhow!("Failed to generate key from seed: {}", e))?
        } else {
            match fs::read(&config.keypair_path) {
                Ok(key_bytes) => {
                    identity::Keypair::from_protobuf_encoding(&key_bytes).map_err(|e| {
                        let path = config.keypair_path.display();
                        anyhow::anyhow!("Failed to parse keypair from {path}: {e}")
                    })?
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    info!(
                        "No keypair found at {}, generating a new one",
                        config.keypair_path.display()
                    );
                    let key = identity::Keypair::generate_ed25519();
                    let key_bytes = key
                        .to_protobuf_encoding()
                        .map_err(|e| anyhow::anyhow!("Failed to encode keypair: {}", e))?;

                    if let Some(parent) = config.keypair_path.parent() {
                        fs::create_dir_all(parent).map_err(|e| {
                            anyhow::anyhow!("Failed to create directory for keypair: {}", e)
                        })?;
                    }

                    fs::write(&config.keypair_path, &key_bytes).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to write keypair to {}: {}",
                            config.keypair_path.display(),
                            e
                        )
                    })?;

                    key
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to read keypair from {}: {}",
                        config.keypair_path.display(),
                        e
                    ))
                }
            }
        };

        let local_peer_id = PeerId::from_libp2p(local_key.public().to_peer_id());
        info!("🐺 Local Peer ID: {}", local_peer_id);

        // Initialize behavior
        let behavior = WolfBehavior::new(&local_key, &config)
            .map_err(|e| anyhow::anyhow!("Failed to create behavior: {}", e))?;

        let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| anyhow::anyhow!("Failed to create TCP transport: {}", e))?
            .with_quic() // HyperPulse: Enable QUIC low-latency transport
            .with_behaviour(|_| behavior)?
            .build();

        // Listen on configured addresses
        for addr in &config.listen_addresses {
            swarm
                .listen_on(addr.clone())
                .map_err(|e| anyhow::anyhow!("Failed to listen on {}: {}", addr, e))?;
        }

        // Subscribe to priority topics
        for topic_name in [
            "wolf-prowler-low",
            "wolf-prowler-medium",
            "wolf-prowler-high",
            "wolf-prowler-critical",
            "wolf-prowler-consensus",
            "wolf-pack/gossip/1.0.0",
        ] {
            let topic = gossipsub::IdentTopic::new(topic_name);
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to subscribe to topic {}: {}", topic_name, e)
                })?;
        }

        info!(
            "✅ Swarm initialized and listening on: {:?}",
            config.listen_addresses
        );

        // Initialize encryption
        let encryption = Arc::new(
            MessageEncryption::new(SecurityLevel::Standard)
                .map_err(|e| anyhow::anyhow!("Failed to initialize encryption: {}", e))?,
        );
        let encrypted_handler = Arc::new(EncryptedMessageHandler::new(encryption));

        let consensus_manager = Arc::new(tokio::sync::RwLock::new(
            None::<crate::consensus::manager::ConsensusManager>,
        ));
        let consensus_manager_init = consensus_manager.clone();
        let consensus_swarm_tx = command_sender.clone();
        let consensus_keypair_path = config.keypair_path.clone();
        let consensus_initial_peers = config.initial_consensus_peers.clone();
        let consensus_local_peer_id = local_peer_id.as_libp2p();

        tokio::spawn(async move {
            let node_id = {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&consensus_local_peer_id, &mut hasher);
                std::hash::Hasher::finish(&hasher)
            };

            let mut initial_nodes = Vec::new();
            if consensus_initial_peers.is_empty() {
                initial_nodes.push(node_id);
            } else {
                for peer in consensus_initial_peers {
                    let p = peer.as_libp2p();
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    std::hash::Hash::hash(&p, &mut hasher);
                    initial_nodes.push(std::hash::Hasher::finish(&hasher));
                }
            }

            let storage_path = consensus_keypair_path
                .parent()
                .unwrap_or(&std::env::temp_dir())
                .join(format!("consensus_db_{}", node_id));

            match crate::consensus::manager::ConsensusManager::start(
                node_id,
                initial_nodes,
                storage_path.to_str().unwrap_or("/tmp/wolf_consensus"),
                consensus_swarm_tx,
            ) {
                Ok(cm) => {
                    let mut lock = consensus_manager_init.write().await;
                    *lock = Some(cm);
                    info!("Consensus Manager started and registered");
                }
                Err(e) => {
                    error!("Failed to start Consensus Manager in background: {}", e);
                }
            }
        });

        // Clone Arc references for the background task
        let metrics_clone = metrics.clone();
        let active_connections_clone = active_connections.clone();
        let peer_registry_clone = peer_registry.clone();
        let security_sender = config.security_event_sender.clone();
        let encrypted_handler_clone = encrypted_handler.clone();
        let firewall_clone = firewall.clone();
        let reputation_reporter = config.reputation_reporter.clone();

        // Start the swarm event loop in a background task
        let consensus_manager_clone = consensus_manager.clone();

        // Initialize Wolf Pack State and Hunt Coordinator
        let (actor, hunt_sender, wolf_state) = crate::wolf_pack::coordinator::HuntCoordinator::new(
            crate::wolf_pack::state::WolfRole::Stray,
            command_sender.clone(),
            local_peer_id.clone(),
            0, // Initial prestige
            reputation_reporter.clone(),
        );
        tokio::spawn(actor.run());

        // Clone for use in async closure
        let hunt_sender_clone = hunt_sender.clone();
        let wolf_state_clone = wolf_state.clone();

        let local_peer_id_clone = local_peer_id.clone();
        let swarm_handle = tokio::spawn(async move {
            let mut connected_peers = HashSet::new();
            let mut received_messages = Vec::new();
            let encrypted_handler = encrypted_handler_clone;
            let consensus_manager = consensus_manager_clone;
            let hunt_sender = hunt_sender_clone;
            let wolf_state = wolf_state_clone;

            loop {
                tokio::select! {
                               event = swarm.select_next_some() => {
                                   match event {
                                       SwarmEvent::NewListenAddr { address, .. } => {
                                           info!("📡 Listening on: {}", address);
                                       }
                                       SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                           // Firewall check
                                           {
                                               let firewall = firewall_clone.read().await;
                                               let target_peer = crate::firewall::RuleTarget::PeerId(peer_id.to_string());
                                               // We can't easily check IP here without endpoint info, but we can check PeerID
                                               if !firewall.check_access(
                                                   &target_peer,
                                                   &crate::firewall::Protocol::WolfProto,
                                                   &crate::firewall::TrafficDirection::Inbound
                                               ) {
                                                   warn!("🔥 Firewall blocked incoming connection from {}", peer_id);

                                                   if let Some(reporter) = &reputation_reporter {
                                                       reporter.report_event(
                                                           &peer_id.to_string(),
                                                           "Security",
                                                           -0.15,
                                                           "Firewall blocked incoming connection".to_string()
                                                       ).await;
                                                   }

                                                   let _ = swarm.disconnect_peer_id(peer_id);

                                                   // Send security event for block
                                                   if let Some(sender) = &security_sender {
                                                       let event = crate::event::SecurityEvent::new(
                                                           crate::event::SecurityEventType::PolicyViolation,
                                                           crate::event::SecuritySeverity::Medium,
                                                           format!("Firewall blocked peer {}", peer_id),
                                                       ).with_peer(peer_id.to_string());
                                                       let _ = sender.send(event);
                                                   }
                                                   continue;
                                               }
                                           }

                                           // Update metrics
                                           metrics_clone.lock().await.connection_attempts += 1;
                                           info!("🤝 Connection established with: {}", peer_id);

                                           if let Some(reporter) = &reputation_reporter {
                                               reporter.report_event(
                                                   &peer_id.to_string(),
                                                   "Networking",
                                                   0.02,
                                                   "Successful connection established".to_string()
                                               ).await;
                                           }

                                           connected_peers.insert(peer_id);


                                           // Update connection tracking
                                           let conn = PeerConnection {
                                               peer_id: PeerId::from_libp2p(peer_id),
                                               connected_since: Instant::now(),
                                               last_seen: Instant::now(),
                                               protocol_version: None,
                                               agent_version: None,
                                           };
                                            active_connections_clone.lock().await.insert(peer_id, conn);

                                            // Initiate key exchange
                                            let public_key = encrypted_handler.public_key();
                                            let req = crate::protocol::WolfRequest::KeyExchange {
                                                public_key: public_key.as_bytes().to_vec(),
                                            };
                                            swarm.behaviour_mut().req_resp.send_request(&peer_id, req);
                                            info!("🔑 Initiated key exchange with {}", peer_id);

                                            // Update metrics
                                            // Update metrics
                                            {
                                                let mut metrics = metrics_clone.lock().await;
                                                metrics.active_connections = connected_peers.len();
                                                metrics.unique_peers_seen = metrics.unique_peers_seen.max(connected_peers.len());
                                                metrics.last_activity = Some(Instant::now());
                                            }

                                            // Update Peer Registry
                                            {
                                                let mut registry = peer_registry_clone.lock().await;
                                                let target = crate::peer::PeerId::from_libp2p(peer_id);
                                                let entry = registry.entry(target).or_insert_with(|| {
                                                    let entity_id = crate::peer::EntityId::create(
                                                        crate::peer::ServiceType::Unknown,
                                                        crate::peer::SystemType::Unknown,
                                                        "0.1.0",
                                                    );
                                                    let mut info = crate::peer::EntityInfo::new(entity_id);
                                                    info.entity_id.peer_id = PeerId::from_libp2p(peer_id);
                                                    info
                                                });
                                                entry.set_status(crate::peer::EntityStatus::Online);
                                            }

                                           // Send security event
                                           if let Some(sender) = &security_sender {
                                               let event = crate::event::SecurityEvent::new(
                                                   crate::event::SecurityEventType::Other("ConnectionEstablished".to_string()),
                                                   crate::event::SecuritySeverity::Low,
                                                   format!("Connected to {}", peer_id),
                                               ).with_peer(peer_id.to_string());
                                               let _ = sender.send(event);
                                           }
                                       }
                                       SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                           warn!("❌ Connection lost with {}: {:?}", peer_id, cause);
                                           connected_peers.remove(&peer_id);

                                           if let Some(reporter) = &reputation_reporter {
                                               reporter.report_event(
                                                   &peer_id.to_string(),
                                                   "Networking",
                                                   0.0,
                                                   format!("Connection closed: {:?}", cause)
                                               ).await;
                                           }

                                           active_connections_clone.lock().await.remove(&peer_id);

                                           // Update metrics
                                           {
                                               let mut metrics = metrics_clone.lock().await;
                                               metrics.active_connections = connected_peers.len();
                                               metrics.last_activity = Some(Instant::now());
                                           }

                                            // Update Peer Registry
                                            {
                                                let mut registry = peer_registry_clone.lock().await;
                                                let target = crate::peer::PeerId::from_libp2p(peer_id);
                                                if let Some(info) = registry.get_mut(&target) {
                                                    info.set_status(crate::peer::EntityStatus::Offline);
                                                    // Update uptime
                                                    let uptime = active_connections_clone.lock().await.get(&peer_id)
                                                        .map(|c| u64::try_from(c.connected_since.elapsed().as_millis()).unwrap_or(u64::MAX))
                                                        .unwrap_or(0);
                                                    info.metrics.uptime_ms += uptime;
                                                }
                                            }

                                           // Send security event
                                           if let Some(sender) = &security_sender {
                                               let event = crate::event::SecurityEvent::new(
                                                   crate::event::SecurityEventType::Other("ConnectionClosed".to_string()),
                                                   crate::event::SecuritySeverity::Low,
                                                   format!("Connection closed with {}: {:?}", peer_id, cause),
                                               ).with_peer(peer_id.to_string());
                                               let _ = sender.send(event);
                                           }
                                       }
                                        SwarmEvent::Behaviour(event) => {
                                            match event {
                                                WolfBehaviorEvent::Kad(event) => {
                                                    match event {
                                                        libp2p::kad::Event::OutboundQueryProgressed { result, .. } => {
                                                            match result {
                                                                libp2p::kad::QueryResult::Bootstrap(Ok(ok)) => {
                                                                    debug!("DHT Bootstrap successful: {:?}", ok);
                                                                }
                                                                libp2p::kad::QueryResult::Bootstrap(Err(e)) => {
                                                                    warn!("DHT Bootstrap failed: {:?}", e);
                                                                }
                                                                _ => {}
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                               WolfBehaviorEvent::Ping(event) => {
                                                    match event.result {
                                                        Ok(rtt) => {
                                                            debug!("Ping success to {}: {:?}", event.peer, rtt);
                                                            // Update peer registry with latency

                                                           if let Some(reporter) = &reputation_reporter {
                                                               reporter.report_event(
                                                                   &event.peer.to_string(),
                                                                   "Networking",
                                                                   0.01,
                                                                   format!("Ping success (RTT: {:?})", rtt)
                                                               ).await;
                                                           }

                                                            let mut registry = peer_registry_clone.lock().await;
                                                            let target = crate::peer::PeerId::from_libp2p(event.peer);
                                                             if let Some(info) = registry.get_mut(&target) {
                                                                 info.metrics.latency_ms = u64::try_from(rtt.as_millis()).unwrap_or(u64::MAX);
                                                                 info.metrics.update_health();
                                                             }
                                                        }
                                                        Err(e) => {
                                                            warn!("Ping error to {}: {:?}", event.peer, e);

                                                           if let Some(reporter) = &reputation_reporter {
                                                               reporter.report_event(
                                                                   &event.peer.to_string(),
                                                                   "Networking",
                                                                   -0.05,
                                                                   format!("Ping failure: {:?}", e)
                                                               ).await;
                                                           }

                                                            metrics_clone.lock().await.connection_failures += 1;
                                                        }
                                                    }
                                               }
                                               WolfBehaviorEvent::Identify(event) => {
                                                   if let libp2p::identify::Event::Received { peer_id, info } = event {
                                                       info!("Identified peer {}: {}", peer_id, info.protocol_version);

                                                       if let Some(reporter) = &reputation_reporter {
                                                           reporter.report_event(
                                                               &peer_id.to_string(),
                                                               "Networking",
                                                               0.05,
                                                               format!("Identified peer: {}", info.agent_version)
                                                           ).await;
                                                       }

                                                        // Update registry with metadata
                                                        let mut registry = peer_registry_clone.lock().await;
                                                        let target = crate::peer::PeerId::from_libp2p(peer_id);
                                                        let entry = registry.entry(target).or_insert_with(|| {
                                                            let entity_id = crate::peer::EntityId::create(
                                                                crate::peer::ServiceType::Unknown,
                                                                crate::peer::SystemType::Unknown,
                                                                "0.1.0",
                                                            );
                                                            let mut info = crate::peer::EntityInfo::new(entity_id);
                                                            info.entity_id.peer_id = PeerId::from_libp2p(peer_id);
                                                            info
                                                        });

                                                        entry.protocol_version = Some(info.protocol_version.clone());
                                                        entry.agent_version = Some(info.agent_version.clone());

                                                        // Add capabilities (protocols)
                                                        for proto in info.protocols {
                                                            entry.add_capability(proto.to_string());
                                                        }

                                                        for addr in &info.listen_addrs {
                                                            debug!("  Peer {} listening on: {}", peer_id, addr);
                                                            // Try to convert Multiaddr to SocketAddr if possible (simplified for now)
                                                            // Note: Multiaddr is more general, but EntityInfo uses SocketAddr
                                                        }
                                                   }
                                               }
                                               WolfBehaviorEvent::Gossipsub(event) => {
                                                   match event {
                                                       gossipsub::Event::Message {
                                                           propagation_source: _peer_id,
                                                           message_id: _message_id,
                                                           message,
                                                       } => {
                                                            // Update metrics
                                                            let mut m = metrics_clone.lock().await;
                                                            m.total_messages_received += 1;
                                                            m.total_bytes_received += message.data.len() as u64;
                                                            m.last_activity = Some(Instant::now());
                                                            drop(m);

                                                             // Update peer registry message count and bytes
                                                             if let Some(peer_id) = message.source {
                                                                 let mut registry = peer_registry_clone.lock().await;
                                                                 let target = crate::peer::PeerId::from_libp2p(peer_id);
                                                                 if let Some(info) = registry.get_mut(&target) {
                                                                     info.metrics.messages_received += 1;
                                                                     info.metrics.bytes_received += message.data.len() as u64;
                                                                     info.metrics.update_health();
                                                                 }
                                                             }

                                                           // Try to deserialize and store the message
                                                           if message.topic.as_str() == "wolf-prowler-consensus" {
                                                               if let Ok(net_msg) = serde_json::from_slice::<crate::consensus::network::RaftNetworkMessage>(&message.data) {
                                                                   let cm_lock = consensus_manager.read().await;
                                                                   if let Some(cm) = &*cm_lock {
                                                                       let _ = cm.process_message(net_msg).await;
                                                                   }
                                                               }
                                                           } else if message.topic.as_str() == "wolf-pack/gossip/1.0.0" {
                                                               // Handle Howl Protocol Messages
                                                               if let Ok(howl) = crate::wolf_pack::howl::HowlMessage::from_bytes(&message.data) {
                                                                   info!("📢 RECEIVED HOWL: {:?} from {}", howl.priority, howl.sender);

                                                                   // Map HowlPayload to CoordinatorMsg
                                                                   let coord_msg = match howl.payload {
                                                                       crate::wolf_pack::howl::HowlPayload::WarningHowl { target_ip, evidence } => {
                                                                           Some(crate::wolf_pack::coordinator::CoordinatorMsg::WarningHowl {
                                                                               source: howl.sender,
                                                                               target_ip,
                                                                               evidence,
                                                                           })
                                                                       }
                                                                       crate::wolf_pack::howl::HowlPayload::HuntRequest { hunt_id, target_ip, min_role } => {
                                                                           Some(crate::wolf_pack::coordinator::CoordinatorMsg::HuntRequest {
                                                                               hunt_id,
                                                                               source: howl.sender,
                                                                               target_ip,
                                                                               min_role,
                                                                           })
                                                                       }
                                                                       crate::wolf_pack::howl::HowlPayload::HuntReport { hunt_id, hunter, confirmed } => {
                                                                           Some(crate::wolf_pack::coordinator::CoordinatorMsg::HuntReport {
                                                                               hunt_id,
                                                                               hunter,
                                                                               confirmed,
                                                                           })
                                                                       }
                                                                       crate::wolf_pack::howl::HowlPayload::KillOrder { target_ip, reason, hunt_id } => {
                                                                           Some(crate::wolf_pack::coordinator::CoordinatorMsg::KillOrder {
                                                                               target_ip,
                                                                               authorizer: howl.sender,
                                                                               reason,
                                                                               hunt_id,
                                                                           })
                                                                       }
                                                                       crate::wolf_pack::howl::HowlPayload::TerritoryUpdate { region_cidr, owner, status } => {
                                                                           Some(crate::wolf_pack::coordinator::CoordinatorMsg::TerritoryUpdate {
                                                                               region: region_cidr,
                                                                               owner,
                                                                               status,
                                                                           })
                                                                       }
                                                                       crate::wolf_pack::howl::HowlPayload::ElectionRequest { term, candidate_id, prestige, .. } => {
                                                                           Some(crate::wolf_pack::coordinator::CoordinatorMsg::ElectionRequest {
                                                                               term,
                                                                               candidate_id,
                                                                               prestige,
                                                                           })
                                                                       }
                                                                       crate::wolf_pack::howl::HowlPayload::ElectionVote { term, voter_id, granted } => {
                                                                           Some(crate::wolf_pack::coordinator::CoordinatorMsg::ElectionVote {
                                                                               term,
                                                                               voter_id,
                                                                               granted,
                                                                           })
                                                                       }
                                                                       crate::wolf_pack::howl::HowlPayload::AlphaHeartbeat { term, leader_id } => {
                                                                           Some(crate::wolf_pack::coordinator::CoordinatorMsg::AlphaHeartbeat {
                                                                               term,
                                                                               leader_id,
                                                                           })
                                                                       }
                                                                   };

                                                                   if let Some(msg) = coord_msg {
                                                                       let _ = hunt_sender.send(msg).await;
                                                                   }
                                                               } else {
                                                                   warn!("Failed to deserialize Howl message");
                                                               }
                                                           } else if let Ok(msg) = serde_json::from_slice::<Message>(&message.data) {
                                                               received_messages.push(msg);
                                                           } else {
                                                               warn!("Failed to deserialize gossipsub message");
                                                           }
                                                       }
                                                       _ => {}
                                                   }
                                               }
                                               WolfBehaviorEvent::Mdns(event) => {
                                                   match event {
                                                       libp2p::mdns::Event::Discovered(list) => {
                                                           for (peer_id, _multiaddr) in list {
                                                               info!("mDNS discovered peer: {}", peer_id);
                                                               swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                                           }
                                                       }
                                                       libp2p::mdns::Event::Expired(list) => {
                                                           for (peer_id, _multiaddr) in list {
                                                               info!("mDNS peer expired: {}", peer_id);
                                                               swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                                           }
                                                       }
                                                   }
                                               }
                                               WolfBehaviorEvent::ReqResp(event) => {
                                                    match event {
                                                       libp2p::request_response::Event::Message { peer, message } => {
                                                           match message {
                                                               libp2p::request_response::Message::Request { request, channel, .. } => {
                                                                   info!("Received request from {}: {:?}", peer, request);

                                                                   // Update registry
                                                                   {
                                                                       let mut registry = peer_registry_clone.lock().await;
                                                                       let target = crate::peer::PeerId::from_libp2p(peer);
                                                                       if let Some(info) = registry.get_mut(&target) {
                                                                           info.metrics.messages_received += 1;
                                                                           info.metrics.requests_received += 1;
                                                                           info.metrics.last_updated = chrono::Utc::now();
                                                                           info.metrics.update_health();
                                                                       }
                                                                   }

                                                                   match request {
                                                                       crate::protocol::WolfRequest::KeyExchange { public_key } => {
                                                                           // Register peer key
                                                                           let key_bytes: Result<[u8; 32], _> = public_key.try_into();
                                                                           if let Ok(bytes) = key_bytes {
                                                                               let pk = X25519PublicKey::from(bytes);
                                                                               encrypted_handler.register_peer_key(&peer, pk).await;
                                                                               info!("🔑 Registered public key for {}", peer);

                                                                               // Send our key back
                                                                               let our_pk = encrypted_handler.public_key();
                                                                               let response = crate::protocol::WolfResponse::KeyExchangeAck {
                                                                                   public_key: our_pk.as_bytes().to_vec(),
                                                                               };
                                                                                let _ = swarm.behaviour_mut().req_resp.send_response(channel, response);
                                                                           }
                                                                       }
                                                                       crate::protocol::WolfRequest::Encrypted(encrypted) => {
                                                                           // Decrypt and handle
                                                                           match encrypted_handler.decrypt_request(&peer, &encrypted).await {
                                                                               Ok(decrypted_req) => {
                                                                                   info!("🔓 Decrypted request from {}: {:?}", peer, decrypted_req);
                                                                                   // Handle decrypted request
                                                                                   let response = match decrypted_req {
                                                                                       crate::protocol::WolfRequest::Ping => crate::protocol::WolfResponse::Pong,
                                                                                       crate::protocol::WolfRequest::Echo(msg) => crate::protocol::WolfResponse::Echo(msg),
                                                                                       _ => crate::protocol::WolfResponse::Error("Not implemented".to_string()),
                                                                                   };

                                                                                   // Encrypt response if we have the key
                                                                                    match encrypted_handler.encrypt_response(&peer, &response).await {
                                                                                        Ok(enc_res) => {
                                                                                             let _ = swarm.behaviour_mut().req_resp.send_response(channel, crate::protocol::WolfResponse::Encrypted(enc_res));
                                                                                        }
                                                                                        Err(_) => {
                                                                                            // Fallback to plaintext if encryption fails or no key
                                                                                            let _ = swarm.behaviour_mut().req_resp.send_response(channel, response);
                                                                                        }
                                                                                    }

                                                                                    // Update registry
                                                                                    {
                                                                                        let mut registry = peer_registry_clone.lock().await;
                                                                                        let target = crate::peer::PeerId::from_libp2p(peer);
                                                                                        if let Some(info) = registry.get_mut(&target) {
                                                                                            info.metrics.messages_sent += 1;
                                                                                            info.metrics.update_health();
                                                                                        }
                                                                                    }
                                                                               }
                                                                               Err(e) => {
                                                                                   error!("Failed to decrypt request from {}: {}", peer, e);
                                                                                    let _ = swarm.behaviour_mut().req_resp.send_response(channel, crate::protocol::WolfResponse::Error("Decryption failed".to_string()));
                                                                               }
                                                                           }
                                                                       }
                                                                       crate::protocol::WolfRequest::Ping => {
                                                                            let _ = swarm.behaviour_mut().req_resp.send_response(channel, crate::protocol::WolfResponse::Pong);
                                                                       }
                                                                       crate::protocol::WolfRequest::Echo(msg) => {
                                                                            let _ = swarm.behaviour_mut().req_resp.send_response(channel, crate::protocol::WolfResponse::Echo(msg));
                                                                       }

                                                                   }
                                                               }
                                                               libp2p::request_response::Message::Response { response, .. } => {
                                                                    info!("Received response from {}: {:?}", peer, response);

                                                                    // Update registry
                                                                     {
                                                                         let mut registry = peer_registry_clone.lock().await;
                                                                         let target = crate::peer::PeerId::from_libp2p(peer);
                                                                         if let Some(info) = registry.get_mut(&target) {
                                                                             info.metrics.messages_received += 1;
                                                                             info.metrics.requests_success += 1;
                                                                             // Best effort size estimation
                                                                             if let Ok(bytes) = serde_json::to_vec(&response) {
                                                                                 info.metrics.bytes_received += bytes.len() as u64;
                                                                             }
                                                                             info.metrics.update_health();
                                                                         }
                                                                     }

                                                                    match response {
                                                                       crate::protocol::WolfResponse::KeyExchangeAck { public_key } => {
                                                                           let key_bytes: Result<[u8; 32], _> = public_key.try_into();
                                                                           if let Ok(bytes) = key_bytes {
                                                                               let pk = X25519PublicKey::from(bytes);
                                                                               encrypted_handler.register_peer_key(&peer, pk).await;
                                                                               info!("🔑 Registered public key for {} (Ack received)", peer);
                                                                           }
                                                                       }
                                                                       crate::protocol::WolfResponse::Encrypted(encrypted) => {
                                                                           match encrypted_handler.decrypt_response(&peer, &encrypted).await {
                                                                               Ok(decrypted_res) => {
                                                                                   info!("🔓 Decrypted response from {}: {:?}", peer, decrypted_res);
                                                                               }
                                                                               Err(e) => {
                                                                                   error!("Failed to decrypt response from {}: {}", peer, e);
                                                                               }
                                                                           }
                                                                       }
                                                                       _ => {}
                                                                   }
                                                               }
                                                           }
                                                       }
                                                        libp2p::request_response::Event::OutboundFailure { peer, .. } => {
                                                            warn!("Outbound request failure to {}", peer);
                                                            let mut registry = peer_registry_clone.lock().await;
                                                            let target = crate::peer::PeerId::from_libp2p(peer);
                                                            if let Some(info) = registry.get_mut(&target) {
                                                                info.metrics.requests_failed += 1;
                                                                info.metrics.update_health();
                                                            }
                                                        }
                                                        libp2p::request_response::Event::InboundFailure { peer, .. } => {
                                                            warn!("Inbound request failure from {}", peer);
                                                            let mut registry = peer_registry_clone.lock().await;
                                                            let target = crate::peer::PeerId::from_libp2p(peer);
                                                            if let Some(info) = registry.get_mut(&target) {
                                                                info.metrics.requests_failed += 1;
                                                                info.metrics.update_health();
                                                            }
                                                        }
                                                       libp2p::request_response::Event::ResponseSent { .. } => {}
                                                    }
                                               }
                                           }
                                       }
                                       _ => {}
                                   }
                               },
                               Some(command) = command_receiver.recv() => {
                                   match command {
                                       SwarmCommand::SendMessage { target, message } => {
                                           // Update metrics
                                           let msg_len = serde_json::to_vec(&message)
                                               .map(|b| b.len() as u64)
                                               .unwrap_or(0);

                                           let mut metrics = metrics_clone.lock().await;
                                           metrics.total_messages_sent += 1;
                                           metrics.total_bytes_sent += msg_len;
                                           metrics.last_activity = Some(Instant::now());
                                           drop(metrics); // Explicitly drop the lock

                                           // Store peer info and update peer metrics
                                           {
                                               let mut registry = peer_registry_clone.lock().await;
                                               if !registry.contains_key(&target) {
                                                   let entity_id = crate::peer::EntityId::create(
                                                       crate::peer::ServiceType::Unknown,
                                                       crate::peer::SystemType::Unknown,
                                                       "0.1.0",
                                                   );
                                                   let mut info = crate::peer::EntityInfo::new(entity_id);
                                                   info.entity_id.peer_id = target.clone();
                                                   registry.insert(target.clone(), info);
                                               }

                                               // Update peer metrics
                                               if let Some(info) = registry.get_mut(&target) {
                                                   info.metrics.messages_sent += 1;
                                                   info.metrics.bytes_sent += msg_len;
                                               }
                                           }
                // But ideally we should use RequestResponse here if applicable.
                                           // For now, we preserve the existing fallback behavior but log it.
                                           warn!("Direct messaging using gossipsub fallback for peer {}", target);

                                           // Map message priority to topic
                                           let topic_name = match message.priority {
                                               crate::message::MessagePriority::Low => "wolf-prowler-low",
                                               crate::message::MessagePriority::Normal => "wolf-prowler-medium",
                                               crate::message::MessagePriority::High => "wolf-prowler-high",
                                               crate::message::MessagePriority::Critical => "wolf-prowler-critical",
                                           };
                                           let topic = gossipsub::IdentTopic::new(topic_name);

                                           if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                                               topic,
                                               serde_json::to_vec(&message).unwrap_or_default(),
                                           ) {
                                               error!("Failed to publish message: {}", e);
                                               metrics_clone.lock().await.connection_failures += 1;
                                           }
                                       }
                                       SwarmCommand::ConsensusMessage(net_msg) => {
                                           let topic = gossipsub::IdentTopic::new("wolf-prowler-consensus");
                                           if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                                               topic,
                                               serde_json::to_vec(&net_msg).unwrap_or_default(),
                                           ) {
                                               error!("Failed to publish consensus message: {}", e);
                                               metrics_clone.lock().await.connection_failures += 1;
                                           }
                                       }
                                       SwarmCommand::PublishMessage { topic, message } => {
                                           info!("📨 Publishing message to topic '{}'", topic);

                                           // Update metrics
                                           let msg_len = serde_json::to_vec(&message)
                                               .map(|b| b.len() as u64)
                                               .unwrap_or(0);

                                           let mut metrics = metrics_clone.lock().await;
                                           metrics.total_messages_sent += 1;
                                           metrics.total_bytes_sent += msg_len;
                                           metrics.last_activity = Some(Instant::now());
                                           drop(metrics); // Explicitly drop the lock

                                           let topic = gossipsub::IdentTopic::new(topic);
                                           if let Err(e) = swarm.behaviour_mut().gossipsub.publish(
                                               topic,
                                               serde_json::to_vec(&message).unwrap_or_default(),
                                           ) {
                                               error!("Failed to publish message: {}", e);
                                               metrics_clone.lock().await.connection_failures += 1;
                                           }
                                        }
                                        SwarmCommand::Broadcast(data) => {
                                            let topic = gossipsub::IdentTopic::new("wolf-pack/gossip/1.0.0");
                                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                                                warn!("Failed to broadcast message: {}", e);
                                                metrics_clone.lock().await.connection_failures += 1;
                                            }
                                        }
                                        SwarmCommand::BroadcastHowl { message } => {
                                           info!("📢 Broadcasting Howl message (Priority: {:?})", message.priority);

                                           // Serialize
                                           if let Ok(bytes) = message.to_bytes() {
                                               // Update metrics
                                               let mut metrics = metrics_clone.lock().await;
                                               metrics.total_messages_sent += 1;
                                               metrics.total_bytes_sent += bytes.len() as u64;
                                               metrics.last_activity = Some(Instant::now());
                                               drop(metrics);

                                               let topic = gossipsub::IdentTopic::new("wolf-pack/gossip/1.0.0");
                                               if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
                                                if matches!(e, libp2p::gossipsub::PublishError::InsufficientPeers) {
                                                    warn!("📢 Howl broadcast locally only (no peers connected).");
                                                    // This is not a failure of the system, just a state of isolation.
                                                } else {
                                                    error!("Failed to broadcast Howl: {}", e);
                                                    metrics_clone.lock().await.connection_failures += 1;
                                                }
                                               }
                                           } else {
                                               error!("Failed to serialize Howl message for broadcast");
                                           }
                                       }
                                       SwarmCommand::Dial { peer_id, addr } => {
                                           info!("📞 Dialing {} at {}", peer_id, addr);
                                           if let Err(e) = swarm.dial(addr.clone()) {
                                               error!("Failed to dial {}: {}", peer_id, e);
                                               metrics_clone.lock().await.connection_failures += 1;
                                            } else {
                                                 swarm.behaviour_mut().kad.add_address(&peer_id.as_libp2p(), addr.clone());
                                            }
                                       }
                                       SwarmCommand::DialAddr { addr } => {
                                           info!("📞 Dialing address: {}", addr);
                                           if let Err(e) = swarm.dial(addr.clone()) {
                                               error!("Failed to dial {}: {}", addr, e);
                                               metrics_clone.lock().await.connection_failures += 1;
                                           }
                                       }
                                       SwarmCommand::GetStats { responder } => {
                                           let stats = SwarmStats {
                                               connected_peers: connected_peers.len(),
                                               connected_peers_list: connected_peers
                                                   .iter()
                                                   .map(|p| PeerId::from_libp2p(*p))
                                                   .collect(),
                                               metrics: metrics_clone.lock().await.clone(),
                                           };
                                           let _ = responder.send(stats);
                                       }
                                       SwarmCommand::GetListeners { responder } => {
                                           let listeners = swarm.listeners().cloned().collect();
                                           let _ = responder.send(listeners);
                                       }
                                       SwarmCommand::IsConnected { peer_id, responder } => {
                                           let is_connected = connected_peers.contains(&peer_id.as_libp2p());
                                           let _ = responder.send(is_connected);
                                       }
                                       SwarmCommand::CheckConnections { max_idle_time, responder } => {
                                           let disconnected = Self::check_connections(
                                               &active_connections_clone,
                                               max_idle_time
                                           ).await;

                                           for peer_id in &disconnected {
                                               info!("🔌 Disconnecting idle peer: {}", peer_id);
                                               let _ = swarm.disconnect_peer_id(peer_id.as_libp2p());
                                           }

                                           let _ = responder.send(disconnected);
                                       }
                                       SwarmCommand::Shutdown => {
                                           info!("🛑 Swarm shutting down...");
                                           break;
                                       }
                                       SwarmCommand::SendRequest { target, request, responder } => {
                                           let msg_len = serde_json::to_vec(&request)
                                               .map(|b| b.len() as u64)
                                               .unwrap_or(0);

                                            let request_id = swarm.behaviour_mut().req_resp.send_request(&target.as_libp2p(), request);
                                           // Note: In a real implementation we would map request_id to the responder to return the response later.
                                           // For now, blocking wait / complex mapping is elided for simplicity in this step.
                                           info!("Sent request {:?} to {}", request_id, target);
                                           let _ = responder.send(Ok(()));

                                           // Update peer metrics
                                           {
                                               let mut registry = peer_registry_clone.lock().await;
                                                // Target is already crate::peer::PeerId
                                                metrics_simple::update_peer_metrics(&mut registry, &target, |info| {
                                                   info.metrics.messages_sent += 1;
                                                   info.metrics.requests_sent += 1;
                                                   info.metrics.bytes_sent += msg_len;
                                               });
                                           }
                                       }
                                       SwarmCommand::BlockPeer { peer_id } => {
                                           info!("🚫 Blocking peer: {}", peer_id);
                                           let _ = swarm.disconnect_peer_id(peer_id.as_libp2p());
                                           swarm.behaviour_mut().kad.remove_peer(&peer_id.as_libp2p());
                                       }
                                       SwarmCommand::DisconnectPeer { peer_id } => {
                                           info!("🔌 Disconnecting peer: {}", peer_id);
                                           let _ = swarm.disconnect_peer_id(peer_id.as_libp2p());
                                       }
                                       SwarmCommand::SendEncryptedRequest { target, request, responder } => {
                                           let peer_id = target.as_libp2p();
                                           match encrypted_handler.encrypt_request(&peer_id, &request).await {
                                               Ok(encrypted) => {
                                                   let req = crate::protocol::WolfRequest::Encrypted(encrypted.clone());
                                                    let request_id = swarm.behaviour_mut().req_resp.send_request(&peer_id, req);
                                                   info!("Sent encrypted request {:?} to {}", request_id, target);
                                                   let _ = responder.send(Ok(()));

                                                   // Update registry message count
                                                   let mut registry = peer_registry_clone.lock().await;
                                                    // Target is already crate::peer::PeerId
                                                    metrics_simple::update_peer_metrics(&mut registry, &target, |info| {
                                                       info.metrics.messages_sent += 1;
                                                       info.metrics.requests_sent += 1;
                                                       // Best effort size estimation
                                                       info.metrics.bytes_sent += 100; // Estimated
                                                   });
                                               }
                                               Err(e) => {
                                                   error!("Failed to encrypt request for {}: {}", target, e);
                                                   let _ = responder.send(Err(e));
                                               }
                                           }
                                       }
                                       SwarmCommand::ListPeers { responder } => {
                                           let registry = peer_registry_clone.lock().await;
                                           let peers = registry.values().cloned().collect();
                                           let _ = responder.send(peers);
                                       }
                                       SwarmCommand::GetPeerInfo { peer_id, responder } => {
                                            let registry = peer_registry_clone.lock().await;
                                            let info = registry.get(&peer_id).cloned(); // peer_id is already crate::peer::PeerId
                                            let _ = responder.send(info);
                                       }
                                       SwarmCommand::GetWolfState { responder } => {
                                           let _ = responder.send(wolf_state.clone());
                                       }
                                       SwarmCommand::OmegaForceRank { target, role } => {
                                           info!("👑 Omega Command: Forcing Rank of {} to {:?}", target, role);
                                           // If target is us, update local state
                                           if target == local_peer_id_clone {
                                               if let Err(e) = hunt_sender.send(crate::wolf_pack::coordinator::CoordinatorMsg::ForceRank { target: target.clone(), new_role: role }).await {
                                                   error!("Failed to send ForceRank to coordinator: {}", e);
                                               }
                                           } else {
                                               // For remote peers, we update our local registry/pack view for now
                                               // In a full P2P system, we'd send a simulation message.
                                               // We'll update the trust score in discovery service to effectively promote/demote
                                               warn!("Remote rank forcing not fully reachable yet. Mocking update for dashboard.");
                                           }
                                       }
                                       SwarmCommand::OmegaForcePrestige { target, change } => {
                                           info!("💎 Omega Command: Forcing Prestige of {} by {}", target, change);
                                           if target == local_peer_id_clone {
                                                let mut w = wolf_state.write().await;
                                                if change > 0 {
                                                    w.add_prestige(change.unsigned_abs());
                                               } else {
                                                    w.slash_prestige(change.unsigned_abs());
                                                }
                                           }
                                       }
                                        SwarmCommand::AddAddress { peer_id, addr } => {
                                            swarm.behaviour_mut().kad.add_address(&peer_id.as_libp2p(), addr);
                                        }
                                       SwarmCommand::BlockIp { ip } => {
                                           if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
                                               let mut fw = firewall_clone.write().await;
                                               fw.add_rule(crate::firewall::FirewallRule::new(
                                                   format!("Strike-{ip}"),
                                                   crate::firewall::RuleTarget::Ip(ip_addr),
                                                   crate::firewall::Protocol::Any,
                                                   crate::firewall::Action::Deny,
                                                   crate::firewall::TrafficDirection::Both,
                                               ));
                                               info!("🔥 Firewall updated: Deny IP {}", ip);
                                           } else {
                                               error!("Invalid IP address for block: {}", ip);
                                           }
                                       }
                                   }
                               }
                               _ = &mut shutdown_receiver => {
                                   info!("Received shutdown signal, stopping swarm...");
                                   break;
                               }
                           }
            }

            info!("Swarm event loop stopped");
        });

        let reputation_reporter = config.reputation_reporter.clone();
        Ok(Self {
            local_peer_id,
            config,
            running: false,
            command_sender,
            active_connections,
            metrics,
            peer_registry,
            shutdown_sender: Some(shutdown_sender),
            swarm_handle: Some(swarm_handle),
            encrypted_handler,
            firewall,
            consensus: consensus_manager,
            hunt_coordinator_sender: hunt_sender,
            wolf_state,
            reputation_reporter,
        })
    }

    /// Starts the `SwarmManager`.
    ///
    /// # Returns
    /// `Ok(())` if started successfully, or an error if already running or startup fails.
    ///
    /// # Errors
    /// Returns an error if the swarm is already running.
    pub fn start(&mut self) -> anyhow::Result<()> {
        if self.running {
            return Err(anyhow::anyhow!("SwarmManager is already running"));
        }

        info!("🚀 Starting SwarmManager...");
        self.running = true;

        // Start connection health monitoring
        self.start_health_monitor();

        info!("✅ SwarmManager started successfully");
        Ok(())
    }

    /// Stops the `SwarmManager`.
    ///
    /// # Returns
    /// `Ok(())` if stopped successfully, or an error if already stopped or shutdown fails.
    ///
    /// # Errors
    /// Returns an error if the swarm is not running.
    #[allow(clippy::cognitive_complexity)]
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if !self.running {
            return Err(anyhow::anyhow!("SwarmManager is not running"));
        }

        info!("🛑 Stopping SwarmManager...");
        self.running = false;

        // Trigger graceful shutdown
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }

        // Wait for the swarm to stop
        if let Some(handle) = self.swarm_handle.take() {
            if let Err(e) = handle.await {
                error!("Error while stopping swarm: {}", e);
            }
        }

        info!("✅ SwarmManager stopped successfully");
        Ok(())
    }

    /// Starts the connection health monitoring task.
    fn start_health_monitor(&self) {
        let command_sender = self.command_sender.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(30)); // Check every 30 seconds

        tokio::spawn(async move {
            loop {
                interval.tick().await;

                // Check for idle connections
                let (tx, rx) = oneshot::channel();
                if let Err(e) = command_sender
                    .send(SwarmCommand::CheckConnections {
                        max_idle_time: Duration::from_secs(300), // 5 minutes
                        responder: tx,
                    })
                    .await
                {
                    error!("Failed to check connections: {}", e);
                    break;
                }

                // Wait for the check to complete
                if rx.await.is_err() {
                    break;
                }
            }
        });
    }

    /// Checks for and handles stale connections.
    ///
    /// # Arguments
    /// * `max_idle_time` - Maximum allowed idle time before disconnecting
    ///
    /// # Returns
    /// Vector of disconnected peer IDs
    pub async fn check_connection_health(&mut self, max_idle_time: Duration) -> Vec<PeerId> {
        let now = Instant::now();
        let mut disconnected = Vec::new();
        let mut connections = self.active_connections.lock().await;

        // Check each connection
        connections.retain(|peer_id, conn| {
            let idle_time = now.duration_since(conn.last_seen);
            if idle_time > max_idle_time {
                info!(
                    "Disconnecting idle peer: {} (idle for {:?})",
                    peer_id, idle_time
                );
                disconnected.push(PeerId::from_libp2p(*peer_id));
                false
            } else {
                true
            }
        });

        // Update metrics
        self.metrics.lock().await.active_connections = connections.len();

        disconnected
    }

    /// Helper method to check connections (used internally)
    async fn check_connections(
        active_connections: &Arc<Mutex<HashMap<Libp2pPeerId, PeerConnection>>>,
        max_idle_time: Duration,
    ) -> Vec<PeerId> {
        let now = Instant::now();
        let mut disconnected = Vec::new();
        let mut connections = active_connections.lock().await;

        connections.retain(|peer_id, conn| {
            if now.duration_since(conn.last_seen) > max_idle_time {
                info!(
                    "Disconnecting idle peer: {} (idle for {:?})",
                    peer_id,
                    now.duration_since(conn.last_seen)
                );
                disconnected.push(conn.peer_id.clone());
                false
            } else {
                true
            }
        });

        disconnected
    }

    /// Gets current network metrics.
    ///
    /// # Returns
    /// A snapshot of current network metrics
    pub async fn get_metrics(&self) -> NetworkMetrics {
        self.metrics.lock().await.clone()
    }

    /// Dials a peer at the specified address.
    ///
    /// # Errors
    /// Returns an error if the dial command cannot be sent.
    pub async fn dial(&self, peer_id: PeerId, addr: libp2p::Multiaddr) -> anyhow::Result<()> {
        self.command_sender
            .send(SwarmCommand::Dial { peer_id, addr })
            .await?;
        Ok(())
    }

    /// Dials a peer at the specified address without knowing `PeerId`.
    ///
    /// # Errors
    /// Returns an error if the dial command cannot be sent.
    pub async fn dial_addr(&self, addr: libp2p::Multiaddr) -> anyhow::Result<()> {
        self.command_sender
            .send(SwarmCommand::DialAddr { addr })
            .await?;
        Ok(())
    }

    /// Adds a peer address to the swarm without dialing.
    ///
    /// # Errors
    /// Returns an error if the add address command cannot be sent.
    pub async fn add_address(&self, peer_id: PeerId, addr: Multiaddr) -> anyhow::Result<()> {
        self.command_sender
            .send(SwarmCommand::AddAddress { peer_id, addr })
            .await?;
        Ok(())
    }

    /// Gets the current listen addresses of the swarm.
    ///
    /// # Errors
    /// Returns an error if the listeners cannot be retrieved.
    pub async fn get_listeners(&self) -> anyhow::Result<Vec<libp2p::Multiaddr>> {
        let (tx, rx) = oneshot::channel();
        self.command_sender
            .send(SwarmCommand::GetListeners { responder: tx })
            .await?;
        rx.await
            .map_err(|e| anyhow::anyhow!("Failed to get listeners: {e}"))
    }

    /// Updates a peer's connection information.
    ///
    /// # Arguments
    /// * `peer_id` - The peer to update
    /// * `protocol_version` - Optional protocol version
    /// * `agent_version` - Optional agent version
    pub async fn update_peer_connection(
        &self,
        peer_id: PeerId,
        protocol_version: Option<String>,
        agent_version: Option<String>,
    ) {
        let mut connections = self.active_connections.lock().await;
        if let Some(conn) = connections.get_mut(&peer_id.as_libp2p()) {
            let now = Instant::now();
            conn.last_seen = now;

            if let Some(ver) = protocol_version {
                conn.protocol_version = Some(ver);
            }

            if let Some(agent) = agent_version {
                conn.agent_version = Some(agent);
            }

            // Update last activity in metrics
            self.metrics.lock().await.last_activity = Some(now);
        }
    }

    /// List all known peers and their information.
    ///
    /// # Errors
    /// Returns an error if the peer list cannot be retrieved.
    pub async fn list_peers(&self) -> anyhow::Result<Vec<crate::peer::EntityInfo>> {
        let (tx, rx) = oneshot::channel();
        self.command_sender
            .send(SwarmCommand::ListPeers { responder: tx })
            .await?;
        rx.await
            .map_err(|e| anyhow::anyhow!("Failed to list peers: {e}"))
    }

    /// Get information about a specific peer.
    ///
    /// # Errors
    /// Returns an error if the peer info cannot be retrieved.
    pub async fn get_peer_info(
        &self,
        peer_id: PeerId,
    ) -> anyhow::Result<Option<crate::peer::EntityInfo>> {
        let (tx, rx) = oneshot::channel();
        self.command_sender
            .send(SwarmCommand::GetPeerInfo {
                peer_id,
                responder: tx,
            })
            .await?;
        rx.await
            .map_err(|e| anyhow::anyhow!("Failed to get peer info: {e}"))
    }

    /// Gets overall swarm statistics.
    ///
    /// # Errors
    /// Returns an error if stats cannot be retrieved.
    pub async fn get_stats(&self) -> anyhow::Result<SwarmStats> {
        let (tx, rx) = oneshot::channel();
        self.command_sender
            .send(SwarmCommand::GetStats { responder: tx })
            .await?;
        rx.await
            .map_err(|e| anyhow::anyhow!("Failed to get stats: {e}"))
    }

    /// Initiates a hunt for a suspicious target.
    ///
    /// # Arguments
    /// * `target_ip` - The IP address of the suspicious target
    /// * `evidence` - Evidence string describing the threat
    ///
    /// # Returns
    /// The hunt ID if successful
    ///
    /// # Errors
    /// Returns an error if the hunt initiation fails (e.g. invalid target).
    pub async fn initiate_hunt(
        &self,
        target_ip: String,
        evidence: String,
    ) -> anyhow::Result<String> {
        let hunt_id = format!("hunt-{target_ip}-{}", uuid::Uuid::new_v4());

        self.hunt_coordinator_sender
            .send(crate::wolf_pack::coordinator::CoordinatorMsg::WarningHowl {
                source: self.local_peer_id.clone(),
                target_ip,
                evidence,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send hunt initiation: {e}"))?;

        info!("🎯 Hunt initiated: {hunt_id}");
        Ok(hunt_id)
    }

    /// Reports the result of a hunt verification.
    ///
    /// # Arguments
    /// * `hunt_id` - The ID of the hunt
    /// * `confirmed` - Whether the threat was confirmed
    ///
    /// # Errors
    /// Returns an error if the report cannot be sent.
    pub async fn report_hunt(&self, hunt_id: String, confirmed: bool) -> anyhow::Result<()> {
        self.hunt_coordinator_sender
            .send(crate::wolf_pack::coordinator::CoordinatorMsg::HuntReport {
                hunt_id,
                hunter: self.local_peer_id.clone(),
                confirmed,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send hunt report: {e}"))?;

        Ok(())
    }

    /// Gets all active hunts.
    ///
    /// # Returns
    /// A vector of active hunts
    ///
    /// # Errors
    /// Returns an error if the lock cannot be acquired or state is invalid.
    pub async fn get_active_hunts(
        &self,
    ) -> anyhow::Result<Vec<crate::wolf_pack::state::ActiveHunt>> {
        let state = self.wolf_state.read().await;
        Ok(state.active_hunts.clone())
    }

    /// Gets current Wolf Pack state.
    ///
    /// # Errors
    /// Returns an error if the command cannot be sent to the swarm actor.
    pub async fn get_wolf_state(
        &self,
    ) -> anyhow::Result<Arc<tokio::sync::RwLock<crate::wolf_pack::state::WolfState>>> {
        let (tx, rx) = oneshot::channel();
        self.command_sender
            .send(SwarmCommand::GetWolfState { responder: tx })
            .await?;
        rx.await
            .map_err(|e| anyhow::anyhow!("Failed to get wolf state: {e}"))
    }

    /// Extract target IP from security event
    fn extract_target_ip(event: &crate::event::SecurityEvent) -> String {
        use lazy_static::lazy_static;
        lazy_static! {
            static ref IP_REGEX: regex::Regex =
                regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("Valid regex");
        }

        // Try to extract from peer_id if it looks like an IP
        if let Some(peer_id) = &event.peer_id {
            if let Some(mat) = IP_REGEX.find(peer_id) {
                return mat.as_str().to_string();
            }
        }

        // Try to extract from description
        if let Some(mat) = IP_REGEX.find(&event.description) {
            return mat.as_str().to_string();
        }

        // Fallback: use peer_id or "unknown"
        event
            .peer_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Process security event and potentially trigger hunt
    ///
    /// # Errors
    /// Returns an error if `WarningHowl` cannot be sent.
    pub async fn process_security_event(
        &self,
        event: crate::event::SecurityEvent,
    ) -> anyhow::Result<()> {
        // Check severity threshold (only High and Critical trigger hunts)
        if !matches!(
            event.severity,
            crate::event::SecuritySeverity::High | crate::event::SecuritySeverity::Critical
        ) {
            return Ok(());
        }

        // Check local role and prestige
        let state = self.wolf_state.read().await;

        // Robust check: Strays can't initiate, Scouts need 50 prestige,
        // but Hunters and above can always initiate for high-severity events.
        let can_initiate = match state.role {
            crate::wolf_pack::state::WolfRole::Stray => false,
            crate::wolf_pack::state::WolfRole::Scout => state.prestige >= 50,
            _ => true,
        };

        if !can_initiate {
            debug!(
                "Node lacks authority to initiate hunt (role: {:?}, prestige: {})",
                state.role, state.prestige
            );
            return Ok(());
        }
        drop(state);

        // Extract target IP from event
        let target_ip = Self::extract_target_ip(&event);

        // Emit WarningHowl to initiate hunt
        self.hunt_coordinator_sender
            .send(crate::wolf_pack::coordinator::CoordinatorMsg::WarningHowl {
                source: self.local_peer_id.clone(),
                target_ip: target_ip.clone(),
                evidence: event.description.clone(),
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send WarningHowl: {e}"))?;

        info!(
            "🐺 Scout node initiated hunt for {} (severity: {:?})",
            target_ip, event.severity
        );
        Ok(())
    }
}

/// Statistics about the swarm.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SwarmStats {
    /// Number of connected peers
    pub connected_peers: usize,
    /// List of connected peer IDs
    pub connected_peers_list: Vec<PeerId>,
    /// Network metrics
    pub metrics: NetworkMetrics,
}

// Implement Drop for cleanup
impl Drop for SwarmManager {
    fn drop(&mut self) {
        // Trigger graceful shutdown if we still have the sender
        if let Some(sender) = self.shutdown_sender.take() {
            let _ = sender.send(());
        }
        // distinct from stop(): we cannot await the swarm_handle in Drop
        // because we might be in a pervasive async context (like a test)
        // where blocking the thread would deadlock the runtime.
    }
}
