//! P2P networking engine for Wolf Prowler

use anyhow::Result;
use libp2p::autonat::Autonat;
use libp2p::gossipsub::{Gossipsub, GossipsubMessage, MessageAuthenticity, ValidationMode};
use libp2p::identify::{Identify, IdentifyConfig};
use libp2p::kad::{store::MemoryStore, Kademlia};
use libp2p::mdns;
use libp2p::ping::{Ping, PingConfig};
use libp2p::relay::client::Behaviour as RelayClient;
use libp2p::request_response::{RequestResponse, RequestResponseConfig};
use libp2p::{identity::Keypair, Swarm, SwarmBuilder};
use libp2p::{noise, tcp, yamux, Transport};
use std::time::Duration;

/// Custom behavior combining multiple libp2p protocols
#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(out_event = "WolfProwlerEvent")]
pub struct WolfProwlerBehaviour {
    mdns: mdns::tokio::Behaviour,
    gossipsub: Gossipsub,
    kademlia: Kademlia<MemoryStore>,
    identify: Identify,
    ping: Ping,
    autonat: Autonat,
    request_response: RequestResponse<crate::network::messaging::WolfCodec>,
    relay: RelayClient,
}

/// Events from the P2P network
#[derive(Debug)]
pub enum WolfProwlerEvent {
    Mdns(mdns::Event),
    Gossipsub(GossipsubMessage),
    Kademlia(libp2p::kad::Event),
    Identify(libp2p::identify::Event),
    Ping(libp2p::ping::Event),
    Autonat(libp2p::autonat::Event),
    RequestResponse(
        libp2p::request_response::Event<
            crate::network::messaging::WolfMessage,
            crate::network::messaging::WolfResponse,
        >,
    ),
    Relay(libp2p::relay::client::Event),
}

impl From<mdns::Event> for WolfProwlerEvent {
    fn from(event: mdns::Event) -> Self {
        WolfProwlerEvent::Mdns(event)
    }
}

impl From<GossipsubMessage> for WolfProwlerEvent {
    fn from(event: GossipsubMessage) -> Self {
        WolfProwlerEvent::Gossipsub(event)
    }
}

impl From<libp2p::kad::Event> for WolfProwlerEvent {
    fn from(event: libp2p::kad::Event) -> Self {
        WolfProwlerEvent::Kademlia(event)
    }
}

impl From<libp2p::identify::Event> for WolfProwlerEvent {
    fn from(event: libp2p::identify::Event) -> Self {
        WolfProwlerEvent::Identify(event)
    }
}

impl From<libp2p::ping::Event> for WolfProwlerEvent {
    fn from(event: libp2p::ping::Event) -> Self {
        WolfProwlerEvent::Ping(event)
    }
}

impl From<libp2p::autonat::Event> for WolfProwlerEvent {
    fn from(event: libp2p::autonat::Event) -> Self {
        WolfProwlerEvent::Autonat(event)
    }
}

impl
    From<
        libp2p::request_response::Event<
            crate::network::messaging::WolfMessage,
            crate::network::messaging::WolfResponse,
        >,
    > for WolfProwlerEvent
{
    fn from(
        event: libp2p::request_response::Event<
            crate::network::messaging::WolfMessage,
            crate::network::messaging::WolfResponse,
        >,
    ) -> Self {
        WolfProwlerEvent::RequestResponse(event)
    }
}

impl From<libp2p::relay::client::Event> for WolfProwlerEvent {
    fn from(event: libp2p::relay::client::Event) -> Self {
        WolfProwlerEvent::Relay(event)
    }
}

/// Main P2P network manager
pub struct P2PNetwork {
    swarm: Swarm<WolfProwlerBehaviour>,
    local_peer_id: libp2p::PeerId,
}

impl P2PNetwork {
    /// Create a new P2P network instance
    pub async fn new(config: &crate::core::settings::NetworkConfig) -> Result<Self> {
        let keypair = Keypair::generate_ed25519();
        let local_peer_id = libp2p::PeerId::from(keypair.public());

        // Build transport with noise protocol
        let transport = tcp::tokio::Transport::default()
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::xx(&keypair).expect("Noise authentication failed"))
            .multiplex(yamux::Config::default())
            .boxed();

        // Create gossipsub
        let gossipsub_config = libp2p::gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(config.network.heartbeat_interval_secs))
            .validation_mode(ValidationMode::Strict)
            .build()
            .expect("Valid config");

        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .expect("Correct configuration");

        // Create Kademlia
        let store = MemoryStore::new(local_peer_id);
        let kademlia = Kademlia::new(local_peer_id, store);

        // Create identify
        let identify_config = IdentifyConfig::new("wolf-prowler/1.0".to_string(), keypair.public());
        let identify = Identify::new(identify_config);

        // Create ping
        let ping = Ping::new(PingConfig::new().with_keep_alive(true));

        // Create autonat
        let autonat = Autonat::new(local_peer_id, Default::default());

        // Create request-response
        let request_response_config = RequestResponseConfig::default();
        let request_response = RequestResponse::new(
            crate::network::messaging::WolfCodec,
            request_response_config,
        );

        // Create relay client
        let relay = RelayClient::new(local_peer_id, Default::default());

        // Create behavior
        let behaviour = WolfProwlerBehaviour {
            mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                .expect("Valid config"),
            gossipsub,
            kademlia,
            identify,
            ping,
            autonat,
            request_response,
            relay,
        };

        // Create swarm
        let swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build();

        Ok(Self {
            swarm,
            local_peer_id,
        })
    }

    /// Start listening on the configured port
    pub fn start_listening(&mut self, port: u16) -> Result<()> {
        let addr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
        self.swarm.listen_on(addr)?;
        Ok(())
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> libp2p::PeerId {
        self.local_peer_id
    }

    /// Get swarm for advanced operations
    pub fn swarm(&mut self) -> &mut Swarm<WolfProwlerBehaviour> {
        &mut self.swarm
    }

    /// Handle network events
    pub async fn handle_event(&mut self) -> Option<WolfProwlerEvent> {
        use libp2p::swarm::SwarmEvent;

        match self.swarm.select_next_some().await {
            SwarmEvent::Behaviour(event) => Some(event),
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Listening on {}", address);
                None
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::info!("Connected to {}", peer_id);
                None
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                tracing::info!("Disconnected from {} due to {:?}", peer_id, cause);
                None
            }
            _ => None,
        }
    }
}
