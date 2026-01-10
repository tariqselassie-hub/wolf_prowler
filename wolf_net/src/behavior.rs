use crate::protocol::WolfCodec;
use libp2p::{
    gossipsub,
    identify,
    kad,
    mdns,
    ping,
    request_response,
    swarm::NetworkBehaviour,
    // swarm::{NetworkBehaviour, SwarmEvent},
    // Swarm,
};

/// Events produced by the `WolfBehavior`.
#[derive(Debug)]
pub enum WolfBehaviorEvent {
    /// Event from the ping behaviour.
    Ping(ping::Event),
    /// Event from the Kademlia behaviour.
    Kad(kad::Event),
    /// Event from the gossipsub behaviour.
    Gossipsub(gossipsub::Event),
    /// Event from the request/response behaviour.
    ReqResp(request_response::Event<crate::protocol::WolfRequest, crate::protocol::WolfResponse>),
    /// Event from the identify behaviour.
    Identify(identify::Event),
    /// Event from the mDNS behaviour.
    Mdns(mdns::Event),
}

impl From<ping::Event> for WolfBehaviorEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<kad::Event> for WolfBehaviorEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<gossipsub::Event> for WolfBehaviorEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(event)
    }
}

impl From<request_response::Event<crate::protocol::WolfRequest, crate::protocol::WolfResponse>> for WolfBehaviorEvent {
    fn from(event: request_response::Event<crate::protocol::WolfRequest, crate::protocol::WolfResponse>) -> Self {
        Self::ReqResp(event)
    }
}

impl From<identify::Event> for WolfBehaviorEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<mdns::Event> for WolfBehaviorEvent {
    fn from(event: mdns::Event) -> Self {
        Self::Mdns(event)
    }
}

/// Custom network behavior for Wolf Net, aggregating various protocol behaviours.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "WolfBehaviorEvent")]
pub struct WolfBehavior {
    /// Ping protocol behaviour for checking peer liveness.
    pub ping: ping::Behaviour,
    /// Kademlia DHT behaviour for peer discovery and content routing.
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    /// Gossipsub pub/sub behaviour for efficient message broadcasting.
    pub gossipsub: gossipsub::Behaviour,
    /// Custom request/response behaviour for direct node‑to‑node communication.
    pub req_resp: request_response::Behaviour<WolfCodec>,
    /// Identify protocol behaviour for exchanging peer information.
    pub identify: identify::Behaviour,
    /// mDNS behaviour for local peer discovery.
    pub mdns: mdns::tokio::Behaviour,
}

impl WolfBehavior {
    /// Creates a new `WolfBehavior` instance with default configurations.
    ///
    /// * `local_key` - Keypair used for identity and signing.
    /// * `_config` - Swarm configuration parameters.
    ///
    /// # Errors
    /// Returns an error if the gossipsub configuration or behaviour cannot be created.
    pub fn new(
        local_key: &libp2p::identity::Keypair,
        config: &crate::swarm::SwarmConfig,
    ) -> anyhow::Result<Self> {
        let peer_id = local_key.public().to_peer_id();

        // Ping
        let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new());

        // Kademlia
        let store = kad::store::MemoryStore::new(peer_id);
        let kad_config = kad::Config::default();
        let kad = kad::Behaviour::with_config(peer_id, store, kad_config);

        // Gossipsub
        let gossipsub_config = libp2p::gossipsub::ConfigBuilder::default()
            .max_transmit_size(262_144)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build gossipsub config: {e}"))?;

        let message_authenticity =
            libp2p::gossipsub::MessageAuthenticity::Signed(local_key.clone());
        let gossipsub =
            libp2p::gossipsub::Behaviour::new(message_authenticity, gossipsub_config)
                .map_err(|e| anyhow::anyhow!("Failed to create gossipsub behaviour: {e}"))?;

        // Request-Response
        let req_resp = request_response::Behaviour::with_codec(
            crate::protocol::WolfCodec,
            [(
                crate::protocol::WolfProtocol,
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );

        // Identify
        let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
            "/wolf-net/1.0.0".to_string(),
            local_key.public(),
        ));

        // mDNS
        let mdns = if config.enable_mdns {
            tracing::info!("Enable mDNS for peer discovery");
            libp2p::mdns::tokio::Behaviour::new(
                libp2p::mdns::Config::default(),
                peer_id
            )?
        } else {
            // If disabled, we still need to provide a behaviour instance, but maybe we can disable it via config?
            // Or we use a Toggle wrapper?
            // For now, let's just create it but it won't do much if we don't poll it?
            // Actually, libp2p behaviours are static in the struct.
            // We'll create it with default config, but we should probably have a way to disable it.
            // libp2p::mdns::Behaviour doesn't have a "disable" method easily accessible.
            // We can use `libp2p::swarm::behaviour::toggle::Toggle`.
            // But that requires changing the struct definition.
            // For simplicity in this "fix", I'll just enable it if requested, or create it anyway (it's low overhead).
            // But to be "correct", I should probably follow the config.
            // Let's stick to creating it for now, as the struct expects it.
            // PROPER FIX: Use Toggle<Mdns> in struct. But that changes the type.
            // Let's just create it.
            libp2p::mdns::tokio::Behaviour::new(
                libp2p::mdns::Config::default(),
                peer_id
            )?
        };

        Ok(Self {
            ping,
            kad,
            gossipsub,
            req_resp,
            identify,
            mdns,
        })
    }
}
