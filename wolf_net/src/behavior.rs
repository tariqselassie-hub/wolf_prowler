use crate::protocol::WolfCodec;
use libp2p::{
    gossipsub,
    identify,
    kad,
    ping,
    request_response,
    swarm::NetworkBehaviour,
    // swarm::{NetworkBehaviour, SwarmEvent},
    // Swarm,
};

/// Custom network behavior for Wolf Net
#[derive(NetworkBehaviour)]
pub struct WolfBehavior {
    pub ping: ping::Behaviour,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub req_resp: request_response::Behaviour<WolfCodec>,
    pub identify: identify::Behaviour,
}

impl WolfBehavior {
    pub fn new(
        local_key: &libp2p::identity::Keypair,
        _config: &crate::swarm::SwarmConfig,
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
            .max_transmit_size(262144)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build gossipsub config: {}", e))?;

        let message_authenticity =
            libp2p::gossipsub::MessageAuthenticity::Signed(local_key.clone());
        let gossipsub =
            libp2p::gossipsub::Behaviour::new(message_authenticity, gossipsub_config)
                .map_err(|e| anyhow::anyhow!("Failed to create gossipsub behaviour: {}", e))?;

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

        Ok(Self {
            ping,
            kad,
            gossipsub,
            req_resp,
            identify,
        })
    }
}
