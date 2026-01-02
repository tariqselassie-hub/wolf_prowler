use crate::logic::WolfLogicEngine;
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
    #[behaviour(ignore)]
    pub logic: WolfLogicEngine,
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
            logic: WolfLogicEngine::new(),
        })
    }

    // ... existing methods ...
    pub async fn handle_pack_coordination(
        &mut self,
        peer_id: libp2p::PeerId,
        pack_id: &str,
        action: &crate::wolf_pack::messaging::PackAction,
    ) -> anyhow::Result<crate::wolf_pack::messaging::WolfResponse> {
        self.logic
            .handle_pack_coordination(peer_id, pack_id, action)
            .await
    }

    pub async fn handle_howl(
        &mut self,
        peer_id: libp2p::PeerId,
        frequency: f32,
        pattern: &crate::wolf_pack::messaging::HowlPattern,
        message: Option<Vec<u8>>,
        territory: Option<String>,
    ) -> anyhow::Result<crate::wolf_pack::messaging::WolfResponse> {
        self.logic
            .handle_howl(peer_id, frequency, pattern, message, territory)
            .await
    }

    pub async fn handle_heartbeat(
        &mut self,
        peer_id: libp2p::PeerId,
        heartbeat_peer: &str,
        status: &crate::wolf_pack::messaging::PeerStatus,
        metrics: &crate::wolf_pack::messaging::PeerMetrics,
    ) -> anyhow::Result<crate::wolf_pack::messaging::WolfResponse> {
        self.logic
            .handle_heartbeat(peer_id, heartbeat_peer, status, metrics)
            .await
    }

    pub async fn perform_patrol(
        &mut self,
    ) -> anyhow::Result<Vec<crate::wolf_pack::messaging::WolfMessage>> {
        self.logic.perform_patrol().await
    }

    pub fn set_hunt_sender(
        &mut self,
        sender: tokio::sync::mpsc::Sender<crate::wolf_pack::coordinator::CoordinatorMsg>,
    ) {
        self.logic.set_coordinator_sender(sender);
        // Logic engine updated to support this wiring.
    }
}
