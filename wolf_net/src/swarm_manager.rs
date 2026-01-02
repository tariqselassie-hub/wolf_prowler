use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub, identity, kad, noise, request_response, swarm::SwarmEvent, tcp, yamux, Multiaddr,
    PeerId, Swarm, Transport,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::behavior::{WolfBehavior, WolfEvent};
use crate::protocol::{WolfRequest, WolfResponse};
use crate::NetworkConfig;

/// Main struct for managing the P2P swarm
pub struct SwarmManager {
    swarm: Swarm<WolfBehavior>,
}

impl SwarmManager {
    /// Creates a new SwarmManager with the given configuration
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        // 1. Generate Identity
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(id_keys.public());
        tracing::info!("Local Peer ID: {}", peer_id);

        // 2. Create Transport (TCP + Noise + Yamux)
        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));

        let transport = tcp_transport
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&id_keys)?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Initialize Kademlia DHT
        let store = kad::store::MemoryStore::new(peer_id);
        let kad_behaviour = kad::Behaviour::new(peer_id, store);

        // Initialize Gossipsub
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = std::collections::hash_map::DefaultHasher::new();
            use std::hash::{Hash, Hasher};
            message.data.hash(&mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .map_err(|msg| anyhow::anyhow!("Validation Error: {}", msg))?;

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(id_keys.clone()),
            gossipsub_config,
        )
        .map_err(|msg| anyhow::anyhow!("Gossipsub Error: {}", msg))?;

        // Subscribe to default topic
        let topic = gossipsub::IdentTopic::new("wolf-pack-global");
        gossipsub.subscribe(&topic)?;

        // Initialize RequestResponse
        let req_resp = request_response::cbor::Behaviour::new(
            [(
                libp2p::StreamProtocol::new("/wolf-prowler/1.0.0"),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );

        // 3. Define Behaviour
        let behaviour = WolfBehavior {
            ping: libp2p::ping::Behaviour::new(
                libp2p::ping::Config::new().with_interval(Duration::from_secs(30)),
            ),
            kad: kad_behaviour,
            gossipsub,
            req_resp,
            logic: crate::logic::WolfLogicEngine::new(),
        };

        // 4. Build Swarm
        let swarm =
            libp2p::SwarmBuilder::with_tokio_executor(transport, behaviour, peer_id).build();

        let mut manager = Self { swarm };

        // Bootstrap DHT if peers are configured
        if !config.bootstrap_peers.is_empty() {
            manager.bootstrap(&config.bootstrap_peers)?;
        }

        Ok(manager)
    }

    /// Returns the local peer ID of the swarm.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Bootstraps the Kademlia DHT using a list of bootnodes
    pub fn bootstrap(&mut self, bootnodes: &[(PeerId, Multiaddr)]) -> Result<()> {
        for (peer_id, addr) in bootnodes {
            self.swarm
                .behaviour_mut()
                .kad
                .add_address(peer_id, addr.clone());
        }

        if !bootnodes.is_empty() {
            self.swarm.behaviour_mut().kad.bootstrap()?;
        }
        Ok(())
    }

    /// Adds a peer address to the Kademlia DHT
    pub fn add_address_to_dht(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kad.add_address(peer_id, addr);
    }

    /// Dials a peer at the given address
    pub fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }

    /// Disconnects from a peer
    pub fn disconnect(&mut self, peer_id: PeerId) -> Result<()> {
        let _ = self.swarm.disconnect_peer_id(peer_id);
        Ok(())
    }

    /// Broadcasts a message to the global topic
    pub fn broadcast(&mut self, message: Vec<u8>) -> Result<()> {
        let topic = gossipsub::IdentTopic::new("wolf-pack-global");
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, message)?;
        Ok(())
    }

    /// Sends a direct request to a specific peer
    pub fn send_direct_request(
        &mut self,
        peer_id: PeerId,
        request: Vec<u8>,
    ) -> request_response::RequestId {
        self.swarm
            .behaviour_mut()
            .req_resp
            .send_request(&peer_id, WolfRequest(request))
    }

    /// Handles incoming request/response events
    pub fn handle_req_resp_event(
        &mut self,
        event: request_response::Event<WolfRequest, WolfResponse>,
    ) {
        // Log all events for debugging
        tracing::debug!("RequestResponse event: {:?}", event);

        match event {
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        channel, request, ..
                    },
                ..
            } => {
                tracing::info!("Received request: {:?}", request);

                // Determine response based on request content
                let response_data = if request.0 == b"Ping" {
                    b"Pong".to_vec()
                } else {
                    // Echo back the request data for now
                    request.0
                };

                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .req_resp
                    .send_response(channel, WolfResponse(response_data))
                {
                    tracing::error!("Failed to send response: {:?}", e);
                }
            }
            _ => {}
        }
    }

    /// Starts listening on the default interface
    pub fn listen_on_default(&mut self) -> Result<()> {
        // Listen on all interfaces
        // TODO: Use config.listen_addresses
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        Ok(())
    }

    /// Drives the swarm forward, processing one event
    pub async fn next_event(&mut self) -> WolfEvent {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(event) => return event,
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!("Listening on {:?}", address);
                }
                _ => {}
            }
        }
    }

    /// Starts the Swarm event loop
    pub async fn start(&mut self) -> Result<()> {
        self.listen_on_default()?;
        loop {
            let event = self.next_event().await;
            // Handle internal logic for events that require it
            if let WolfEvent::ReqResp(e) = event {
                self.handle_req_resp_event(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkConfig;
    use libp2p::{identity, request_response, Multiaddr, PeerId};

    #[tokio::test]
    async fn test_bootstrap_adds_peers() {
        let config = NetworkConfig::default();
        let mut manager = SwarmManager::new(config)
            .await
            .expect("Failed to create SwarmManager");

        let key = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(key.public());
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8080".parse().unwrap();

        manager
            .bootstrap(&[(peer_id, addr.clone())])
            .expect("Bootstrap failed");

        let addresses = manager
            .swarm
            .behaviour_mut()
            .kad
            .addresses_of_peer(&peer_id);
        assert!(
            addresses.contains(&addr),
            "Bootnode address should be added to Kademlia"
        );
    }

    #[tokio::test]
    async fn test_broadcast_gossipsub() {
        let config = NetworkConfig::default();
        let mut peer1 = SwarmManager::new(config.clone())
            .await
            .expect("Failed to create Peer 1");
        let mut peer2 = SwarmManager::new(config)
            .await
            .expect("Failed to create Peer 2");

        // Peer 2 listens
        peer2
            .swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();

        // Get Peer 2 address
        let addr2 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = peer2.swarm.select_next_some().await
            {
                break address;
            }
        };

        // Peer 1 dials Peer 2
        peer1.swarm.dial(addr2).unwrap();

        // Wait for connection
        let wait_connect = async {
            let mut p1_done = false;
            let mut p2_done = false;
            loop {
                tokio::select! {
                    event = peer1.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { .. } = event { p1_done = true; }
                    }
                    event = peer2.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { .. } = event { p2_done = true; }
                    }
                }
                if p1_done && p2_done {
                    break;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait_connect)
            .await
            .expect("Connection timed out");

        // Wait for Gossipsub heartbeat (mesh formation)
        let wait_mesh = async {
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(2) {
                tokio::select! {
                    _ = peer1.swarm.select_next_some() => {}
                    _ = peer2.swarm.select_next_some() => {}
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
        };
        wait_mesh.await;

        // Broadcast
        let msg = b"Hello Wolf Pack".to_vec();
        peer1.broadcast(msg.clone()).expect("Broadcast failed");

        // Verify receipt
        let wait_msg = async {
            loop {
                tokio::select! {
                    _ = peer1.swarm.select_next_some() => {}
                    event = peer2.swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(WolfEvent::Gossipsub(libp2p::gossipsub::Event::Message { message, .. })) = event {
                            if message.data == msg { return; }
                        }
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait_msg)
            .await
            .expect("Message receipt timed out");
    }

    #[tokio::test]
    async fn test_direct_request_response() {
        let config = NetworkConfig::default();
        let mut peer1 = SwarmManager::new(config.clone())
            .await
            .expect("Failed to create Peer 1");
        let mut peer2 = SwarmManager::new(config)
            .await
            .expect("Failed to create Peer 2");

        // Peer 2 listens
        peer2
            .swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let addr2 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = peer2.swarm.select_next_some().await
            {
                break address;
            }
        };

        // Peer 1 dials Peer 2
        peer1.swarm.dial(addr2).unwrap();

        // Wait for connection
        let wait_connect = async {
            let mut p1_done = false;
            let mut p2_done = false;
            loop {
                tokio::select! {
                    event = peer1.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { .. } = event { p1_done = true; }
                    }
                    event = peer2.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { .. } = event { p2_done = true; }
                    }
                }
                if p1_done && p2_done {
                    break;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait_connect)
            .await
            .expect("Connection timed out");

        // Send Request
        let req_data = b"Ping".to_vec();
        peer1.send_direct_request(*peer2.swarm.local_peer_id(), req_data.clone());

        // Handle Request on Peer 2 and Send Response
        let handle_request = async {
            loop {
                let event = peer2.swarm.select_next_some().await;
                if let SwarmEvent::Behaviour(WolfEvent::ReqResp(
                    request_response::Event::Message {
                        message:
                            request_response::Message::Request {
                                channel, request, ..
                            },
                        ..
                    },
                )) = event
                {
                    assert_eq!(request.0, req_data);
                    peer2
                        .swarm
                        .behaviour_mut()
                        .req_resp
                        .send_response(channel, WolfResponse(b"Pong".to_vec()))
                        .unwrap();
                    break;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), handle_request)
            .await
            .expect("Request receive timed out");

        // Handle Response on Peer 1
        let handle_response = async {
            loop {
                let event = peer1.swarm.select_next_some().await;
                if let SwarmEvent::Behaviour(WolfEvent::ReqResp(
                    request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    },
                )) = event
                {
                    assert_eq!(response.0, b"Pong".to_vec());
                    break;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), handle_response)
            .await
            .expect("Response receive timed out");
    }
}
