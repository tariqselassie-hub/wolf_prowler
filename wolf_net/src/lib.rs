//! 🐺 Wolf Net - Advanced P2P Networking & Coordination
//!
//! A modular networking library built on libp2p, featuring the "Wolf Pack"
//! coordination protocol for distributed threat detection and response.
//!
//! ### Core Components:
//! - **WolfNode**: The primary system facade for initialization and orchestration.
//! - **SwarmManager**: Low-level P2P swarm management, discovery, and routing.
//! - **HuntCoordinator**: An actor-based engine managing the "Wolf Pack" lifecycle (Scent -> Stalk -> Strike).
//! - **Internal Firewall**: Dynamic rule-based traffic control integrated with hunt outcomes.

pub mod api;
pub mod behavior;
pub mod config;
pub mod consensus;
pub mod discovery;
pub mod encrypted_handler;
pub mod encryption;
pub mod event;
pub mod firewall;
pub mod geo;
pub mod handshake;
pub mod hub_orchestration;
pub mod message;
pub mod metrics_simple;
pub mod p2p;
pub mod peer;
pub mod protocol;
pub mod reporting_service;
pub mod scanner;
pub mod security;
pub mod swarm;
pub mod utils;
pub mod wolf_node;
pub mod wolf_pack;

// Re-export main components for easy access
pub use behavior::{WolfBehavior, WolfBehaviorEvent};
pub use config::WolfConfig;
pub use discovery::{
    DhtDiscovery, DiscoveryConfig, DiscoveryMethod, DiscoveryService, MdnsDiscovery,
};
pub use encrypted_handler::EncryptedMessageHandler;
pub use encryption::{EncryptedMessage, MessageEncryption};
pub use event::EventHandler;
pub use handshake::HandshakeManager;
pub use libp2p;
pub use message::{Message, MessageHandler, MessageType};
pub use peer::{
    DeviceId, EntityId, EntityInfo, EntityStatus, PeerId, PeerInfo, ServiceId, ServiceType,
    SystemId, SystemType,
};
pub use security::{NetworkSecurity, SignedEnvelope};
pub use swarm::{SwarmCommand, SwarmConfig, SwarmManager, SwarmStats};
pub use wolf_den;
pub use wolf_pack::coordinator::{CoordinatorMsg, HuntCoordinator}; // Export crypto library used by this network library

/// Library version and metadata
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = "Wolf Net";

/// Initialize Wolf Net ID system
pub fn init() -> anyhow::Result<()> {
    // Initialize logging
    let _ = utils::setup_logging(tracing::Level::INFO);

    tracing::info!("🐺 {} v{} ID system initialized", NAME, VERSION);
    Ok(())
}

/// Create a new entity with specified types
pub fn create_entity(
    service_type: ServiceType,
    system_type: SystemType,
    version: &str,
) -> EntityId {
    EntityId::create(service_type, system_type, version)
}

/// Create entity info for network tracking
pub fn create_entity_info(
    service_type: ServiceType,
    system_type: SystemType,
    version: &str,
) -> crate::peer::EntityInfo {
    let entity_id = EntityId::create(service_type, system_type, version);
    crate::peer::EntityInfo::new(entity_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_init() {
        let result = init();
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_entity() {
        let entity = create_entity(ServiceType::Server, SystemType::Production, "1.0.0");

        assert!(entity.is_service_type(ServiceType::Server));
        assert!(entity.is_system_type(SystemType::Production));
    }

    #[test]
    fn test_create_entity_info() {
        let info = create_entity_info(ServiceType::Database, SystemType::Cloud, "2.0.0");

        assert!(info.entity_id.is_service_type(ServiceType::Database));
        assert!(info.entity_id.is_system_type(SystemType::Cloud));
    }
}
