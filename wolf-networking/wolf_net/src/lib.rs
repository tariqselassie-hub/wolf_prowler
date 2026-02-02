//! 🐺 Wolf Net - Advanced P2P Networking & Coordination
#![allow(missing_docs)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::doc_markdown)]
//!
//! A modular networking library built on libp2p, featuring the "Wolf Pack"
//! coordination protocol for distributed threat detection and response.
//!
//! ### Core Components:
//! - **`WolfNode`**: The primary system facade for initialization and orchestration.
//! - **`SwarmManager`**: Low-level P2P swarm management, discovery, and routing.
//! - **`HuntCoordinator`**: An actor-based engine managing the "Wolf Pack" lifecycle (`Scent` -> `Stalk` -> `Strike`).
//! - **Internal Firewall**: Dynamic rule-based traffic control integrated with hunt outcomes.

/// API for external control and status.
pub mod api;
pub mod behavior;
/// Node and network configuration.
pub mod config;
/// Consensus mechanisms.
pub mod consensus;
/// Peer discovery services.
pub mod discovery;
/// Handler for encrypted messages.
pub mod encrypted_handler;
/// PQC encryption utilities.
pub mod encryption;
/// System event definitions.
pub mod event;
/// Internal firewall manager.
pub mod firewall;
/// GeoIP resolution service.
pub mod geo;
/// Handshake protocol implementation.
pub mod handshake;
/// Central Hub coordination.
pub mod hub_orchestration;
/// Network message definitions.
pub mod message;
/// Custom network behaviours.
/// Basic metrics collection.
pub mod metrics_simple;
/// P2P network behavior.
pub mod p2p;
/// Network protection against DoS and attacks.
pub mod network_protection;
pub mod network_protection_simple;

/// Peer identification and tracking.
pub mod peer;
/// Custom request/response protocol.
pub mod protocol;
/// Telemetry reporting service.
pub mod reporting_service;
/// Local network scanner.
pub mod scanner;
/// Security monitoring and alerts.
pub mod security;
/// Libp2p swarm manager.
pub mod swarm;
/// Common utility functions.
pub mod utils;
/// Main node entry point.
pub mod wolf_node;
/// Distributed coordination protocol.
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
/// The human‑readable name of the library.
pub const NAME: &str = "Wolf Net";

/// Initialize Wolf Net ID system
///
/// # Errors
/// Returns an error if logging setup fails.
pub fn init() -> anyhow::Result<()> {
    // Initialize logging
    let _ = utils::init_logging(tracing::Level::INFO);

    tracing::info!("🐺 {} v{} ID system initialized", NAME, VERSION);
    Ok(())
}

/// Create a new entity with specified types
#[must_use]
pub fn create_entity(
    service_type: ServiceType,
    system_type: SystemType,
    version: &str,
) -> EntityId {
    EntityId::create(service_type, system_type, version)
}

/// Create entity info for network tracking
#[must_use]
pub fn create_entity_info(
    service_type: ServiceType,
    system_type: SystemType,
    version: &str,
) -> EntityInfo {
    let entity_id = EntityId::create(service_type, system_type, version);
    EntityInfo::new(entity_id)
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
