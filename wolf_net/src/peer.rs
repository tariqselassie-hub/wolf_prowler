//! Wolf Net Entity Identification System
//!
//! Comprehensive ID system for identifying all aspects of an entity:
//! - Peer ID: Network-level identification
//! - Device ID: Hardware/device identification  
//! - Service ID: Service/process identification
//! - System ID: Overall system identification

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

/// Primary network identifier for entities
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId(String);

// Type alias for libp2p PeerId to avoid conflicts
/// Alias for the libp2p `PeerId` type to avoid naming conflicts.
pub type Libp2pPeerId = libp2p::PeerId;

impl PeerId {
    /// Generate a new random peer ID
    pub fn new() -> Self {
        Self(Libp2pPeerId::random().to_string())
    }

    /// Create from string
    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    /// Get string representation
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get peer ID (alias for as_str for compatibility)
    pub fn peer_id(&self) -> &str {
        &self.0
    }

    /// Check if this is a valid peer ID
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty() && self.0.len() >= 8
    }

    /// Convert to libp2p PeerId
    pub fn as_libp2p(&self) -> Libp2pPeerId {
        // Parse from Base58 (which is what we store in self.0)
        self.0.parse().unwrap_or_else(|_| Libp2pPeerId::random())
    }

    /// Create from libp2p PeerId
    pub fn from_libp2p(libp2p_id: Libp2pPeerId) -> Self {
        Self(libp2p_id.to_string())
    }

    /// Generate a random peer ID (alias for new())
    pub fn random() -> Self {
        Self::new()
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer:{}", self.0)
    }
}

/// Device identifier for hardware/system identification
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    /// Generate a new device ID
    pub fn new() -> Self {
        Self(format!("device_{}", Uuid::new_v4()))
    }

    /// Create from hardware identifier (MAC address, etc.)
    pub fn from_hardware(hardware_id: &str) -> Self {
        Self(format!("device_hw_{}", hardware_id))
    }

    /// Create from string
    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    /// Get string representation
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract hardware ID if present
    pub fn hardware_id(&self) -> Option<&str> {
        self.0.strip_prefix("device_hw_")
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Service identifier for process/service identification
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceId {
    id: String,
    service_type: ServiceType,
    instance: u32,
}

impl ServiceId {
    /// Create a new service ID
    pub fn new(service_type: ServiceType, instance: u32) -> Self {
        let id = format!("svc_{}_{}", service_type.prefix(), instance);
        Self {
            id,
            service_type,
            instance,
        }
    }

    /// I will check the file content next.
    pub fn from_components(service_type: ServiceType, name: &str, instance: u32) -> Self {
        let id = format!("svc_{}_{}_{}", service_type.prefix(), name, instance);
        Self {
            id,
            service_type,
            instance,
        }
    }

    /// Create from string (parse)
    pub fn from_string(id: String) -> anyhow::Result<Self> {
        // Parse format: svc_{type}_{name}_{instance}
        let parts: Vec<&str> = id.split('_').collect();
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("Invalid service ID format"));
        }

        let service_type = ServiceType::from_prefix(parts[1])?;
        let instance = parts.last().unwrap_or(&"0").parse::<u32>()?;

        Ok(Self {
            id,
            service_type,
            instance,
        })
    }

    /// Get string representation
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// Get service type
    pub fn service_type(&self) -> ServiceType {
        self.service_type
    }

    /// Get instance number
    pub fn instance(&self) -> u32 {
        self.instance
    }
}

impl Default for ServiceId {
    fn default() -> Self {
        Self::new(ServiceType::Unknown, 0)
    }
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Service types supported by Wolf Net
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceType {
    /// Unknown or unspecified service type.
    Unknown,
    /// Router service.
    Router,
    /// Server service.
    Server,
    /// Client service.
    Client,
    /// MDNS discovery service.
    Discovery,
    /// Storage service.
    Storage,
    /// Compute service.
    Compute,
    /// Monitoring service.
    Monitoring,
    /// Security service.
    Security,
    /// Database service.
    Database,
    /// Message broker service.
    MessageBroker,
    /// API gateway service.
    ApiGateway,
    /// Load balancer service.
    LoadBalancer,
    /// Firewall service.
    Firewall,
    /// Proxy service.
    Proxy,
    /// Cache service.
    Cache,
}

impl ServiceType {
    /// Get prefix for this service type
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Router => "router",
            Self::Server => "server",
            Self::Client => "client",
            Self::Discovery => "discovery",
            Self::Storage => "storage",
            Self::Compute => "compute",
            Self::Monitoring => "monitor",
            Self::Security => "security",
            Self::Database => "database",
            Self::MessageBroker => "broker",
            Self::ApiGateway => "gateway",
            Self::LoadBalancer => "balancer",
            Self::Firewall => "firewall",
            Self::Proxy => "proxy",
            Self::Cache => "cache",
        }
    }

    /// Create from prefix string
    pub fn from_prefix(prefix: &str) -> anyhow::Result<Self> {
        match prefix {
            "unknown" => Ok(Self::Unknown),
            "router" => Ok(Self::Router),
            "server" => Ok(Self::Server),
            "client" => Ok(Self::Client),
            "discovery" => Ok(Self::Discovery),
            "storage" => Ok(Self::Storage),
            "compute" => Ok(Self::Compute),
            "monitor" => Ok(Self::Monitoring),
            "security" => Ok(Self::Security),
            "database" => Ok(Self::Database),
            "broker" => Ok(Self::MessageBroker),
            "gateway" => Ok(Self::ApiGateway),
            "balancer" => Ok(Self::LoadBalancer),
            "firewall" => Ok(Self::Firewall),
            "proxy" => Ok(Self::Proxy),
            "cache" => Ok(Self::Cache),
            _ => Err(anyhow::anyhow!("Unknown service type prefix: {}", prefix)),
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown Service",
            Self::Router => "Router",
            Self::Server => "Server",
            Self::Client => "Client",
            Self::Discovery => "Discovery Service",
            Self::Storage => "Storage Service",
            Self::Compute => "Compute Service",
            Self::Monitoring => "Monitoring Service",
            Self::Security => "Security Service",
            Self::Database => "Database Service",
            Self::MessageBroker => "Message Broker",
            Self::ApiGateway => "API Gateway",
            Self::LoadBalancer => "Load Balancer",
            Self::Firewall => "Firewall",
            Self::Proxy => "Proxy Service",
            Self::Cache => "Cache Service",
        }
    }
}

/// System identifier for overall system identification
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemId {
    id: String,
    system_type: SystemType,
    version: String,
    created_at: DateTime<Utc>,
}

impl SystemId {
    /// Create a new system ID
    pub fn new(system_type: SystemType, version: &str) -> Self {
        let id = format!(
            "sys_{}_{}_{}",
            system_type.prefix(),
            version,
            Uuid::new_v4()
        );
        Self {
            id,
            system_type,
            version: version.to_string(),
            created_at: Utc::now(),
        }
    }

    /// Create from string
    pub fn from_string(id: String) -> anyhow::Result<Self> {
        // Parse format: sys_{type}_{version}_{uuid}
        let parts: Vec<&str> = id.split('_').collect();
        if parts.len() < 4 {
            return Err(anyhow::anyhow!("Invalid system ID format"));
        }

        let system_type = SystemType::from_prefix(parts[1])?;
        let version = parts[2].to_string();

        Ok(Self {
            id,
            system_type,
            version,
            created_at: Utc::now(), // We don't store timestamp in the ID string
        })
    }

    /// Get string representation
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// Get system type
    pub fn system_type(&self) -> SystemType {
        self.system_type
    }

    /// Get version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get creation time
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

impl Default for SystemId {
    fn default() -> Self {
        Self::new(SystemType::Unknown, "1.0.0")
    }
}

impl std::fmt::Display for SystemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// System types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemType {
    /// Unknown system type.
    Unknown,
    /// Development environment.
    Development,
    /// Production environment.
    Production,
    /// Testing environment.
    Testing,
    /// Staging environment.
    Staging,
    /// Local environment.
    Local,
    /// Cloud environment.
    Cloud,
    /// Edge computing environment.
    Edge,
    /// Hybrid environment.
    Hybrid,
    /// Distributed environment.
    Distributed,
    /// Standalone environment.
    Standalone,
}

impl SystemType {
    /// Get prefix for this system type
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Development => "dev",
            Self::Production => "prod",
            Self::Testing => "test",
            Self::Staging => "staging",
            Self::Local => "local",
            Self::Cloud => "cloud",
            Self::Edge => "edge",
            Self::Hybrid => "hybrid",
            Self::Distributed => "dist",
            Self::Standalone => "standalone",
        }
    }

    /// Create from prefix
    pub fn from_prefix(prefix: &str) -> anyhow::Result<Self> {
        match prefix {
            "unknown" => Ok(Self::Unknown),
            "dev" => Ok(Self::Development),
            "prod" => Ok(Self::Production),
            "test" => Ok(Self::Testing),
            "staging" => Ok(Self::Staging),
            "local" => Ok(Self::Local),
            "cloud" => Ok(Self::Cloud),
            "edge" => Ok(Self::Edge),
            "hybrid" => Ok(Self::Hybrid),
            "dist" => Ok(Self::Distributed),
            "standalone" => Ok(Self::Standalone),
            _ => Err(anyhow::anyhow!("Unknown system type prefix: {}", prefix)),
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown System",
            Self::Development => "Development System",
            Self::Production => "Production System",
            Self::Testing => "Testing System",
            Self::Staging => "Staging System",
            Self::Local => "Local System",
            Self::Cloud => "Cloud System",
            Self::Edge => "Edge System",
            Self::Hybrid => "Hybrid System",
            Self::Distributed => "Distributed System",
            Self::Standalone => "Standalone System",
        }
    }
}

/// Complete entity identification combining all ID types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityId {
    /// Network peer ID
    pub peer_id: PeerId,
    /// Device ID
    pub device_id: DeviceId,
    /// Service ID
    pub service_id: ServiceId,
    /// System ID
    pub system_id: SystemId,
    /// Entity creation time
    pub created_at: DateTime<Utc>,
    /// Last updated time
    pub updated_at: DateTime<Utc>,
    /// Entity metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Entity status
    pub status: EntityStatus,
    /// Trust score (0.0 - 1.0)
    pub trust_score: f64,
    /// Entity capabilities
    pub capabilities: Vec<String>,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Performance metrics
    pub metrics: EntityMetrics,
}

impl EntityId {
    /// Create a new complete entity ID
    pub fn new(
        peer_id: PeerId,
        device_id: DeviceId,
        service_id: ServiceId,
        system_id: SystemId,
    ) -> Self {
        let now = Utc::now();
        Self {
            peer_id,
            device_id,
            service_id,
            system_id,
            created_at: now,
            updated_at: now,
            metadata: std::collections::HashMap::new(),
            status: EntityStatus::Unknown,
            trust_score: 0.5,
            capabilities: Vec::new(),
            addresses: Vec::new(),
            metrics: EntityMetrics::default(),
        }
    }

    /// Create with service type and system type
    pub fn create(service_type: ServiceType, system_type: SystemType, version: &str) -> Self {
        Self::new(
            PeerId::new(),
            DeviceId::new(),
            ServiceId::new(service_type, 0),
            SystemId::new(system_type, version),
        )
    }

    /// Update timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Add metadata
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
        self.touch();
    }

    /// Get metadata
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Get entity summary
    pub fn summary(&self) -> String {
        format!(
            "Entity: {} | {} | {} | {}",
            self.peer_id, self.device_id, self.service_id, self.system_id
        )
    }

    /// Check if entity is of a specific service type
    pub fn is_service_type(&self, service_type: ServiceType) -> bool {
        self.service_id.service_type() == service_type
    }

    /// Check if entity is of a specific system type
    pub fn is_system_type(&self, system_type: SystemType) -> bool {
        self.system_id.system_type() == system_type
    }

    /// Get entity age
    pub fn age(&self) -> chrono::Duration {
        Utc::now() - self.created_at
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new(
            PeerId::default(),
            DeviceId::default(),
            ServiceId::default(),
            SystemId::default(),
        )
    }
}

/// Entity status and connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityInfo {
    /// Complete entity ID
    pub entity_id: EntityId,
    /// Network addresses
    pub addresses: Vec<SocketAddr>,
    /// Connection status
    pub status: EntityStatus,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Trust score (0.0 to 1.0)
    pub trust_score: f64,
    /// Capabilities
    pub capabilities: Vec<String>,
    /// Protocol version
    pub protocol_version: Option<String>,
    /// Agent version
    pub agent_version: Option<String>,
    /// Performance metrics
    pub metrics: EntityMetrics,
}

impl EntityInfo {
    /// Create new entity info
    pub fn new(entity_id: EntityId) -> Self {
        Self {
            entity_id,
            addresses: Vec::new(),
            status: EntityStatus::Unknown,
            last_seen: Utc::now(),
            trust_score: 0.5,
            capabilities: Vec::new(),
            protocol_version: None,
            agent_version: None,
            metrics: EntityMetrics::default(),
        }
    }

    /// Add address
    pub fn add_address(&mut self, addr: SocketAddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    /// Update status
    pub fn set_status(&mut self, status: EntityStatus) {
        self.status = status;
        self.last_seen = Utc::now();
    }

    /// Add capability
    pub fn add_capability(&mut self, capability: String) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
        }
    }

    /// Update trust score
    pub fn update_trust_score(&mut self, score: f64) {
        self.trust_score = score.clamp(0.0, 1.0);
    }

    /// Check if entity is online
    pub fn is_online(&self) -> bool {
        matches!(self.status, EntityStatus::Online)
    }

    /// Check if entity is trusted
    pub fn is_trusted(&self) -> bool {
        self.trust_score >= 0.7
    }
}

impl Default for EntityInfo {
    fn default() -> Self {
        Self::new(EntityId::default())
    }
}

/// Entity status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityStatus {
    /// The status is unknown or not yet determined.
    Unknown,
    /// The peer is currently online and reachable.
    Online,
    /// The peer is currently offline.
    Offline,
    /// The peer is in the process of establishing a connection.
    Connecting,
    /// The peer is being disconnected.
    Disconnecting,
    /// An error occurred, with a description.
    Error(String),
    /// The peer is under maintenance and may not respond.
    Maintenance,
}

/// Entity performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityMetrics {
    /// CPU usage (0.0 to 1.0)
    pub cpu_usage: f64,
    /// Memory usage (0.0 to 1.0)
    pub memory_usage: f64,
    /// Network latency in milliseconds
    pub latency_ms: u64,
    /// Throughput in bytes per second
    pub throughput_bps: u64,
    /// Total messages sent to this peer
    pub messages_sent: u64,
    /// Total messages received from this peer
    pub messages_received: u64,
    /// Total bytes sent to this peer
    pub bytes_sent: u64,
    /// Total bytes received from this peer
    pub bytes_received: u64,
    /// Successful requests/deliveries
    pub requests_success: u64,
    /// Failed requests/deliveries
    pub requests_failed: u64,
    /// Network health score (0.0 to 1.0)
    pub health_score: f64,
    /// Total requests sent to this peer
    pub requests_sent: u64,
    /// Total requests received from this peer
    pub requests_received: u64,
    /// When this peer was first seen
    pub first_seen: DateTime<Utc>,
    /// Total uptime in milliseconds
    pub uptime_ms: u64,
    /// Last updated
    pub last_updated: DateTime<Utc>,
}

impl Default for EntityMetrics {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            latency_ms: 0,
            throughput_bps: 0,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            requests_success: 0,
            requests_failed: 0,
            requests_sent: 0,
            requests_received: 0,
            health_score: 1.0, // Start with full health
            first_seen: now,
            uptime_ms: 0,
            last_updated: now,
        }
    }
}

impl EntityMetrics {
    /// Calculate and update network health score
    pub fn update_health(&mut self) {
        // Simple health score calculation based on latency and request success rate
        let latency_score = if self.latency_ms == 0 {
            1.0
        } else if self.latency_ms < 50 {
            1.0
        } else if self.latency_ms < 200 {
            0.8
        } else if self.latency_ms < 500 {
            0.5
        } else {
            0.2
        };

        let total_requests = self.requests_success + self.requests_failed;
        let success_score = if total_requests == 0 {
            1.0
        } else {
            self.requests_success as f64 / total_requests as f64
        };

        // Weighted average: 40% latency, 60% success rate
        self.health_score = (latency_score * 0.4) + (success_score * 0.6);
        self.last_updated = Utc::now();
    }
}

/// Peer information for network discovery and management
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Known addresses
    pub addresses: Vec<SocketAddr>,
    /// Capabilities
    pub capabilities: Vec<String>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Trust score
    pub trust_score: f64,
    /// Active session secret for encrypted communication (not serialized)
    #[serde(skip)]
    pub session_secret: Option<Vec<u8>>,
    status: EntityStatus,
}

impl PeerInfo {
    /// Create new peer info
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            addresses: Vec::new(),
            capabilities: Vec::new(),
            last_seen: Utc::now(),
            trust_score: 0.0,
            session_secret: None,
            status: EntityStatus::Unknown,
        }
    }

    /// Add an address
    pub fn add_address(&mut self, addr: SocketAddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    /// Add a capability
    pub fn add_capability(&mut self, capability: String) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
        }
    }

    /// Update trust score
    pub fn update_trust_score(&mut self, score: f64) {
        self.trust_score = score.clamp(0.0, 1.0);
    }

    /// Set the session secret for encrypted communication
    pub fn set_session_secret(&mut self, secret: Vec<u8>) {
        self.session_secret = Some(secret);
    }

    /// Get the session secret
    pub fn session_secret(&self) -> Option<&[u8]> {
        self.session_secret.as_deref()
    }

    /// Check if peer is trusted
    pub fn is_trusted(&self) -> bool {
        self.trust_score > 0.5
    }

    /// Get status
    pub fn status(&self) -> EntityStatus {
        self.status.clone()
    }

    /// Get trust score
    pub fn trust_score(&self) -> f64 {
        self.trust_score
    }

    /// Get capabilities
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Get addresses
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    // Note: PeerInfo does not have metrics or entity_id fields.
    // Use EntityInfo instead for full entity information.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_creation() {
        let peer_id = PeerId::new();
        assert!(peer_id.is_valid());
        assert!(peer_id.as_str().len() >= 8);
    }

    #[test]
    fn test_service_id_creation() {
        let service_id = ServiceId::new(ServiceType::Router, 1);
        assert_eq!(service_id.service_type(), ServiceType::Router);
        assert_eq!(service_id.instance(), 1);
        assert!(service_id.as_str().starts_with("svc_router_"));
    }

    #[test]
    fn test_entity_id_creation() {
        let entity = EntityId::create(ServiceType::Server, SystemType::Production, "1.0.0");

        assert!(entity.is_service_type(ServiceType::Server));
        assert!(entity.is_system_type(SystemType::Production));
        assert!(entity.summary().contains("svc_server_"));
        assert!(entity.summary().contains("sys_prod_"));
    }

    #[test]
    fn test_entity_info() {
        let entity_id = EntityId::create(ServiceType::Database, SystemType::Cloud, "2.1.0");
        let mut info = EntityInfo::new(entity_id);

        info.set_status(EntityStatus::Online);
        info.add_capability("sql".to_string());
        info.update_trust_score(0.8);

        assert!(info.is_online());
        assert!(info.is_trusted());
        assert!(info.capabilities.contains(&"sql".to_string()));
    }
}
