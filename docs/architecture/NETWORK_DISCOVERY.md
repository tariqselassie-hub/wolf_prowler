# Network Topology Discovery System

## 🐺 Overview

The Network Topology Discovery system is a powerful network reconnaissance tool that automatically discovers and maps the entire local network topology from your entry point to all connected corners of the system. Every discovered device is themed as part of the wolf pack territory system, creating an immersive and intuitive network mapping experience.

## 🎯 Key Features

### 🔍 Advanced Discovery Capabilities
- **Automatic IP Range Detection** - Discovers local network automatically
- **Concurrent Port Scanning** - Scans up to 50 hosts simultaneously for speed
- **Service Detection** - Identifies running services and grabs banners
- **Device Classification** - Automatically categorizes devices by type
- **Wolf Territory Mapping** - Converts all devices to themed territories
- **Network Topology Visualization** - Shows complete network structure
- **Gateway/DNS Identification** - Finds critical network infrastructure
- **Response Time Measurement** - Performance metrics for each device
- **Security Assessment** - Evaluates security levels based on open ports

### 🏰 Wolf Territory Theming
Every network component is mapped to its natural wolf equivalent:

| **Network Component** | **Wolf Territory** | **Wolf Theme** | **Purpose** |
|----------------------|-------------------|---------------|-------------|
| 🖥️ **Servers** | 🏰 **Alpha/Beta Dens** | Command centers | Main/backup servers |
| 🌐 **Routers** | 🗺️ **Trail Markers** | Path guidance | Network routing |
| 🔌 **Switches** | 🐺 **Meeting Points** | Gathering spots | Network switching |
| 💻 **Hosts** | 🏚️ **Individual Dens** | Personal spaces | Client computers |
| 🗄️ **Databases** | 💧 **Water Sources** | Essential resources | Data storage |
| 🔥 **Firewalls** | 🛡️ **Border Patrol** | Territory protection | Security systems |
| 📊 **Monitoring** | 👁️ **Lookout Points** | Observation posts | Network monitoring |
| ☁️ **Cloud** | 🦌 **Hunting Grounds** | Resource gathering | Cloud services |
| 💾 **CDN** | 📦 **Cache Points** | Frequent resources | Content delivery |

## 🚀 Usage

### Basic Usage

```bash
# Run network discovery
cargo run --bin wolf_prowler discover

# Run standalone demo
cargo run --bin test_discovery

# View all available commands
cargo run --bin wolf_prowler --help
```

### Configuration Options

The discovery system can be configured with these options:

```rust
DiscoveryConfig {
    start_ip: Ipv4Addr::new(192, 168, 1, 1),     // Starting IP
    end_ip: Ipv4Addr::new(192, 168, 1, 254),     // Ending IP
    scan_ports: vec![22, 80, 443, 3306, ...],    // Ports to scan
    connection_timeout: Duration::from_millis(2000),
    max_concurrent_scans: 50,                     // Concurrent hosts
    deep_scan: true,                             // Service detection
    resolve_hostnames: true,                      // DNS resolution
}
```

## 🌐 Discovery Process

### 1. Network Range Detection
The system automatically detects your local network range:
- Identifies your local IP address
- Determines subnet mask
- Calculates scan range (typically /24 network)

### 2. Host Discovery
Scans the entire network range to find responsive hosts:
- TCP ping on common ports (80, 443, 22)
- Response time measurement
- Hostname resolution via DNS

### 3. Port Scanning
For each responsive host, scans configured ports:
- Concurrent scanning for performance
- Configurable timeout per port
- Open port identification

### 4. Service Detection
Identifies services running on open ports:
- Banner grabbing for service identification
- Version detection when possible
- Confidence scoring for accuracy

### 5. Device Classification
Classifies devices based on open ports and services:
- **Router/Gateway** - DNS, DHCP, routing services
- **Server** - Multiple services, high port count
- **Workstation** - SSH, RDP, VNC services
- **Storage** - Database ports (MySQL, PostgreSQL, etc.)
- **Firewall** - Management ports only
- **IoT Device** - Limited services, web interface

### 6. Territory Mapping
Maps each device type to appropriate wolf territory:
- Based on device role and capabilities
- Security level assessment
- Natural wolf pack hierarchy

## 📊 Output Examples

### Discovery Statistics
```
📊 Discovery Statistics:
   Total IPs scanned: 254
   Responsive hosts: 8
   Total open ports: 19
   Discovery duration: 120s
   Average response time: 11.6ms
```

### Device Details
```
🏰 192.168.1.10 (server-alpha.local)
   🏗️ Infrastructure: Server | 🐺 Territory: Central command den
   🔌 Open ports: 4 | ⚡ Response: 12ms
   🛠️ Services:
     - Port 22: SSH (95% confidence)
       Banner: OpenSSH_7.4
     - Port 80: HTTP (90% confidence)
       Banner: Apache/2.4.41
```

### Network Topology
```
🌐 Discovered Network Topology (Wolf Theme):
==============================================
🌍 Internet
  │
  🛡️ Border Patrol (Firewall: 192.168.1.253)
  │
  🗺️ Trail Marker (Gateway: 192.168.1.1)
  │
  ├─🐺 Meeting Point (Switch: 192.168.1.254)
  │  │
  │  ├─🏰 Alpha Den (Server: 192.168.1.10)
  │  │  └─💧 Water Source (Database: 192.168.1.20)
  │  │
  │  └─🏚️ Individual Den (Workstation: 192.168.1.100)
```

## 🔧 Technical Implementation

### Core Components

#### NetworkDiscovery
Main discovery engine that orchestrates the entire scanning process.

#### DiscoveredDevice
Represents a found network device with all its properties:
```rust
pub struct DiscoveredDevice {
    pub ip_address: IpAddr,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub services: Vec<DetectedService>,
    pub device_type: DeviceType,
    pub territory_type: TerritoryType,
    pub response_time: u64,
    pub discovered_at: DateTime<Utc>,
}
```

#### NetworkTopology
Complete network map containing all discovered devices and statistics.

#### TerritoryType
Wolf-themed territory classifications that map to network infrastructure.

### Scanning Algorithms

#### TCP Port Scanning
```rust
async fn scan_port(ip: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}
```

#### Service Detection
```rust
async fn grab_banner(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    // Connect to service
    // Send appropriate probe
    // Read response banner
    // Return identified service
}
```

#### Device Classification
```rust
fn classify_device_type(device: &DiscoveredDevice) -> DeviceType {
    let ports: HashSet<u16> = device.open_ports.iter().cloned().collect();
    
    match ports {
        _ if ports.contains(&53) => DeviceType::Router,
        _ if ports.contains(&3306) => DeviceType::Storage,
        _ if ports.contains(&22) && ports.contains(&80) => DeviceType::Server,
        _ => DeviceType::Unknown,
    }
}
```

## 🛡️ Security Considerations

### Permissions Required
- Network access for TCP connections
- DNS resolution capabilities
- No elevated privileges required

### Network Impact
- **Minimal**: Uses standard TCP connections
- **Configurable**: Adjustable timeouts and concurrency
- **Respectful**: Default 2-second timeout per port

### Data Privacy
- All scanning data stays local
- No external network communication
- Results stored only in memory during execution

## 🎯 Use Cases

### Network Administration
- **Network Inventory**: Complete device listing
- **Service Mapping**: Identify running services
- **Security Assessment**: Find open ports and potential vulnerabilities
- **Topology Documentation**: Visual network structure

### Security Auditing
- **Asset Discovery**: Find all network-connected devices
- **Port Scanning**: Identify exposed services
- **Service Versioning**: Detect outdated software
- **Network Mapping**: Understand network layout

### System Integration
- **Automated Discovery**: Scheduled network scans
- **Integration**: Combine with monitoring systems
- **Alerting**: Notify on new devices or services
- **Reporting**: Generate network documentation

## 🔍 Advanced Features

### Custom Port Ranges
```rust
let mut config = DiscoveryConfig::default();
config.scan_ports = vec![80, 443, 8080, 8443]; // Web services only
```

### Service Fingerprinting
The system includes service fingerprinting for:
- **Web Servers** - Apache, Nginx, IIS
- **Database Servers** - MySQL, PostgreSQL, MSSQL
- **Remote Access** - SSH, RDP, VNC
- **Network Services** - DNS, DHCP, SNMP

### Performance Optimization
- **Concurrent Scanning** - Up to 50 hosts simultaneously
- **Adaptive Timeouts** - Adjust based on network latency
- **Result Caching** - Avoid duplicate scans
- **Progress Tracking** - Real-time scan progress

## 📈 Integration Examples

### Programmatic Usage
```rust
use wolf_prowler::network_discovery::{NetworkDiscovery, DiscoveryConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let config = DiscoveryConfig::default();
    let mut discovery = NetworkDiscovery::new(config)?;
    
    let topology = discovery.discover_topology().await?;
    
    println!("Discovered {} devices", topology.devices.len());
    
    Ok(())
}
```

### Custom Territory Mapping
```rust
fn custom_territory_mapping(device: &DiscoveredDevice) -> TerritoryType {
    match device.device_type {
        DeviceType::Server => {
            if device.open_ports.len() > 10 {
                TerritoryType::AlphaDen
            } else {
                TerritoryType::BetaDen
            }
        }
        DeviceType::Router => TerritoryType::TrailMarker,
        // ... custom logic
    }
}
```

## 🐺 Wolf Pack Integration

The discovery system integrates seamlessly with the wolf pack ecosystem:

### Territory Manager Integration
```rust
let territories = discovery.convert_to_territories(&topology);
for territory in territories {
    territory_manager.register_territory(territory)?;
}
```

### Howl Communication
```rust
// Send discovery howls to find other wolf prowler instances
let discovered_peers = manager.send_peer_discovery_howl(
    "scout_wolf".to_string(),
    "northern_pack".to_string(),
    "Scout".to_string(),
    "192.168.1.100:8080".to_string()
).await?;
```

### Dashboard Integration
```rust
// Display discovered network in security dashboard
dashboard.add_network_topology(&topology);
```

## 🔧 Troubleshooting

### Common Issues

#### "No devices discovered"
- Check network connectivity
- Verify IP range configuration
- Ensure firewall allows outbound connections
- Try with longer timeouts

#### "Slow discovery"
- Reduce `max_concurrent_scans`
- Increase `connection_timeout`
- Limit scan ports to essential ones
- Check network latency

#### "Permission denied"
- Ensure network access is allowed
- Check local firewall settings
- Run with appropriate network permissions

### Debug Mode
Enable debug logging for detailed information:
```bash
RUST_LOG=debug cargo run --bin wolf_prowler discover
```

## 📚 API Reference

### NetworkDiscovery
```rust
impl NetworkDiscovery {
    pub fn new(config: DiscoveryConfig) -> Result<Self>;
    pub async fn discover_topology(&mut self) -> Result<NetworkTopology>;
    pub fn convert_to_territories(&self, topology: &NetworkTopology) -> Vec<WolfTerritory>;
}
```

### DiscoveryConfig
```rust
pub struct DiscoveryConfig {
    pub start_ip: Ipv4Addr,
    pub end_ip: Ipv4Addr,
    pub scan_ports: Vec<u16>,
    pub connection_timeout: Duration,
    pub max_concurrent_scans: usize,
    pub deep_scan: bool,
    pub resolve_hostnames: bool,
}
```

### NetworkTopology
```rust
pub struct NetworkTopology {
    pub devices: Vec<DiscoveredDevice>,
    pub gateways: Vec<DiscoveredDevice>,
    pub dns_servers: Vec<DiscoveredDevice>,
    pub statistics: DiscoveryStatistics,
    pub discovered_at: DateTime<Utc>,
}
```

## 🎉 Conclusion

The Network Topology Discovery system provides comprehensive network mapping capabilities with an immersive wolf-themed interface. It transforms technical network reconnaissance into an intuitive experience while maintaining professional-grade functionality.

Whether you're a network administrator, security professional, or system integrator, this tool offers the perfect blend of power, usability, and thematic consistency with the Wolf Prowler ecosystem.

**Deploy it on any system and discover your entire network from entry point to all corners!** 🐺🗺️
