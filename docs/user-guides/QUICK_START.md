# Quick Start Guide

## 🐺 Welcome to Wolf Prowler!

Get up and running with Wolf Prowler in minutes. This guide will walk you through the essential features and get you discovering your network territories right away!

## 🚀 5-Minute Quick Start

### Step 1: Install & Build
```bash
# Clone and build (if you haven't already)
git clone https://github.com/your-repo/wolf-prowler.git
cd wolf-prowler/wolf-prowler
cargo build --release
```

### Step 2: Discover Your Network
```bash
# Run network discovery - this is the main feature!
cargo run --bin wolf_prowler discover
```

### Step 3: Explore the Results
You'll see output like:
```
🗺️ Network Topology Discovery Demo
===================================
🎉 Discovery Complete!
📊 Discovery Statistics:
   Total IPs scanned: 254
   Responsive hosts: 8
🐺 Every device is now part of the wolf pack territory!
```

### Step 4: Try Other Features
```bash
# Test wolf communication (howls)
cargo run --bin wolf_prowler howl

# Explore territory infrastructure
cargo run --bin wolf_prowler territories

# Start the web dashboard
cargo run --bin wolf_prowler dashboard
```

**🎉 That's it! You're now running Wolf Prowler!**

## 🌐 Core Features Overview

### 🔍 Network Discovery (Main Feature)
**What it does:** Automatically discovers and maps your entire local network

**How to use:**
```bash
cargo run --bin wolf_prowler discover
```

**What you'll see:**
- All devices on your network (routers, servers, computers, IoT devices)
- Each device themed as a wolf territory
- Network topology visualization
- Service detection and port scanning
- Security assessment

**Example output:**
```
🏰 192.168.1.10 (server-alpha.local)
   🏗️ Infrastructure: Server | 🐺 Territory: Central command den
   🔌 Open ports: 4 | ⚡ Response: 12ms
   🛠️ Services:
     - Port 22: SSH (95% confidence)
     - Port 80: HTTP (90% confidence)
```

### 📢 Wolf Howl Communication
**What it does:** Peer-to-peer communication system themed as wolf howls

**How to use:**
```bash
cargo run --bin wolf_prowler howl
```

**What you'll see:**
- Different types of howls (territory, pack, hunt, alert)
- Peer discovery system
- Network topology generation
- Real-time message propagation

### 🏰 Wolf Territories
**What it does:** Network infrastructure themed as wolf territories

**How to use:**
```bash
cargo run --bin wolf_prowler territories
```

**What you'll see:**
- Servers → Alpha/Beta Dens (command centers)
- Routers → Trail Markers (path guidance)
- Switches → Meeting Points (gathering spots)
- Hosts → Individual Dens (personal spaces)
- Databases → Water Sources (essential resources)

### 📊 Security Dashboard
**What it does:** Web-based monitoring interface

**How to use:**
```bash
cargo run --bin wolf_prowler dashboard
```

**What you'll see:**
- Web interface at http://localhost:3000
- Real-time network monitoring
- Security metrics and alerts
- Territory visualization

## 🎯 Common Use Cases

### 1. Network Administrator
```bash
# Discover all devices on your network
cargo run --bin wolf_prowler discover

# Get a complete network map
cargo run --bin wolf_prowler territories

# Monitor network security
cargo run --bin wolf_prowler dashboard
```

### 2. Security Professional
```bash
# Perform network reconnaissance
cargo run --bin wolf_prowler discover

# Identify open ports and services
cargo run --bin test_discovery

# Monitor for security issues
cargo run --bin wolf_prowler dashboard
```

### 3. System Administrator
```bash
# Inventory network assets
cargo run --bin wolf_prowler discover

# Document network topology
cargo run --bin wolf_prowler territories

# Set up monitoring
cargo run --bin wolf_prowler dashboard
```

## 🔧 Basic Configuration

### Environment Variables
```bash
# Set logging level (debug, info, warn, error)
export RUST_LOG=info

# Network discovery settings
export DISCOVERY_TIMEOUT=2000        # Timeout in milliseconds
export DISCOVERY_CONCURRENT=50       # Max concurrent scans
export DISCOVERY_DEEP_SCAN=true      # Enable service detection
```

### Quick Configuration
Create a simple config file `~/.wolf-prowler/config.toml`:
```toml
[network_discovery]
timeout_ms = 2000
max_concurrent = 50
deep_scan = true
resolve_hostnames = true

[scan_ports]
common = [22, 80, 443, 3306, 5432]
```

## 🧪 Testing Your Installation

### Run All Tests
```bash
# Test network discovery
cargo run --bin test_discovery

# Test wolf communication
cargo run --bin test_howl

# Test territory system
cargo run --bin test_territories

# Run full integration test
cargo run --bin wolf_prowler integration
```

### Expected Results
Each test should complete successfully with wolf-themed output and no error messages.

## 📱 First Network Discovery Walkthrough

Let's walk through your first network discovery:

### 1. Start Discovery
```bash
cargo run --bin wolf_prowler discover
```

### 2. Watch the Process
You'll see:
```
🔍 Starting network discovery...
📍 This will scan your local network and map all devices!
⚠️  Note: This may take several minutes depending on network size
```

### 3. Review the Results
You'll get:
- **Discovery Statistics** - How many devices found, ports scanned, etc.
- **Network Segments** - Your network breakdown
- **Gateways** - Your routers and entry points
- **DNS Servers** - Your domain name servers
- **Discovered Devices** - All devices with wolf territory themes

### 4. Understand the Output
Each device shows:
```
🗺️ 192.168.1.1 (gateway.local)
   🏗️ Infrastructure: Router | 🐺 Territory: Trail marker
   🔌 Open ports: 3 | ⚡ Response: 5ms
   🛠️ Services: DNS, HTTP, Router Admin
```

## 🎯 Next Steps

### Explore More Features
```bash
# Try all available commands
cargo run --bin wolf_prowler --help

# Test wolf pack coordination
cargo run --bin wolf_prowler pack

# Run security tests
cargo run --bin wolf_prowler secure

# Start the web dashboard
cargo run --bin wolf_prowler dashboard
```

### Read the Documentation
- [Network Discovery Guide](NETWORK_DISCOVERY.md) - Deep dive into network mapping
- [Wolf Howl Communication](WOLF_HOWL.md) - Peer-to-peer communication
- [Wolf Territories](WOLF_TERRITORIES.md) - Infrastructure theming
- [Security Features](WOLF_DEN_CRYPTO.md) - Cryptography and security

### Customize Your Experience
```bash
# Edit configuration files
nano ~/.wolf-prowler/config.toml

# Create custom port lists
# Add your own territory mappings
# Configure security settings
```

## 🔍 Troubleshooting Quick Fixes

### "No devices discovered"
```bash
# Check network connectivity
ping 8.8.8.8

# Try with longer timeout
export DISCOVERY_TIMEOUT=5000
cargo run --bin wolf_prowler discover

# Check firewall settings
# Ensure outbound connections are allowed
```

### "Permission denied"
```bash
# Use cargo directly instead of binary
cargo run --bin wolf_prowler discover

# Check file permissions
ls -la target/release/
```

### "Build errors"
```bash
# Clean and rebuild
cargo clean
cargo build --release

# Update Rust
rustup update
```

## 🎉 Success Indicators

You know everything is working when you see:

✅ **Successful build** - No compilation errors  
✅ **Network discovery** - Devices found and themed  
✅ **Wolf territories** - Devices mapped to territories  
✅ **Service detection** - Ports and services identified  
✅ **Topology visualization** - Network structure displayed  
✅ **No error messages** - Clean, successful execution  

## 🚀 Going Further

### Advanced Usage
```bash
# Custom IP range
export DISCOVERY_START_IP="192.168.1.1"
export DISCOVERY_END_IP="192.168.1.254"

# Custom ports
export DISCOVERY_PORTS="22,80,443,3306,5432,8080"

# Deep scan mode
export DISCOVERY_DEEP_SCAN=true
export DISCOVERY_BANNER_GRAB=true
```

### Integration
```bash
# Export results
cargo run --bin wolf_prowler discover > network_map.txt

# Import into other tools
# Use JSON output for integration
# Combine with monitoring systems
```

### Automation
```bash
# Schedule regular discovery
# Add to cron jobs or task scheduler
# Set up automated reporting
# Integrate with alerting systems
```

## 🐺 Wolf Pack Community

### Get Help
- **Documentation** - Check these docs first
- **GitHub Issues** - Report bugs and request features
- **Community** - Join discussions and share experiences

### Share Your Experience
- Show off your network maps
- Share custom territory themes
- Contribute to the project
- Help other users

---

**🎉 Congratulations! You're now a Wolf Prowler!**

You've successfully:
✅ Installed and built Wolf Prowler  
✅ Discovered your network territories  
✅ Explored wolf-themed infrastructure mapping  
✅ Started your journey into network reconnaissance  

**Ready to explore your network like never before?** 🐺🗺️

The next step is to dive deeper into the features that interest you most. Whether it's network discovery, security monitoring, or wolf pack communication, there's always more territory to explore!

**Happy hunting!** 🦌
