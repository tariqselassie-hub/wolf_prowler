# Installation Guide

## 🐺 System Requirements

### Minimum Requirements
- **Rust 1.70+** - Latest stable Rust toolchain
- **Memory**: 512MB RAM minimum
- **Disk**: 100MB free space
- **Network**: Active network connection for discovery features

### Recommended Requirements
- **Rust 1.75+** - Latest stable with async features
- **Memory**: 2GB RAM for optimal performance
- **Disk**: 1GB free space for full build
- **Network**: Local network access for discovery
- **OS**: Windows 10+, macOS 10.15+, Linux (Ubuntu 20.04+)

## 🚀 Quick Installation

### 1. Install Rust
```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Restart your terminal or run:
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

### 2. Clone the Repository
```bash
# Clone the Wolf Prowler repository
git clone https://github.com/your-repo/wolf-prowler.git
cd wolf-prowler

# Navigate to the main project directory
cd wolf-prowler
```

### 3. Build the Project
```bash
# Build the main binary
cargo build --release

# Or build for development
cargo build
```

### 4. Run the Application
```bash
# Run the main application
cargo run --bin wolf_prowler --help

# Test network discovery
cargo run --bin wolf_prowler discover

# Start the dashboard
cargo run --bin wolf_prowler dashboard
```

## 🔧 Detailed Installation

### Prerequisites by Operating System

#### Windows
```powershell
# Install Rust (download from https://rustup.rs/)
# Install Visual Studio Build Tools (for C++ dependencies)
# Install Git for Windows

# Using PowerShell
# 1. Download and run rustup-init.exe
# 2. Restart PowerShell
# 3. Clone and build
```

#### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Rust
brew install rust

# Install additional dependencies
brew install openssl

# Clone and build
git clone https://github.com/your-repo/wolf-prowler.git
cd wolf-prowler/wolf-prowler
cargo build --release
```

#### Linux (Ubuntu/Debian)
```bash
# Update package manager
sudo apt update

# Install build dependencies
sudo apt install -y build-essential pkg-config libssl-dev

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/your-repo/wolf-prowler.git
cd wolf-prowler/wolf-prowler
cargo build --release
```

## 📦 Build Options

### Release Build (Recommended)
```bash
# Optimized for production use
cargo build --release

# Run the optimized binary
./target/release/wolf_prowler
```

### Development Build
```bash
# Faster compilation, debug symbols
cargo build

# Run development binary
./target/debug/wolf_prowler
```

### Custom Build Features
```bash
# Build with specific features
cargo build --release --features "full-features"

# Build without certain features
cargo build --release --no-default-features

# Build specific binary only
cargo build --release --bin wolf_prowler
cargo build --release --bin test_discovery
```

## 🗂️ Project Structure

After installation, your project structure should look like:

```
wolf-prowler/
├── wolf-prowler/           # Main project directory
│   ├── src/                 # Source code
│   │   ├── main.rs         # Main application entry
│   │   ├── wolf_howl.rs    # Howl communication
│   │   ├── wolf_territories.rs # Territory system
│   │   ├── network_discovery.rs # Network discovery
│   │   └── ...
│   ├── target/             # Build output
│   │   ├── release/        # Release binaries
│   │   └── debug/          # Debug binaries
│   ├── docs/               # Documentation
│   ├── config/             # Configuration files
│   └── Cargo.toml          # Project configuration
├── full/                   # Full version (if available)
└── README.md              # Project readme
```

## ⚙️ Configuration

### Environment Setup
```bash
# Set up environment variables
export RUST_LOG=info
export WOLF_PROWLER_CONFIG_DIR="$HOME/.wolf-prowler"

# Create config directory
mkdir -p "$WOLF_PROWLER_CONFIG_DIR"
```

### Configuration Files
Create configuration files in `~/.wolf-prowler/` or the project config directory:

#### `network.toml`
```toml
[network_discovery]
timeout_ms = 2000
max_concurrent = 50
deep_scan = true
resolve_hostnames = true

[scan_ports]
common = [22, 80, 443, 3306, 5432]
extended = [21, 23, 25, 53, 110, 143, 993, 995]
custom = []
```

#### `security.toml`
```toml
[security]
encryption_algorithm = "AES-256-GCM"
hash_algorithm = "SHA-256"
key_derivation = "PBKDF2"

[certificates]
auto_generate = true
validity_days = 365
key_size = 2048
```

## 🧪 Verification

### Test Installation
```bash
# Test basic functionality
cargo run --bin wolf_prowler test

# Test network discovery
cargo run --bin test_discovery

# Test wolf communication
cargo run --bin test_howl

# Test territory system
cargo run --bin test_territories
```

### Expected Output
You should see successful test runs with wolf-themed output:

```
🗺️ Network Topology Discovery Demo
===================================
🔍 Starting network discovery simulation...
🎉 Discovery Complete!
📊 Discovery Statistics:
   Total IPs scanned: 254
   Responsive hosts: 8
🐺 Every device is now part of the wolf pack territory!
```

## 🔧 Troubleshooting

### Common Issues

#### "cargo: command not found"
```bash
# Install Rust first
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

#### "Linker error" on Windows
```bash
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/
# Select "C++ build tools" during installation
```

#### "OpenSSL headers not found" on Linux
```bash
# Install development headers
sudo apt install libssl-dev pkg-config
# or on CentOS/RHEL
sudo yum install openssl-devel
```

#### "Permission denied" errors
```bash
# Check file permissions
ls -la target/release/
chmod +x target/release/wolf_prowler

# Or run with cargo directly
cargo run --bin wolf_prowler
```

#### Network discovery not working
```bash
# Check network connectivity
ping 8.8.8.8

# Check if ports are accessible
telnet your-router-ip 80

# Run with debug logging
RUST_LOG=debug cargo run --bin wolf_prowler discover
```

### Build Issues

#### Clean Build
```bash
# Clean previous build artifacts
cargo clean

# Rebuild from scratch
cargo build --release
```

#### Update Dependencies
```bash
# Update Cargo.lock
cargo update

# Rebuild with latest dependencies
cargo build --release
```

#### Check Rust Version
```bash
# Ensure you have compatible Rust version
rustc --version
# Should be 1.70 or newer

# Update Rust if needed
rustup update
```

## 🚀 Performance Optimization

### Build Optimizations
```bash
# Maximum optimization
cargo build --release --target-cpu=native

# Strip debug symbols for smaller binary
cargo build --release && strip target/release/wolf_prowler

# Use LTO (Link Time Optimization)
export RUSTFLAGS="-C link-arg=-fuse-ld=lld"
cargo build --release --lto
```

### Runtime Optimizations
```bash
# Set environment for better performance
export RUST_LOG=warn  # Reduce logging overhead
export TOKIO_WORKER_THREADS=4  # Set worker threads

# Run with optimized settings
cargo run --release --bin wolf_prowler discover
```

## 📦 Distribution

### Creating a Release Package
```bash
# Build release binary
cargo build --release

# Create distribution directory
mkdir -p wolf-prowler-v1.0.0/{bin,docs,config}

# Copy files
cp target/release/wolf_prowler wolf-prowler-v1.0.0/bin/
cp -r docs/* wolf-prowler-v1.0.0/docs/
cp -r config/* wolf-prowler-v1.0.0/config/

# Create archive
tar -czf wolf-prowler-v1.0.0.tar.gz wolf-prowler-v1.0.0/
```

### Installation from Archive
```bash
# Extract archive
tar -xzf wolf-prowler-v1.0.0.tar.gz
cd wolf-prowler-v1.0.0

# Run the binary
./bin/wolf_prowler --help
```

## 🔄 Updates

### Updating Wolf Prowler
```bash
# Pull latest changes
git pull origin main

# Update dependencies
cargo update

# Rebuild
cargo build --release

# Test the update
cargo run --bin wolf_prowler test
```

### Checking for Updates
```bash
# Check git status
git status

# Check for new releases
git tag -l | tail -5
```

## 📚 Next Steps

After successful installation:

1. **Read the Quick Start Guide** - [QUICK_START.md](QUICK_START.md)
2. **Try Network Discovery** - `cargo run --bin wolf_prowler discover`
3. **Explore the Dashboard** - `cargo run --bin wolf_prowler dashboard`
4. **Read the Documentation** - [docs/README.md](README.md)

## 🤝 Getting Help

If you encounter issues during installation:

1. **Check this guide** for common solutions
2. **Search existing issues** on GitHub
3. **Create a new issue** with detailed error information
4. **Join community discussions** for help

---

**🐺 Happy hunting with Wolf Prowler!**

Once installed, you'll have a powerful network discovery and management system with an immersive wolf-themed experience. Enjoy exploring your network territories! 🗺️
