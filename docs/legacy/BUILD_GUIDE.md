# Wolf Prowler Build Guide

## Overview
Wolf Prowler now has three distinct versions with separate build systems:
- **Prototype** - Minimal educational implementation
- **Basic** - Enhanced with real networking  
- **Full** - Production-ready with advanced crypto

## Build Commands

### Prototype Version ✅
```bash
# Build
cd prototype
cargo build

# Run
cargo run -- --port 8080

# Features:
- Simulated networking
- Basic crypto integration
- Educational focused
- Easy to understand
```

### Basic Version 🔄
```bash
# Build (currently has compilation issues)
cd basic
cargo build

# Run
cargo run -- --port 8081

# Features:
- Real TCP connections
- Enhanced message protocol
- Better peer management
- Development focused
```

### Full Version 🔄
```bash
# Build (currently has compilation issues)
cd full
cargo build

# Run
cargo run -- --port 8082

# Features:
- Production crypto (ring crate)
- AES-GCM encryption
- Certificate management
- Enterprise focused
```

## Quick Start

### 1. Build Prototype (Working)
```bash
cd "c:\Users\Student\Rust Project 1\wolf_prowler\wolf-prowler\prototype"
cargo build
```

### 2. Run Multiple Nodes
```bash
# Terminal 1
cd prototype
cargo run -- --port 8080

# Terminal 2  
cd prototype
cargo run -- --port 8081

# Terminal 3
cd prototype
cargo run -- --port 8082
```

## Version Comparison

| Feature | Prototype | Basic | Full |
|---------|-----------|-------|------|
| **Build Status** | ✅ Working | 🔄 In Progress | 🔄 In Progress |
| **Networking** | Simulated | Real TCP | Advanced TCP |
| **Crypto** | Basic Hash | Ed25519 | Ring + AES-GCM |
| **Authentication** | None | Basic | Full PKI |
| **Certificates** | None | Basic | Full X.509-like |
| **Key Management** | Simple | Enhanced | Production |
| **Use Case** | Learning | Development | Production |

## Dependencies by Version

### Prototype Dependencies
```toml
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
futures = "0.3"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "0.8", features = ["v4"] }
rand = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
wolf_den_prototype = { path = "../wolf_den/prototype" }
```

### Basic Dependencies (Additional)
```toml
anyhow = "1.0"
thiserror = "1.0"
wolf_den_basic = { path = "../wolf_den/basic" }
```

### Full Dependencies (Additional)
```toml
sha2 = "0.10"
hex = "0.4"
ring = "0.16"
base64 = "0.13"
wolf_den_full = { path = "../wolf_den/full" }
```

## Project Structure

```
wolf-prowler/
├── prototype/          # ✅ Working
│   ├── Cargo.toml
│   └── src/main.rs
├── basic/              # 🔄 In Progress
│   ├── Cargo.toml
│   └── src/main.rs
├── full/               # 🔄 In Progress
│   ├── Cargo.toml
│   └── src/main.rs
└── wolf_den/
    ├── prototype/      # ✅ Working
    ├── basic/          # 🔄 In Progress
    └── full/           # 🔄 In Progress
```

## Next Steps

1. **✅ Prototype**: Ready to use for learning and testing
2. **🔄 Basic**: Fix compilation issues, then ready for development
3. **🔄 Full**: Fix compilation issues, then ready for production

## Running Multiple Prototypes

The prototype version supports multiple nodes that can discover each other:

```bash
# Node 1
cargo run -- --port 8080

# Node 2 (will discover Node 1)
cargo run -- --port 8081

# Node 3 (will discover both)
cargo run -- --port 8082
```

Each node will:
- Discover peers on nearby ports
- Exchange public keys
- Send signed messages
- Display connection status
- Show message history

## Troubleshooting

### Prototype Issues
- **Port conflicts**: Use different ports for each node
- **Discovery not working**: Check that ports are sequential (8080, 8081, 8082)

### Basic/Full Issues
- **Compilation errors**: Currently being fixed
- **Missing dependencies**: Run `cargo build` to download dependencies
- **Crypto library issues**: Ensure ring crate is properly installed

## Development Workflow

1. Start with **Prototype** to understand the concepts
2. Move to **Basic** for real networking features
3. Use **Full** for production-grade implementations

Each version builds upon the previous one, providing a clear learning path from simple to complex.
