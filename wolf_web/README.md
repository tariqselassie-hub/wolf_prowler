# wolf_web

**Dioxus-based Web Dashboard for Wolf Prowler Security Platform**

## Overview

`wolf_web` provides a modern, reactive web dashboard for monitoring and controlling Wolf Prowler security infrastructure. Built with Dioxus 0.6, it offers real-time security monitoring, network visualization, and administrative controls through an intuitive full-stack Rust web application.

## Features

- **🎨 Modern Dioxus UI**: Full-stack Rust with server-side rendering and hydration
- **🔐 SSO Authentication**: OpenID Connect integration with secure session management
- **📊 Real-time Dashboards**: Live security events, network status, and threat intelligence
- **🌐 Multi-Section Navigation**: Dedicated views for Security, Network, System, Intelligence, Compliance, Administration, Settings, Vault, and Database management
- **🔄 WebSocket Streaming**: Real-time updates for security events and network topology
- **🧠 Lock Prowler Integration**: Digital forensics and incident response capabilities
- **🗄️ WolfDb Explorer**: Browse and query the post-quantum cryptographic database

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    wolf_web (Dioxus)                     │
├─────────────────────────────────────────────────────────┤
│  Dashboard Router                                        │
│  ├─ Overview         - System status and metrics        │
│  ├─ Security         - Threat detection and alerts      │
│  ├─ Network          - P2P mesh and peer management     │
│  ├─ System           - Resource monitoring              │
│  ├─ Intelligence     - Threat feeds and ML insights     │
│  ├─ Compliance       - Audit logs and reports           │
│  ├─ Administration   - User and role management         │
│  ├─ Settings         - Configuration management         │
│  ├─ Vault            - Secret management (Wolf Den)     │
│  └─ Database         - WolfDb query interface           │
└─────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
      wolfsec              wolf_net              wolf_db
   (Security Core)     (P2P Networking)    (PQC Database)
```

## Usage

### Running the Dashboard

```bash
# Development mode with hot-reload
cargo run -p wolf_web

# Production build
cargo build --release -p wolf_web
./target/release/wolf_web
```

### Access

Navigate to `https://localhost:3031` (HTTPS is enforced for security).

**Default Credentials:**
- Username: `admin`
- Password: Set via `WOLF_ADMIN_PASSWORD` environment variable

### SSO Configuration

```bash
# .env configuration
SSO_ENABLED=true
SSO_ISSUER=https://your-idp.com
SSO_CLIENT_ID=your-client-id
SSO_CLIENT_SECRET=your-client-secret
SSO_REDIRECT_URI=https://localhost:3031/auth/callback
```

## Dependencies

- **Dioxus 0.6**: Full-stack framework with router and server features
- **wolfsec**: Security monitoring and threat detection
- **wolf_net**: P2P networking and peer management
- **wolf_den**: Cryptographic operations
- **lock_prowler**: Digital forensics toolkit
- **wolf_db**: Post-quantum cryptographic database

## Development

```bash
# Run with file watching
dx serve --hot-reload

# Check for errors
cargo check -p wolf_web

# Run tests
cargo test -p wolf_web
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

See [LICENSE-APACHE](../../LICENSE-APACHE) and [LICENSE-MIT](../../LICENSE-MIT) for details.
