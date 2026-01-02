# Wolf Server - HTTP/WebSocket Server

**Status**: ✅ Production Ready | **Version**: 1.0

Wolf Server provides high-performance HTTP and WebSocket services for the Wolf Prowler dashboard and API.

## 🌐 Features

- **HTTPS Support**
  - TLS 1.3 encryption
  - Self-signed or custom certificates
  - Automatic certificate management

- **WebSocket**
  - Real-time bidirectional communication
  - Automatic reconnection
  - Message compression

- **Authentication**
  - JWT-based session management
  - Role-based access control
  - Secure cookie handling

- **Performance**
  - Async/await with Axum framework
  - Connection pooling
  - Request rate limiting
  - Response compression

## 🚀 Quick Start

```rust
use wolf_server::{ServerConfig, start_server};

#[tokio::main]
async fn main() -> Result<()> {
    let config = ServerConfig {
        port: 3031,
        enable_tls: true,
        ..Default::default()
    };
    
    start_server(config).await?;
    Ok(())
}
```

## 📦 Installation

```toml
[dependencies]
wolf_server = { path = "../wolf_server" }
```

## 🔧 Configuration

```rust
let config = ServerConfig {
    port: 3031,
    enable_tls: true,
    cert_path: "./certs/cert.pem",
    key_path: "./certs/key.pem",
    max_connections: 1000,
};
```

## 🛡️ Security

- TLS 1.3 encryption for all connections
- JWT token authentication
- CORS protection
- Rate limiting per endpoint
- Security headers (HSTS, CSP, etc.)

## 📄 License

MIT License - See [LICENSE](../LICENSE) for details.
