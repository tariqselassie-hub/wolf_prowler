# Wolf Prowler Dashboard Expansion Documentation

## Overview

This document covers all features, APIs, and enhancements added during the dashboard expansion phase of the Wolf Prowler project. The expansion focused on creating a comprehensive security monitoring and crypto testing web interface.

## Table of Contents

1. [New Features](#new-features)
2. [API Endpoints](#api-endpoints)
3. [Frontend Components](#frontend-components)
4. [Security Enhancements](#security-enhancements)
5. [Crypto Testing Tools](#crypto-testing-tools)
6. [Installation & Setup](#installation--setup)
7. [Usage Examples](#usage-examples)
8. [Troubleshooting](#troubleshooting)

---

## New Features

### 🎯 Dashboard Web Interface
- **Real-time Security Monitoring**: Live updates via WebSocket connections
- **Interactive Charts**: Network activity and security events visualization
- **Peer Management**: View, trust, and block connected peers
- **System Health Monitoring**: CPU, memory, disk usage tracking
- **Responsive Design**: Mobile-friendly interface using Tailwind CSS

### 🔐 Security Features
- **WolfSec Authentication**: Token-based authentication system
- **Secure WebSocket Connections**: End-to-end encrypted real-time communication
- **Certificate Management**: X.509 certificate generation and validation
- **Access Control**: Role-based permissions and resource protection

### 🛠️ Crypto Testing Tools
- **Certificate Generator**: Create test certificates for any domain
- **Hash Generator**: SHA-256/SHA-512 hash generation
- **Keypair Generator**: ED25519 cryptographic keypair creation
- **Signature Verifier**: Digital signature validation tool

---

## API Endpoints

### Core Dashboard APIs

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `GET` | `/` | Main dashboard HTML page | HTML |
| `GET` | `/api/health` | System health status | JSON |
| `GET` | `/api/security/metrics` | Security metrics and stats | JSON |
| `GET` | `/api/network/stats` | Network activity statistics | JSON |
| `GET` | `/api/peers` | List of connected peers | JSON |
| `GET` | `/api/peers/:id` | Detailed peer information | JSON |
| `POST` | `/api/peers/:id/trust` | Trust a peer | JSON |
| `POST` | `/api/peers/:id/block` | Block a peer | JSON |

### Authentication APIs

| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| `POST` | `/api/auth` | Generate authentication token | `{"user_id": "string"}` | `{"token": "string", "expires_in": number}` |
| `GET` | `/ws/secure` | Secure WebSocket connection | WebSocket upgrade | Real-time updates |

### Crypto Testing APIs

| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| `POST` | `/api/crypto/generate-cert` | Generate test certificate | `{"domain": "string", "user_id": "string"}` | Certificate PEM data |
| `POST` | `/api/crypto/generate-hash` | Generate cryptographic hash | `{"data": "string", "algorithm": "sha256|sha512"}` | Hash result |
| `POST` | `/api/crypto/generate-keypair` | Generate ED25519 keypair | None | Public key |
| `POST` | `/api/crypto/verify-signature` | Verify digital signature | `{"data": "string", "signature": "base64"}` | Validity result |
| `GET` | `/api/crypto/list-certs` | List generated certificates | None | Certificate list |

### System Testing APIs

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `POST` | `/api/system/test` | Run P2P system tests | JSON status |

---

## Frontend Components

### 📊 Dashboard Layout

#### Header Component
```html
<header class="bg-gray-900 text-white p-4">
  <div class="container mx-auto flex justify-between items-center">
    <div class="flex items-center space-x-3">
      <!-- Wolf Prowler Logo -->
      <h1 class="text-2xl font-bold">Wolf Prowler Security Dashboard</h1>
    </div>
    <div class="flex items-center space-x-4">
      <!-- Connection Status Indicator -->
      <button id="refresh-btn" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">
        Refresh
      </button>
    </div>
  </div>
</header>
```

#### Metrics Cards
- **Active Peers**: Number of connected P2P peers
- **Security Events**: Count of security-related events
- **Message Rate**: Messages per second
- **Trust Score**: Average peer reputation

#### Charts Section
- **Network Activity Chart**: Real-time message flow visualization
- **Security Events Chart**: Categorized security event tracking

#### Peers Table
```javascript
// Peer management functionality
updatePeersTable(peers) {
  const tbody = document.getElementById('peers-table');
  tbody.innerHTML = peers.map(peer => `
    <tr class="border-b">
      <td class="py-2">${peer.peer_id}</td>
      <td class="py-2">${peer.address || 'N/A'}</td>
      <td class="py-2">
        <span class="px-2 py-1 rounded text-xs ${
          peer.trust_level === 'trusted' ? 'bg-green-100 text-green-800' :
          peer.trust_level === 'unknown' ? 'bg-yellow-100 text-yellow-800' :
          'bg-red-100 text-red-800'
        }">
          ${peer.trust_level}
        </span>
      </td>
      <td class="py-2">${peer.reputation_score?.toFixed(2) || '0.00'}</td>
      <td class="py-2">${peer.connected_since ? new Date(peer.connected_since).toLocaleString() : 'N/A'}</td>
      <td class="py-2">
        <button class="text-blue-600 hover:text-blue-800 mr-2">Trust</button>
        <button class="text-red-600 hover:text-red-800">Block</button>
      </td>
    </tr>
  `).join('');
}
```

### 🔐 Crypto Testing Tools

#### Certificate Generator
```javascript
async function generateCertificate() {
  const domain = document.getElementById('cert-domain').value || 'localhost';
  const user_id = document.getElementById('cert-user').value || 'test_user';
  
  const response = await fetch('/api/crypto/generate-cert', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, user_id })
  });
  
  const result = await response.json();
  // Display certificate PEM data and fingerprint
}
```

#### Hash Generator
```javascript
async function generateHash() {
  const data = document.getElementById('hash-data').value || 'test data';
  const algorithm = document.getElementById('hash-algorithm').value;
  
  const response = await fetch('/api/crypto/generate-hash', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data, algorithm })
  });
  
  const result = await response.json();
  // Display hash result
}
```

#### Keypair Generator
```javascript
async function generateKeypair() {
  const response = await fetch('/api/crypto/generate-keypair', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  });
  
  const result = await response.json();
  // Display public key
}
```

#### Signature Verifier
```javascript
async function verifySignature() {
  const data = document.getElementById('sig-data').value;
  const signature = document.getElementById('sig-signature').value;
  
  const response = await fetch('/api/crypto/verify-signature', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data, signature })
  });
  
  const result = await response.json();
  // Display verification result
}
```

---

## Security Enhancements

### 🔒 WolfSec Authentication System

#### Token Generation
```rust
pub async fn auth_handler(
    State(state): State<DashboardState>,
    Json(request): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let mut auth = (*state.auth).clone();
    let mut crypto_guard = state.crypto.lock().await;
    if let Some(ref crypto) = *crypto_guard {
        match auth.generate_token(crypto, &request.user_id, std::time::Duration::from_secs(3600)) {
            Ok(token) => Ok(Json(AuthResponse {
                token,
                expires_in: 3600,
                peer_id: request.user_id,
            })),
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    } else {
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
```

#### Middleware Integration
```rust
pub async fn auth_middleware(
    State(state): State<AuthState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Token validation logic
    // Request authentication and authorization
}
```

### 🛡️ Secure WebSocket Connections

#### WebSocket Handler
```rust
async fn secure_websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<DashboardState>,
) -> Response {
    ws.on_upgrade(|socket| async move {
        if let Err(e) = handle_secure_websocket(socket, state).await {
            tracing::error!("WebSocket error: {}", e);
        }
    })
}
```

#### End-to-End Encryption
- Messages encrypted using WolfDenCrypto engine
- ED25519 digital signatures for message integrity
- Automatic key rotation and management

### 🔐 Certificate Management

#### X.509 Certificate Generation
```rust
pub fn generate_server_certificate(&self, domain: &str) -> Result<TlsConfig> {
    let subject_alt_names = vec![domain.to_string(), "localhost".to_string()];
    let server_cert = generate_simple_self_signed(subject_alt_names)?;
    
    let server_key_pem = server_cert.serialize_private_key_pem();
    let server_key = KeyPair::from_pem(&server_key_pem)?;
    
    // Convert to PEM format and create TLS configuration
}
```

#### Certificate Validation
- SHA-256 fingerprint calculation
- Certificate chain verification
- Revocation status checking

---

## Crypto Testing Tools

### 📋 Tool Overview

#### 1. Certificate Generator
- **Purpose**: Generate X.509 test certificates
- **Features**:
  - Custom domain support
  - PEM format output
  - Fingerprint calculation
  - Private key generation
- **Usage**: Enter domain and user ID, click "Generate Certificate"

#### 2. Hash Generator
- **Purpose**: Generate cryptographic hashes
- **Algorithms**: SHA-256, SHA-512
- **Features**:
  - Real-time hash calculation
  - Copy-friendly output
  - Multiple algorithm support
- **Usage**: Enter data, select algorithm, click "Generate Hash"

#### 3. Keypair Generator
- **Purpose**: Generate ED25519 keypairs
- **Features**:
  - Cryptographically secure key generation
  - Public key display
  - WolfDenCrypto integration
- **Usage**: Click "Generate New Keypair"

#### 4. Signature Verifier
- **Purpose**: Verify digital signatures
- **Features**:
  - Base64 signature input
  - Real-time verification
  - Visual feedback for validity
- **Usage**: Enter data and signature, click "Verify Signature"

### 🔧 Technical Implementation

#### Backend Handlers
```rust
// Certificate Generation
async fn generate_test_cert_handler(
    State(state): State<DashboardState>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode>

// Hash Generation
async fn generate_test_hash_handler(
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode>

// Keypair Generation
async fn generate_test_keypair_handler(
    State(state): State<DashboardState>,
) -> Result<Json<serde_json::Value>, StatusCode>

// Signature Verification
async fn verify_signature_handler(
    State(state): State<DashboardState>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode>
```

#### Frontend Integration
```javascript
// Unified error handling
try {
    const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    
    const result = await response.json();
    
    if (result.status === 'success') {
        // Display success result
    } else {
        // Display error message
    }
} catch (error) {
    // Handle network errors
}
```

---

## Installation & Setup

### 📦 Prerequisites
- Rust 1.70+ with tokio runtime
- Node.js 16+ (for frontend development)
- Modern web browser with WebSocket support

### 🚀 Installation Steps

1. **Clone Repository**
```bash
git clone <repository-url>
cd wolf_prowler/wolf-prowler
```

2. **Build Project**
```bash
cargo build --release
```

3. **Run Dashboard**
```bash
cargo run --bin wolf_prowler
```

4. **Access Dashboard**
```
Open http://localhost:8080 in your browser
```

### ⚙️ Configuration

#### Dashboard Configuration
```rust
pub struct DashboardConfig {
    pub bind_address: SocketAddr,           // Server bind address
    pub enable_cors: bool,                  // CORS support
    pub auth_required: bool,                // Authentication requirement
    pub static_files: bool,                 // Static file serving
    pub tls_enabled: bool,                  // TLS encryption
}
```

#### Security Configuration
```rust
pub struct WolfSecConfig {
    pub ca_cert_path: Option<String>,        // CA certificate path
    pub server_cert_path: Option<String>,   // Server certificate path
    pub server_key_path: Option<String>,    // Server private key path
    pub auto_generate_certs: bool,          // Auto-generate certificates
}
```

---

## Usage Examples

### 🎯 Basic Dashboard Usage

#### 1. Accessing the Dashboard
```bash
# Start the server
cargo run --bin wolf_prowler

# Open in browser
http://localhost:8080
```

#### 2. Monitoring System Health
- Navigate to the dashboard
- View system metrics in the overview cards
- Monitor real-time charts for network activity
- Check peer connections in the peers table

#### 3. Managing Peers
- View connected peers in the peers table
- Click "Trust" to mark a peer as trusted
- Click "Block" to block a malicious peer
- Use search to find specific peers

### 🔐 Crypto Testing Examples

#### 1. Generating a Test Certificate
```javascript
// Using the dashboard UI
1. Navigate to "Crypto Testing Tools" section
2. Enter domain: "example.com"
3. Enter user ID: "test_user"
4. Click "Generate Certificate"
5. View certificate PEM and fingerprint
```

```bash
# Using the API directly
curl -X POST http://localhost:8080/api/crypto/generate-cert \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "user_id": "test_user"}'
```

#### 2. Generating a Hash
```javascript
// Using the dashboard UI
1. Enter data: "Hello, World!"
2. Select algorithm: "SHA-256"
3. Click "Generate Hash"
4. Copy the resulting hash
```

```bash
# Using the API directly
curl -X POST http://localhost:8080/api/crypto/generate-hash \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello, World!", "algorithm": "sha256"}'
```

#### 3. Generating a Keypair
```javascript
// Using the dashboard UI
1. Click "Generate New Keypair"
2. Copy the public key for use in applications
```

```bash
# Using the API directly
curl -X POST http://localhost:8080/api/crypto/generate-keypair \
  -H "Content-Type: application/json"
```

#### 4. Verifying a Signature
```javascript
// Using the dashboard UI
1. Enter original data
2. Enter Base64 signature
3. Click "Verify Signature"
4. View validity result
```

```bash
# Using the API directly
curl -X POST http://localhost:8080/api/crypto/verify-signature \
  -H "Content-Type: application/json" \
  -d '{"data": "Hello, World!", "signature": "base64_signature_here"}'
```

### 📊 API Integration Examples

#### JavaScript/TypeScript
```typescript
class WolfProwlerClient {
    private baseUrl: string;
    
    constructor(baseUrl: string = 'http://localhost:8080') {
        this.baseUrl = baseUrl;
    }
    
    async generateCertificate(domain: string, userId: string) {
        const response = await fetch(`${this.baseUrl}/api/crypto/generate-cert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, user_id: userId })
        });
        return response.json();
    }
    
    async getSystemHealth() {
        const response = await fetch(`${this.baseUrl}/api/health`);
        return response.json();
    }
    
    async getNetworkStats() {
        const response = await fetch(`${this.baseUrl}/api/network/stats`);
        return response.json();
    }
}

// Usage
const client = new WolfProwlerClient();
const cert = await client.generateCertificate('example.com', 'user1');
const health = await client.getSystemHealth();
```

#### Python
```python
import requests
import json

class WolfProwlerClient:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
    
    def generate_certificate(self, domain, user_id):
        response = requests.post(
            f"{self.base_url}/api/crypto/generate-cert",
            json={"domain": domain, "user_id": user_id}
        )
        return response.json()
    
    def generate_hash(self, data, algorithm="sha256"):
        response = requests.post(
            f"{self.base_url}/api/crypto/generate-hash",
            json={"data": data, "algorithm": algorithm}
        )
        return response.json()
    
    def get_system_health(self):
        response = requests.get(f"{self.base_url}/api/health")
        return response.json()

# Usage
client = WolfProwlerClient()
cert = client.generate_certificate("example.com", "user1")
hash_result = client.generate_hash("Hello, World!")
health = client.get_system_health()
```

---

## Troubleshooting

### 🔧 Common Issues

#### 1. Dashboard Not Loading
**Problem**: Browser shows connection error
**Solution**:
- Check if the server is running: `cargo run --bin wolf_prowler`
- Verify port 8080 is not in use
- Check firewall settings

#### 2. WebSocket Connection Failed
**Problem**: Real-time updates not working
**Solution**:
- Ensure WebSocket support is enabled in browser
- Check network proxy settings
- Verify CORS configuration

#### 3. Certificate Generation Fails
**Problem**: Certificate generation returns error
**Solution**:
- Check rcgen crate installation
- Verify cryptographic dependencies
- Check system time and date

#### 4. Hash Generation Issues
**Problem**: Hash generation returns incorrect results
**Solution**:
- Verify input data encoding
- Check algorithm selection
- Ensure proper UTF-8 encoding

#### 5. Signature Verification Fails
**Problem**: Signature verification always returns false
**Solution**:
- Check Base64 encoding of signature
- Verify original data matches signed data
- Ensure proper keypair usage

### 🐛 Debug Mode

#### Enable Debug Logging
```bash
# Set RUST_LOG environment variable
RUST_LOG=debug cargo run --bin wolf_prowler
```

#### Browser Console Debugging
```javascript
// Enable debug mode in dashboard
localStorage.setItem('debug', 'true');

// Monitor WebSocket events
console.log('WebSocket state:', this.ws.readyState);
```

#### API Debugging
```bash
# Test API endpoints directly
curl -v http://localhost:8080/api/health

# Check response headers and status
curl -I http://localhost:8080/api/network/stats
```

### 📊 Performance Monitoring

#### System Metrics
- Monitor CPU and memory usage
- Check network bandwidth
- Track WebSocket connection count

#### Dashboard Performance
- Use browser developer tools
- Monitor JavaScript execution time
- Check chart rendering performance

---

## Architecture Overview

### 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │    │   Axum Server   │    │  Wolf Prowler   │
│                 │    │                 │    │     Core        │
│  - Dashboard    │◄──►│  - HTTP APIs    │◄──►│                 │
│  - Charts       │    │  - WebSocket    │    │  - P2P Network  │
│  - Crypto Tools │    │  - Middleware   │    │  - Crypto Engine│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  WolfSec Module │
                    │                 │
                    │  - Certificates │
                    │  - Authentication│
                    │  - TLS Config   │
                    └─────────────────┘
```

### 📦 Module Structure

```
src/
├── dashboard/
│   ├── mod.rs              # Main dashboard module
│   ├── static/
│   │   └── index.html       # Frontend HTML/JS/CSS
│   └── secure_websocket.rs  # WebSocket security
├── wolfsec_certificates.rs # Certificate management
├── wolf_den.rs            # Cryptographic engine
├── wolfsec_protocol.rs    # Security protocol
└── main.rs                # Application entry point
```

### 🔒 Security Architecture

```
┌─────────────────┐
│  Authentication │
│                 │
│  - Token-based  │
│  - WolfSec Auth │
│  - JWT tokens   │
└─────────────────┘
         │
┌─────────────────┐
│   Transport     │
│                 │
│  - HTTPS/TLS    │
│  - WebSocket    │
│  - CORS         │
└─────────────────┘
         │
┌─────────────────┐
│   Application   │
│                 │
│  - API routes   │
│  - Middleware   │
│  - Validation   │
└─────────────────┘
         │
┌─────────────────┐
│     Data        │
│                 │
│  - Encryption   │
│  - Signatures   │
│  - Hashing      │
└─────────────────┘
```

---

## Future Enhancements

### 🚀 Planned Features

#### Dashboard Enhancements
- **Real-time Alert System**: Security event notifications
- **Historical Data**: Persistent metrics storage
- **User Management**: Multi-user support with roles
- **Export Functionality**: Data export in CSV/JSON format
- **Dark Mode**: Theme switching support

#### Crypto Tools Expansion
- **More Algorithms**: Support for additional hash algorithms
- **Batch Operations**: Multiple certificate generation
- **Certificate Templates**: Pre-configured certificate types
- **Key Management**: Import/export keypairs
- **Crypto Benchmarks**: Performance testing tools

#### Security Features
- **Multi-factor Authentication**: 2FA support
- **Audit Logging**: Comprehensive audit trails
- **Rate Limiting**: API abuse prevention
- **IP Whitelisting**: Access control by IP
- **Session Management**: Active session monitoring

#### Integration Features
- **REST API Documentation**: OpenAPI/Swagger specs
- **Webhook Support**: Event notifications
- **Database Integration**: Persistent storage
- **Monitoring Metrics**: Prometheus integration
- **Docker Support**: Containerized deployment

### 📋 Development Roadmap

#### Phase 1: Core Features (Current)
- ✅ Basic dashboard interface
- ✅ Real-time monitoring
- ✅ Crypto testing tools
- ✅ Authentication system

#### Phase 2: Enhanced Security
- 🔄 Multi-factor authentication
- 🔄 Audit logging system
- 🔄 Advanced threat detection
- 🔄 Automated security scanning

#### Phase 3: Enterprise Features
- 📋 Multi-tenant support
- 📋 Advanced reporting
- 📋 Integration APIs
- 📋 Scalability improvements

---

## Contributing

### 🤝 Development Guidelines

#### Code Style
- Follow Rust standard formatting
- Use meaningful variable names
- Add comprehensive comments
- Include unit tests

#### Security Considerations
- Validate all user inputs
- Use secure coding practices
- Implement proper error handling
- Follow principle of least privilege

#### Testing
- Unit tests for all functions
- Integration tests for APIs
- Security testing for authentication
- Performance testing for crypto operations

### 📝 Submission Process

1. Fork the repository
2. Create feature branch
3. Implement changes with tests
4. Update documentation
5. Submit pull request
6. Code review and merge

---

## License & Credits

### 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

### 👥 Contributors
- Wolf Prowler Development Team
- Security Research Group
- Open Source Contributors

### 🙏 Acknowledgments
- Rust ecosystem contributors
- Axum web framework team
- Cryptography library developers
- Security community feedback

---

## Contact & Support

### 📧 Support Channels
- **Issues**: GitHub Issues Tracker
- **Discussions**: GitHub Discussions
- **Security**: security@wolfprowler.dev

### 📚 Additional Resources
- **API Documentation**: `/api/docs` (when running)
- **Examples**: `examples/` directory
- **Tutorials**: `docs/tutorials/` directory
- **FAQ**: `docs/faq.md`

---

*This documentation covers all features added during the dashboard expansion phase. For additional information about the core Wolf Prowler project, please refer to the main project documentation.*
