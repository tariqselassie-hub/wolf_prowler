# Wolfsec Architecture

**Comprehensive security architecture for Wolf Prowler distributed systems.**

## 🏗️ Overview

Wolfsec follows a **Hexagonal Architecture** (Ports and Adapters) combined with **Domain-Driven Design** principles to create a maintainable, testable, and scalable security framework.

## 📐 Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                     Presentation Layer                       │
│                    (Wolf Web Dashboard)                      │
└─────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Use Cases  │  │   Services   │  │  Workflows   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Domain Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Entities   │  │    Events    │  │ Repositories │      │
│  │              │  │              │  │   (Ports)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Infrastructure Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Persistence  │  │   Adapters   │  │   Services   │      │
│  │ (DB, Cache)  │  │ (External)   │  │  (Crypto)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## 🎯 Core Modules

### 1. Identity Module (`identity/`)

**Purpose**: Authentication, authorization, and cryptographic operations.

**Components**:
- `auth/`: User authentication and session management
- `crypto/`: Cryptographic primitives and PQC support
- `key_management/`: Secure key generation, rotation, and storage
- `iam/`: Identity and Access Management with RBAC
- `zero_trust/`: Zero-trust security architecture

**Key Types**:
- `IdentityManager`: Main facade for identity operations
- `AuthManager`: Authentication and session handling
- `KeyManager`: Cryptographic key lifecycle management

### 2. Protection Module (`protection/`)

**Purpose**: Active threat detection and security enforcement.

**Components**:
- `network_security/`: Firewall, encryption, transport security
- `threat_detection/`: Real-time threat analysis
- `reputation/`: IP/peer reputation management
- `anomaly_detection/`: ML-based anomaly detection
- `container_security/`: Container and Kubernetes security
- `cloud_security/`: Multi-cloud security posture
- `devsecops/`: CI/CD security integration
- `risk_assessment/`: Continuous risk assessment
- `threat_intelligence/`: External threat feed integration
- `threat_hunting/`: Proactive threat hunting

**Key Types**:
- `ThreatDetector`: Main threat detection engine
- `NetworkSecurityManager`: Network security orchestrator
- `ReputationManager`: Reputation tracking and filtering

### 3. Observability Module (`observability/`)

**Purpose**: Security monitoring, alerting, and compliance.

**Components**:
- `alerts/`: Real-time security alerting
- `audit/`: Comprehensive audit logging
- `metrics/`: Security metrics collection
- `dashboard/`: Security visualization
- `reporting/`: Compliance and security reports
- `siem/`: SIEM integration
- `soar/`: Security orchestration and automation
- `compliance/`: Compliance framework support

**Key Types**:
- `SecurityMonitor`: Continuous monitoring
- `AlertManager`: Alert generation and routing
- `MetricsCollector`: Metrics aggregation
- `WolfSIEMManager`: SIEM integration facade

### 4. Domain Module (`domain/`)

**Purpose**: Core business logic and domain entities.

**Components**:
- `entities/`: Domain entities (User, Threat, Alert, etc.)
- `events/`: Domain events for event-driven architecture
- `repositories/`: Repository trait definitions (ports)
- `error/`: Domain-specific errors

**Design Pattern**: Domain-Driven Design (DDD)

### 5. Infrastructure Module (`infrastructure/`)

**Purpose**: External integrations and persistence.

**Components**:
- `persistence/`: Database implementations
- `adapters/`: External service adapters
- `services/`: Infrastructure services

**Design Pattern**: Hexagonal Architecture (Ports and Adapters)

## 🔄 Data Flow

### Threat Detection Flow

```
1. Network Event
   ↓
2. ThreatDetector (protection/)
   ↓
3. Anomaly Detection (ML analysis)
   ↓
4. Reputation Check
   ↓
5. Alert Generation (observability/)
   ↓
6. SIEM Integration
   ↓
7. Dashboard Update
```

### Authentication Flow

```
1. Login Request
   ↓
2. AuthManager (identity/)
   ↓
3. Credential Validation
   ↓
4. MFA Challenge (if enabled)
   ↓
5. Session Creation
   ↓
6. Audit Log Entry (observability/)
   ↓
7. Token Response
```

### Compliance Reporting Flow

```
1. Audit Events (continuous)
   ↓
2. AuditManager (observability/)
   ↓
3. Compliance Analysis
   ↓
4. Gap Detection
   ↓
5. Report Generation
   ↓
6. Dashboard/Export
```

## 🐺 Wolf Pack Integration

Wolfsec integrates with the Wolf Pack coordination system:

- **Alpha**: Leadership and coordination (main security orchestrator)
- **Beta**: Backup and failover (redundant security services)
- **Hunters**: Active threat detection and response
- **Scouts**: Reconnaissance and monitoring
- **Guardians**: Protection and defense

## 🔐 Security Principles

### 1. Defense in Depth
Multiple layers of security controls:
- Network layer (firewall, encryption)
- Application layer (authentication, authorization)
- Data layer (encryption at rest)

### 2. Zero Trust
Never trust, always verify:
- Continuous authentication
- Least privilege access
- Micro-segmentation

### 3. Secure by Default
- Strong defaults for all configurations
- Explicit opt-in for reduced security
- Fail-safe mechanisms

### 4. Privacy by Design
- Data minimization
- Encryption everywhere
- Audit trails for all access

## 📊 Key Design Patterns

### 1. Hexagonal Architecture
- **Ports**: Domain repository traits
- **Adapters**: Infrastructure implementations
- **Benefit**: Testability and flexibility

### 2. Event-Driven Architecture
- **Domain Events**: Business events (UserAuthenticated, ThreatDetected)
- **Event Bus**: Asynchronous event propagation
- **Benefit**: Loose coupling and scalability

### 3. Repository Pattern
- **Abstraction**: Domain defines interfaces
- **Implementation**: Infrastructure provides adapters
- **Benefit**: Database independence

### 4. Facade Pattern
- **Managers**: High-level APIs (IdentityManager, ThreatDetector)
- **Complexity**: Hidden behind simple interfaces
- **Benefit**: Ease of use

## 🔧 Configuration Management

### Configuration Hierarchy

```
1. Default Configuration (code)
   ↓
2. Environment Variables
   ↓
3. Configuration Files (TOML/YAML)
   ↓
4. Runtime Updates (API)
```

### Key Configuration Types

- `SecurityConfig`: Network security settings
- `IdentityConfig`: Authentication and IAM settings
- `ThreatDetectionConfig`: Threat detection parameters
- `SIEMConfig`: SIEM integration settings

## 🧪 Testing Strategy

### Unit Tests
- Domain logic testing
- Pure function testing
- Mock external dependencies

### Integration Tests
- Module integration testing
- Database integration
- External service integration

### End-to-End Tests
- Full workflow testing
- Security scenario testing
- Performance testing

## 📈 Performance Considerations

### Async/Await
- All I/O operations are async
- Non-blocking threat detection
- Concurrent alert processing

### Caching
- Reputation cache (in-memory)
- Metrics aggregation cache
- Session cache

### Resource Management
- Connection pooling (database)
- Thread pools (CPU-bound tasks)
- Memory limits (configurable)

## 🔗 External Dependencies

### Core Dependencies
- **tokio**: Async runtime
- **serde**: Serialization
- **anyhow**: Error handling
- **tracing**: Logging and instrumentation

### Security Dependencies
- **wolf_den**: Cryptographic primitives
- **wolf_net**: P2P networking
- **libcrux**: Post-quantum cryptography

### Storage Dependencies
- **sqlx**: Database access
- **redis**: Caching (optional)

## 🚀 Deployment Architecture

### Standalone Mode
```
┌─────────────────┐
│   Wolfsec       │
│   (All-in-one)  │
└─────────────────┘
```

### Distributed Mode
```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Identity    │◄──►│  Protection  │◄──►│Observability │
│  Service     │    │  Service     │    │  Service     │
└──────────────┘    └──────────────┘    └──────────────┘
        ▲                   ▲                    ▲
        └───────────────────┴────────────────────┘
                    Event Bus (NATS/Redis)
```

## 📚 Further Reading

- [Identity Module Documentation](src/identity/README.md)
- [Protection Module Documentation](src/protection/README.md)
- [Observability Module Documentation](src/observability/README.md)
- [API Documentation](https://docs.rs/wolfsec)

## 🤝 Contributing

When contributing to wolfsec:

1. Follow the existing architecture patterns
2. Add tests for new functionality
3. Update documentation
4. Ensure zero compilation warnings
5. Follow the Wolf Pack philosophy

---

**Last Updated**: 2026-01-12  
**Architecture Version**: 1.0  
**Status**: Production Ready ✅
