# Clean Architecture Refactoring Strategy

## 1. Core Principles
- **Dependency Rule:** Source code dependencies can only point inwards. Nothing in an inner circle can know anything at all about something in an outer circle.
- **Domain Centric:** The core of the application is the business logic, not the database or the web framework.

## 2. Module Structure (Target State)

### `wolfsec` (Security Core)
**Current:** Mixed concerns in `src/security/`
**Target:**
```text
wolfsec/
├── src/
│   ├── domain/                 # INNERMOST LAYER (No external deps)
│   │   ├── entities/           # e.g., Alert, Threat, Vulnerability
│   │   ├── repositories/       # Traits: AlertRepository, ThreatRepository
│   │   └── services/           # Domain Services: ThreatAnalyzer
│   ├── application/            # USE CASES
│   │   ├── commands/           # CreateAlert, ScanSystem
│   │   ├── queries/            # GetActiveThreats
│   │   └── dtos/               # Data Transfer Objects
│   └── infrastructure/         # OUTERMOST LAYER
│       ├── persistence/        # PostgresAlertRepository (SQLx)
│       ├── notifications/      # SmtpEmailSender, SlackNotifier
│       └── api/                # External API Clients (VirusTotal)
```

### `wolf_net` (Networking Core)
**Target:**
```text
wolf_net/
├── src/
│   ├── domain/
│   │   ├── peer/               # PeerId, PeerStatus, TrustScore
│   │   └── message/            # Message types, Encryption traits
│   ├── application/
│   │   └── swarm/              # SwarmManager logic (orchestration)
│   └── infrastructure/
│       ├── libp2p/             # Libp2p concrete implementation
│       └── storage/            # Peer persistence
```

## 3. Implementation Steps

### Step 1: Isolate the Domain
**Action:** Move core structs (e.g., `Peer`, `Alert`) to `domain/entities`.
**Rule:** Remove all `sqlx`, `serde` (mostly), and `actix` attributes.
- *Exception:* `serde` is often acceptable in domain for simple serialization, but ideally DTOs handle this.
- *Strict Rule:* No `sqlx::FromRow` on domain entities.

### Step 2: Define Interfaces (Ports)
**Action:** Create Traits in `domain/repositories` for data access.
**Example:**
```rust
// domain/repositories/peer_repository.rs
#[async_trait]
pub trait PeerRepository {
    async fn get_by_id(&self, id: &PeerId) -> Result<Option<Peer>, DomainError>;
    async fn save(&self, peer: &Peer) -> Result<(), DomainError>;
}
```

### Step 3: Implement Adapters
**Action:** Move existing SQLx logic to `infrastructure/persistence`.

### Step 4: Dependency Injection
**Action:** Update `main.rs` or `lib.rs` to wire up the concrete implementations to the application services.