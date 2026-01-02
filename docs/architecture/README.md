# Wolf Prowler Architecture

Wolf Prowler follows a modular architecture with three core components designed to work in unison.

## High-Level Design

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Wolf Den      │    │    Wolfsec      │    │    Wolf Net     │
│  (Crypto)       │    │ (Security)      │    │  (Networking)   │
│                 │    │                 │    │                 │
│ • Hashing       │    │ • Threat Detect │    │ • P2P Network   │
│ • KDF           │    │ • Event Logging │    │ • Discovery     │
│ • MAC           │    │ • Peer Mgmt     │    │ • Routing       │
│ • Random        │    │ • Auth/Authz    │    │ • Monitoring    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Dashboard     │
                    │  (Web Interface)│
                    │                 │
                    │ • Monitoring    │
                    │ • Control       │
                    │ • APIs          │
                    │ • WebSocket     │
                    └─────────────────┘
```

## Components
1. **Wolf Den**: The cryptographic engine providing primitives for security.
2. **Wolfsec**: The security monitor handling threat detection and authorization.
3. **Wolf Net**: The networking layer managing P2P connections and message routing.