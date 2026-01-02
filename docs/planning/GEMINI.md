# Wolf Prowler - Project Status & Direction

**Focus:** Stabilization & Functionality over Features.

## 🎯 Strategic Direction
The current phase of development prioritizes **making existing code operational** over adding new capabilities. We are moving from "Development Mode" to "Production Readiness".

### Key Objectives
1.  **Wolf Net**: Complete the P2P networking layer. Ensure messages can be sent, received, and routed securely.
2.  **Wolfsec**: Connect the security monitoring logic to real network events.
3.  **Integration**: Ensure the Dashboard accurately reflects the state of the backend systems via the API.

##  Project Structure & Documentation
Documentation has been consolidated into the `docs/` directory to keep the root clean. Each module maintains its own operational status in a local `README.md` and `TODO.md`.

- **`/docs`**: Comprehensive system documentation (Architecture, API, Security, Deployment).
- **`wolf_net/`**: Networking Core.
    - `README.md`: Module specific usage.
    - `TODO.md`: Module specific implementation gaps.
- **`wolfsec/`**: Security Core.
    - `README.md`: Module specific usage.
    - `TODO.md`: Module specific implementation gaps.
- **`wolf_den/`**: Cryptographic Core.
    - `README.md`: Module specific usage.
    - `TODO.md`: Module specific implementation gaps.

## 🚦 Feature Freeze
New features (e.g., AI models, Blockchain integration) are **paused** until the following core loops are closed:
- [ ] Node-to-Node Encrypted Messaging.
- [ ] Peer Discovery & Status Tracking.
- [ ] Security Alerting Pipeline (Detection -> Notification).
