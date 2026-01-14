# Wolf Web: Security Command Center

> **Status**: Production Ready (Version 0.1.0)
> **Stack**: Dioxus 0.6 (Fullstack) + Axum + TailwindCSS
> **Role**: Command & Control Interface for Wolf Prowler

Wolf Web is the unified dashboard for the Wolf Prowler ecosystem. Built on Dioxus Fullstack, it renders a high-performance "Single Page Application" (SPA) that communicates directly with the Rust backend via Server Functions.

## 🏗️ Architecture

The dashboard implements a **Server-Driven UI** pattern. The frontend is hydrated with state directly from the `WolfNode`, `WolfSec`, and `WolfDb` instances running in the shared server process.

```mermaid
graph TD
    User([Admin]) <-->|Interact| UI[Dioxus Frontend (WASM)]
    UI <-->|RPC| API[Server Functions]
    
    subgraph "Wolf Web Server (Axum)"
        API -->|Read/Write| AppState[Global State]
        AppState <-->|Manage| WSec[WolfSec Engine]
        AppState <-->|Control| WNet[WolfNet Swarm]
        AppState <-->|Query| DB[WolfDb Storage]
        AppState <-->|Command| Agent[Headless Agent]
    end
```

### Core Components

1.  **Command Center (`dashboard.rs`)**:
    *   Real-time HUD displaying Network Status, Threat Level, and DB health.
    *   Uses `use_resource` to poll backend stats via `get_fullstack_stats`.
2.  **Vault Interface (`vault_components.rs`)**:
    *   Management UI for the `WolfDb` Key-Value store.
    *   Supports manual injection and inspection of encrypted records.
3.  **Terminal Stream**:
    *   Live websocket-like stream of system logs and Prowler output.

## 💻 Usage

### Development Server

Run the fullstack application in development mode:

```bash
# Starts the Dioxus/Axum server
cargo run -p wolf_web --features server
```

Access the dashboard at `http://127.0.0.1:8080`.

### Backend Wiring (`src/main.rs`)

Wolf Web initializes the entire ecosystem within its runtime:

```rust
#[tokio::main]
async fn main() {
    // 1. Initialize Storage (WolfDb)
    let store = WolfStore::new(&db_path).await?;
    
    // 2. Initialize Swarm (WolfNet)
    let swarm = SwarmManager::new(config).await?;
    
    // 3. Initialize Security (WolfSec)
    let security = WolfSecurity::create(sec_config).await?;
    
    // 4. Launch Dioxus Server with Shared State
    launch_app(AppState {
        swarm: Arc::new(swarm),
        security: Arc::new(security),
        store: Arc::new(store),
    });
}
```

## 📦 Dependencies

*   `dioxus` / `dioxus-fullstack`: UI Framework.
*   `axum`: Backend server.
*   `wolfsec`: Security logic.
*   `wolf_net`: Network status.
*   `lock_prowler`: Integration with the headless agent.