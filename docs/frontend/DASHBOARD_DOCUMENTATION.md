# Wolf Web Dashboard Documentation

## Overview
The Wolf Web Dashboard is the central command center for the Wolf Prowler ecosystem. It has been redesigned (v2.0) to focus on administrator efficiency, real-time data visibility, and operational control.

## Key Features

### 1. Command Center Layout
The dashboard abandons traditional navigation-heavy layouts for a single-screen "Command Center" approach.
- **HUD**: Top bar displaying critical system-wide status (Net, DB, Uptime).
- **Metric Grid**: Sparkline-enhanced cards for immediate trend analysis of threats and network activity.
- **Operations Panel**: Split view containing deep scan controls and a real-time terminal log.

### 2. UI Kit
The interface is built using a custom `UI Kit` (see [`UI_KIT.md`](UI_KIT.md)) to ensure consistency.
- **Performance**: Components are lightweight Dioxus functions.
- **Aesthetic**: "Cyber-Admin" theme with high contrast and data-density.

### 3. State Management
- **Shared Types**: Data structures like `SystemStats` are shared between the backend and frontend via `wolf_web::types`.
- **Resilience**: The dashboard handles backend failures gracefully, displaying "OFFLINE" states instead of crashing.

## Development

### Setup
Ensure `wolf_server` is running or launch the dashboard in standalone mode:
```bash
cargo run -p wolf_web --features server
```

### Adding Pages
New pages should be added to `wolf_web/src/pages/` and registered in the `Route` enum in `main.rs`. Use `UI Kit` components for layout.