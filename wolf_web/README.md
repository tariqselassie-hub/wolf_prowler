# Wolf Web Dashboard

**Status**: ✅ Production Ready | **Version**: 2.0 Enterprise

The Wolf Web Dashboard is a high-performance, Dioxus-based frontend for the Wolf Prowler ecosystem. It provides a real-time "Command Center" interface for security administrators, featuring granular controls, live metrics, and deep system insights.

## 🌟 Key Features

### 🖥️ Command Center Interface
- **Admin-Centric Design**: Optimized for situational awareness and rapid response.
- **Top Bar HUD**: Always-on visibility of critical system stats (Network Status, Database Health, Uptime).
- **Metric Sparklines**: Real-time trend visualization for Threat Levels and Node Activity.

### 🛠️ Advanced Operations
- **Deep Scan Control**: Granular control over system scanners with progress visualization.
- **Quick Actions**: One-click execution of routine maintenance tasks (Flush Cache, Rotate Keys, Export Logs).
- **Live Terminal**: A real-time system output stream for monitoring low-level events.

### 🎨 UI Kit (`src/ui_kit.rs`)
A custom, lightweight component library built for speed and consistency:
- **`Card`**: Standardized container with "Glassmorphism" styling.
- **`Button`**: Interactive elements with hover states and disabled logic.
- **`Badge`**: Status indicators with semantic coloring (Green/Red/Blue/Yellow).
- **`Sparkline`**: SVG-based lightweight charting component.

## 🏗️ Architecture

- **Framework**: Dioxus 0.6 (Fullstack).
- **Styling**: Tailwind CSS (via CDN) with a custom "Cyber-Security" theme.
- **State Management**: Robust `use_resource` and `use_signal` implementation with proper error handling and fallback states.
- **Data Flow**: Direct server functions for seamless backend communication.

## 🚀 Getting Started

To run the dashboard in development mode:

```bash
cargo run -p wolf_web --features server
```

Navigate to `http://127.0.0.1:8080` to access the interface.

## 📦 Components

- **`dashboard_components.rs`**: High-level widgets like `NetworkBanner` and `SecurityBanner`.
- **`vault_components.rs`**: Cryptographic tools interface.
- **`ui_kit.rs`**: Core design system primitives.
- **`types.rs`**: Shared data structures (`SystemStats`, `RecordView`).

## 🧪 Testing

Run the dashboard integration tests:

```bash
# Run standard unit tests
cargo test -p wolf_web

# Run comprehensive system integration tests
cargo test --test dashboard_comprehensive_test
```