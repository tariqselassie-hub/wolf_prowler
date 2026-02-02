# Wolf Control - TUI Management Interface

**Status**: ✅ Production Ready | **Version**: 1.0

Wolf Control provides a terminal-based user interface for managing and monitoring the Wolf Prowler security platform.

## 🖥️ Features

- **Real-Time Monitoring**
  - Network peer status and traffic metrics
  - Security threat levels and active alerts
  - ML prediction results and anomaly detection
  - System resource usage

- **Interactive Controls**
  - Peer management (connect, disconnect, ping)
  - Security playbook execution
  - Log filtering and search
  - Configuration management

- **User Interface**
  - Vim-style keyboard navigation
  - Multiple dashboard views
  - Live data updates
  - Responsive terminal UI

## 🚀 Quick Start

```bash
# Run the TUI
cargo run --bin wolf_control

# Or after building
./target/release/wolf_control
```

## ⌨️ Keyboard Shortcuts

- `q` - Quit
- `Tab` - Switch between panels
- `↑/↓` - Navigate lists
- `Enter` - Select/Execute
- `/` - Search/Filter
- `r` - Refresh data

## 📦 Installation

```toml
[dependencies]
wolf_control = { path = "../wolf_control" }
```

## 🎨 Technologies

- **Ratatui**: Terminal UI framework
- **Crossterm**: Cross-platform terminal manipulation
- **Tokio**: Async runtime for real-time updates

## 📄 License

MIT License - See [LICENSE](../LICENSE) for details.
