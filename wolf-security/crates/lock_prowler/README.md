# Lock Prowler: Advanced BitLocker Recovery Suite

Lock Prowler is a high-performance toolkit designed for deep analysis and recovery of BitLocker-encrypted volumes. It combines low-level forensic metadata parsing with advanced cryptographic recovery algorithms.

## Project Architecture

The project is split into three primary components:

1. **`lock_prowler` (Core Library & CLI)**: The engine of the project. It handles FVE (Full Volume Encryption) metadata parsing, key protector identification, and implements recovery algorithms such as Nonce Reuse and Weak RSA parameter analysis.
2. **`lock_prowler_dashboard` (Neural Dashboard)**: A modern, web-based interface built for real-time visualization of recovery processes, featuring a high-end "neural" aesthetic.
3. **`dashboard` (Legacy Assets)**: Contains the original web assets that inspired the transition to a unified Rust-based fullstack environment.

---

## 🚀 The Dioxus 0.6 Neural Dashboard

The centerpiece of the Lock Prowler user experience is the **Neural Recovery Dashboard**.

### Acknowledgement: Dioxus 0.6 Fullstack
We would like to extend a massive acknowledgement to the **Dioxus** team and the **Dioxus 0.6** release. This project leverages the cutting-edge features of Dioxus 0.6 Fullstack to bridge the gap between low-level Rust systems and high-end web visualizations.

**Why Dioxus 0.6?**
- **Unified Fullstack Logic**: Dioxus 0.6 allows us to share complex cryptographic data structures directly between the BitLocker recovery core and the web frontend without any serialization overhead or manual API glue.
- **Server Functions**: We utilize Dioxus `#[server]` functions to perform live forensic scans on the host machine and stream results directly to the UI.
- **Enhanced JS Interop**: The new `document::eval` and signal-based reactivity in 0.6 enable our "Neural Net Visualizer"—a high-performance HTML5 Canvas animation that responds dynamically to recovery progress.
- **Modern Developer Experience**: The 0.6 release brings a refined component model and significantly improved platform detection, making it the ideal choice for "cyber-forensic" applications that require both speed and aesthetics.

---

## Getting Started

### Prerequisites
- Rust (Stable)
- Cargo

### Launching the Dashboard (Dioxus 0.6)
```bash
cd lock_prowler_dashboard
cargo run
```
The dashboard will be available at `http://127.0.0.1:7620`.

### Using the CLI
```bash
cd lock_prowler
cargo run -- <path_to_disk_image>
```

## Security and Forensic Integrity
Lock Prowler is designed with a "read-only" philosophy. It parses metadata without modifying the underlying volume, ensuring that forensic integrity is maintained throughout the recovery process.

## License
Distributed under the MIT License. See `LICENSE` for more information.
