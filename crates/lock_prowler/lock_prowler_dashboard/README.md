# lock_prowler_dashboard (Dioxus 0.6)

The primary visual interface for the Lock Prowler BitLocker recovery suite. Built using **Dioxus 0.6 Fullstack**.

## Features
- **Real-time Recovery Monitoring**: Live progress tracking of BitLocker decryption tasks.
- **Neural Visualizer**: Interactive HTML5 Canvas visualization of key shards and heuristic analysis.
- **Dioxus 0.6 Fullstack**: High-performance Rust-to-Web integration with server functions.

## Setup
Ensure you have the latest stable Rust toolchain.

```bash
cargo run
```
The server will bind to `0.0.0.0:7620`.

## Configuration
The following environment variables are supported:
- `PORT`: Overrides the default port (7620).
- `RUST_LOG`: Controls the level of structured tracing (e.g., `RUST_LOG=info`).
