# Wolf Prowler Professional CLI Documentation

## Overview

The Wolf Prowler CLI is a professional-grade command-line interface inspired by modern developer tools like Docker, kubectl, and git. It provides comprehensive control over the Wolf Prowler mesh network platform with intuitive commands, rich help system, and beautiful output.

## Installation

```bash
# Build from source
cargo build --release --bin wolf_prowler_cli

# Add to PATH (optional)
export PATH=$PATH:/path/to/wolf-prowler/target/release
```

## Quick Start

```bash
# Show help
wolf-prowler --help

# 🚀 Method 1: Main Binary with Dashboard (Recommended)
cargo run --bin main
# Dashboard automatically available at: http://127.0.0.1:8080

# 🔧 Method 2: CLI Dashboard Commands
wolf-prowler dashboard start
# Access dashboard at: http://127.0.0.1:8080

# Start Wolf Prowler with default settings
wolf-prowler start

# Start with custom configuration
wolf-prowler start --config production.toml

# Generate cryptographic keys
wolf-prowler generate-keys --key-type ed25519

# Show system status
wolf-prowler status --detailed

# Run security audit
wolf-prowler audit --audit-type comprehensive

# Check dashboard status
wolf-prowler dashboard status
```

## Command Structure

The CLI follows a hierarchical command structure:

```
wolf-prowler [GLOBAL_OPTIONS] <COMMAND> [SUBCOMMAND] [OPTIONS]
```

### Global Options

- `--config <FILE>` - Configuration file path (default: wolf_prowler.toml)
- `--log-level <LEVEL>` - Set logging level (trace, debug, info, warn, error)
- `--verbose` - Enable verbose output
- `--quiet` - Enable quiet mode (minimal output)
- `--work-dir <DIR>` - Working directory
- `--help` - Show help
- `--version` - Show version

## Core Commands

### `start` - Start Wolf Prowler

Start the Wolf Prowler mesh network node.

```bash
# Basic start
wolf-prowler start

# With custom ports
wolf-prowler start --web-port 8080 --p2p-port 9000

# With random ports
wolf-prowler start --random-ports

# With custom node name
wolf-prowler start --node-name "my-wolf-node"

# Daemon mode
wolf-prowler start --daemon --pid-file /var/run/wolf-prowler.pid

# Enable/disable features
wolf-prowler start --enable metrics,health --disable debug
```

**Options:**
- `--web-port <PORT>` - Web server port
- `--p2p-port <PORT>` - P2P listening port
- `--random-ports` - Use random ports for all services
- `--node-name <NAME>` - Node name
- `--daemon` - Run in daemon mode
- `--pid-file <FILE>` - PID file path
- `--enable <FEATURES>` - Enable specific features
- `--disable <FEATURES>` - Disable specific features

### `generate-keys` - Generate Cryptographic Keys

Generate cryptographic keys and certificates for secure communication.

```bash
# Generate Ed25519 keys
wolf-prowler generate-keys --key-type ed25519

# Generate RSA keys
wolf-prowler generate-keys --key-type rsa2048 --strength 2048

# Custom output directory
wolf-prowler generate-keys --output-dir ./keys --name "my-node"

# Generate with CSR
wolf-prowler generate-keys --with-csr --validity-days 365

# Force overwrite existing keys
wolf-prowler generate-keys --force
```

**Options:**
- `--key-type <TYPE>` - Key type (ed25519, rsa2048, rsa4096, secp256k1, x25519)
- `--output-dir <DIR>` - Output directory
- `--name <NAME>` - Key name prefix
- `--force` - Force overwrite existing keys
- `--with-csr` - Generate certificate signing request
- `--validity-days <DAYS>` - Certificate validity period
- `--strength <BITS>` - Key strength in bits

### `status` - Show System Status

Display comprehensive system status and health information.

```bash
# Basic status
wolf-prowler status

# Detailed status
wolf-prowler status --detailed

# JSON output
wolf-prowler status --json

# Watch mode (continuous updates)
wolf-prowler status --watch --interval 5

# Filter by component
wolf-prowler status --component p2p

# Export to file
wolf-prowler status --export status.json
```

**Options:**
- `--detailed` - Show detailed status
- `--json` - Show status in JSON format
- `--watch` - Watch mode (continuous updates)
- `--interval <SECONDS>` - Refresh interval for watch mode
- `--component <COMPONENT>` - Filter status by component
- `--export <FILE>` - Export status to file

### `dashboard` - Security Dashboard Management

Manage the Wolf Prowler security dashboard with real-time monitoring capabilities.

```bash
# Start the security dashboard
wolf-prowler dashboard start

# Start with custom host and port
wolf-prowler dashboard start --host 0.0.0.0 --port 9090

# Start with auto-refresh disabled
wolf-prowler dashboard start --auto-refresh false

# Show dashboard status
wolf-prowler dashboard status

# Show detailed dashboard metrics
wolf-prowler dashboard status --detailed

# Get dashboard URL
wolf-prowler dashboard url

# Copy dashboard URL to clipboard
wolf-prowler dashboard url --copy
```

**Subcommands:**
- `start` - Start the security dashboard web server
- `status` - Show dashboard status and metrics
- `url` - Display dashboard access URL

**Start Options:**
- `--host <HOST>` - Host address to bind to (default: 127.0.0.1)
- `--port <PORT>` - Port to listen on (default: 8080)
- `--auto-refresh <BOOL>` - Enable auto-refresh (default: true)

**Status Options:**
- `--detailed` - Show detailed metrics and statistics

**URL Options:**
- `--copy` - Copy URL to clipboard

**Dashboard Features:**
- **Real-time Metrics**: Security score, threat level, system status
- **Security Alerts**: Live alert feed with severity levels
- **Audit Trail**: Complete security operation history
- **Performance Monitoring**: CPU, memory, network metrics
- **Auto-refresh**: Automatic updates every 10 seconds
- **Modern UI**: Glassmorphism design with responsive layout

**Access URLs:**
- Default: http://127.0.0.1:8080
- Custom: http://[HOST]:[PORT]

### `audit` - Run Security Audit

Perform comprehensive security audit and vulnerability scanning.

```bash
# Comprehensive audit
wolf-prowler audit

# Quick security check
wolf-prowler audit --audit-type quick

# Network security audit
wolf-prowler audit --audit-type network

# JSON output with remediation
wolf-prowler audit --output json --remediation

# Custom severity threshold
wolf-prowler audit --severity high

# Skip network checks
wolf-prowler audit --skip-network

# Scan specific ports
wolf-prowler audit --ports 8080,9000,22
```

**Options:**
- `--audit-type <TYPE>` - Audit type (quick, security, network, crypto, comprehensive)
- `--output <FORMAT>` - Output format (human, json, xml, csv, sarif)
- `--output-file <FILE>` - Output file for audit report
- `--remediation` - Include remediation suggestions
- `--severity <LEVEL>` - Severity threshold (low, medium, high, critical)
- `--skip-network` - Skip network connectivity checks
- `--ports <PORTS>` - Scan specific ports
- `--config <FILE>` - Custom audit configuration file

## Configuration Management

### `config show` - Show Current Configuration

Display current configuration settings.

```bash
# Show configuration
wolf-prowler config show

# JSON format
wolf-prowler config show --json

# Show configuration source
wolf-prowler config show --source

# Show specific section
wolf-prowler config show --section p2p

# Mask sensitive values
wolf-prowler config show --mask
```

### `config validate` - Validate Configuration

Validate configuration file syntax and semantics.

```bash
# Validate default config
wolf-prowler config validate

# Validate specific file
wolf-prowler config validate --file custom.toml

# Detailed validation results
wolf-prowler config validate --detailed

# Auto-fix configuration issues
wolf-prowler config validate --fix
```

### `config create` - Create New Configuration

Create new configuration file from templates.

```bash
# Create from development template
wolf-prowler config create --template development --output my-config.toml

# Interactive configuration
wolf-prowler config create --interactive --template production

# Force overwrite existing file
wolf-prowler config create --template high-security --output config.toml --force
```

### `config list-templates` - List Available Templates

Display all available configuration templates.

```bash
# List templates
wolf-prowler config list-templates

# Show template details
wolf-prowler config list-templates --detailed
```

### `config reset` - Reset Configuration

Reset configuration to defaults.

```bash
# Reset entire configuration
wolf-prowler config reset --backup --confirm

# Reset specific section
wolf-prowler config reset --section p2p --backup
```

## Network Management

### `network status` - Network Status

Show network topology and peer information.

```bash
# Network status
wolf-prowler network status

# Detailed peer information
wolf-prowler network status --detailed

# Show network topology
wolf-prowler network status --topology

# Export network information
wolf-prowler network status --export network.json
```

### `network connect` - Connect to Peer

Establish connection to a peer.

```bash
# Connect to peer
wolf-prowler network connect "/ip4/192.168.1.100/tcp/9000/p2p/12D3KooW..."

# With timeout
wolf-prowler network connect --timeout 60 "/ip4/..."

# Persistent connection
wolf-prowler network connect --persistent "/ip4/..."
```

### `network disconnect` - Disconnect from Peer

Terminate connection to a peer.

```bash
# Disconnect from peer
wolf-prowler network disconnect "12D3KooW..."

# Force disconnect
wolf-prowler network disconnect --force "peer-address"
```

### `network list` - List Connected Peers

Display all connected peers.

```bash
# List peers
wolf-prowler network list

# Detailed peer information
wolf-prowler network list --detailed

# Filter by status
wolf-prowler network list --status online
```

### `network discover` - Discover Peers

Find and discover new peers.

```bash
# Discover peers using mDNS
wolf-prowler network discover --method mdns

# Bootstrap discovery
wolf-prowler network discover --method bootstrap --timeout 120

# Limit discovery results
wolf-prowler network discover --max-peers 25
```

## Metrics and Monitoring

### `metrics show` - Show Current Metrics

Display system metrics and performance data.

```bash
# Show all metrics
wolf-prowler metrics show

# Filter by category
wolf-prowler metrics show --category crypto

# JSON output
wolf-prowler metrics show --json

# Real-time metrics
wolf-prowler metrics show --real-time

# Export metrics
wolf-prowler metrics show --export metrics.json
```

### `metrics start` - Start Metrics Server

Start Prometheus-compatible metrics server.

```bash
# Start metrics server
wolf-prowler metrics start

# Custom port
wolf-prowler metrics start --port 9090

# Enable Prometheus endpoint
wolf-prowler metrics start --prometheus

# Enable health endpoint
wolf-prowler metrics start --health
```

### `metrics reset` - Reset Metrics

Clear all collected metrics.

```bash
# Reset all metrics
wolf-prowler metrics reset --confirm

# Reset specific category
wolf-prowler metrics reset --category network
```

## State Management

### `state show` - Show Current State

Display application state information.

```bash
# Show state
wolf-prowler state show

# JSON format
wolf-prowler state show --json

# Show specific section
wolf-prowler state show --section p2p

# Export state
wolf-prowler state show --export state.json
```

### `state save` - Save State

Save current application state to file.

```bash
# Save state
wolf-prowler state save

# Custom output file
wolf-prowler state save --output backup.json

# Backup before saving
wolf-prowler state save --backup

# Compress state file
wolf-prowler state save --compress
```

### `state load` - Load State

Load application state from file.

```bash
# Load state
wolf-prowler state load --file backup.json

# Validate before loading
wolf-prowler state load --file state.json --validate

# Backup current state
wolf-prowler state load --file state.json --backup

# Force load without validation
wolf-prowler state load --file state.json --force
```

### `state clear` - Clear State

Reset application state.

```bash
# Clear all state
wolf-prowler state clear --backup --confirm

# Clear specific section
wolf-prowler state clear --section metrics
```

## Development Tools

### `dev server` - Development Server

Start development server with hot reload and debug features.

```bash
# Start development server
wolf-prowler dev server

# Enable hot reload
wolf-prowler dev server --hot-reload

# Watch configuration file
wolf-prowler dev server --watch-config

# Enable debug endpoints
wolf-prowler dev server --debug
```

### `dev test` - Run Tests

Execute test suites.

```bash
# Run all tests
wolf-prowler dev test

# Run specific test suite
wolf-prowler dev test --suite integration

# Run integration tests
wolf-prowler dev test --integration

# Run performance tests
wolf-prowler dev test --performance

# Generate test report
wolf-prowler dev test --report --output test-report.html
```

### `dev benchmark` - Run Benchmarks

Execute performance benchmarks.

```bash
# Run all benchmarks
wolf-prowler dev benchmark

# Run specific benchmark suite
wolf-prowler dev benchmark --suite crypto

# Custom iterations
wolf-prowler dev benchmark --iterations 1000

# Generate benchmark report
wolf-prowler dev benchmark --report --output benchmark.html
```

### `dev docs` - Generate Documentation

Generate project documentation.

```bash
# Generate HTML documentation
wolf-prowler dev docs --format html

# Custom output directory
wolf-prowler dev docs --output ./docs

# Include private documentation
wolf-prowler dev docs --private

# Open in browser
wolf-prowler dev docs --open
```

## Information Commands

### `version` - Show Version Information

Display version and build information.

```bash
# Basic version
wolf-prowler version

# Detailed version information
wolf-prowler version --detailed

# Build information
wolf-prowler version --build

# Dependency information
wolf-prowler version --deps
```

### `help` - Show Help and Documentation

Display comprehensive help information.

```bash
# Show main help
wolf-prowler help

# Help for specific command
wolf-prowler help --command start

# Show all commands
wolf-prowler help --all

# Show examples
wolf-prowler help --examples
```

## Examples and Workflows

### Basic Development Workflow

```bash
# 1. Create development configuration
wolf-prowler config create --template development --output dev.toml

# 2. Generate keys for development
wolf-prowler generate-keys --key-type ed25519 --output-dir ./dev-keys

# 3. Start development server
wolf-prowler dev server --hot-reload --debug

# 4. Monitor status
wolf-prowler status --watch --interval 5
```

### Production Deployment Workflow

```bash
# 1. Create production configuration
wolf-prowler config create --template production --output prod.toml

# 2. Validate configuration
wolf-prowler config validate --file prod.toml --detailed

# 3. Generate production keys
wolf-prowler generate-keys --key-type rsa4096 --strength 4096 --output-dir ./prod-keys

# 4. Run security audit
wolf-prowler audit --audit-type comprehensive --severity high

# 5. Start production node
wolf-prowler start --config prod.toml --daemon
```

### Monitoring and Maintenance Workflow

```bash
# 1. Check system status
wolf-prowler status --detailed

# 2. Review metrics
wolf-prowler metrics show --category all --json

# 3. Run security audit
wolf-prowler audit --output json --remediation --output-file audit-report.json

# 4. Backup state
wolf-prowler state save --backup --compress

# 5. Export configuration
wolf-prowler config show --json --export config-backup.json
```

## Environment Variables

The CLI respects all Wolf Prowler environment variables:

```bash
# Override configuration
WOLF_NODE_NAME="production-node" WOLF_WEB_PORT="8080" wolf-prowler start

# Set log level
WOLF_LOG_LEVEL="debug" wolf-prowler status --detailed

# Custom configuration file
WOLF_CONFIG_FILE="/etc/wolf-prowler/production.toml" wolf-prowler start
```

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Invalid arguments or usage
- `3` - Configuration error
- `4` - Network error
- `5` - Cryptographic error
- `6` - File system error

## Troubleshooting

### Common Issues

1. **Configuration not found**
   ```bash
   wolf-prowler config create --template development
   ```

2. **Permission denied**
   ```bash
   sudo wolf-prowler start --daemon
   ```

3. **Port already in use**
   ```bash
   wolf-prowler start --random-ports
   ```

4. **Keys not found**
   ```bash
   wolf-prowler generate-keys --key-type ed25519
   ```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
wolf-prowler --verbose --log-level debug start
```

### Getting Help

```bash
# General help
wolf-prowler --help

# Command-specific help
wolf-prowler start --help
wolf-prowler config --help
wolf-prowler network connect --help

# Show all commands
wolf-prowler help --all

# Show examples
wolf-prowler help --examples
```

## Integration with Other Tools

### Shell Completion

The CLI supports shell completion for bash, zsh, and fish:

```bash
# Generate completion script
wolf-prowler --generate-completion bash > wolf-prowler-completion.bash

# Install completion
source wolf-prowler-completion.bash
```

### JSON Output Integration

All commands support JSON output for automation:

```bash
# Get status as JSON
wolf-prowler status --json | jq '.node.status'

# Parse configuration with jq
wolf-prowler config show --json | jq '.p2p.max_peers'

# Use in scripts
STATUS=$(wolf-prowler status --json | jq -r '.node.status')
if [ "$STATUS" = "online" ]; then
    echo "Wolf Prowler is running"
fi
```

### Docker Integration

```dockerfile
FROM wolf-prowler:latest

# Generate keys in container
RUN wolf-prowler generate-keys --key-type ed25519 --output-dir /app/keys

# Start with configuration
CMD ["wolf-prowler", "start", "--config", "/app/config.toml"]
```

## Advanced Usage

### Custom Configuration

Create custom configuration files for specific use cases:

```bash
# High-security node
wolf-prowler config create --template high-security --output secure.toml
wolf-prowler generate-keys --key-type rsa4096 --strength 4096
wolf-prowler start --config secure.toml

# Testing node
wolf-prowler config create --template testing --output test.toml
wolf-prowler start --config test.toml --random-ports
```

### Automation Scripts

Create automation scripts using the CLI:

```bash
#!/bin/bash
# deploy-wolf-prowler.sh

set -e

echo "🚀 Deploying Wolf Prowler..."

# Create configuration
wolf-prowler config create --template production --output /etc/wolf-prowler/config.toml

# Generate keys
wolf-prowler generate-keys --key-type ed25519 --output-dir /etc/wolf-prowler/keys

# Validate configuration
wolf-prowler config validate --file /etc/wolf-prowler/config.toml

# Run security audit
wolf-prowler audit --audit-type security --severity medium

# Start service
wolf-prowler start --config /etc/wolf-prowler/config.toml --daemon

echo "✅ Wolf Prowler deployed successfully!"
```

## Contributing to the CLI

The CLI is built with Rust and clap. To contribute:

1. Add new commands to the `Commands` enum in `cli.rs`
2. Implement command handlers in the `Cli` impl
3. Update help text and documentation
4. Add tests for new functionality
5. Update this documentation

For more information, see the [CONTRIBUTING.md](CONTRIBUTING.md) file.
