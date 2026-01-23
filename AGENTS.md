# Wolf Prowler - Agent Development Guidelines

## Build, Lint, and Test Commands

### Primary Build Commands
```bash
# Build release binary (optimized)
cargo build --release

# Build with all features enabled
cargo build --release --all-features

# Build specific workspace member
cargo build -p wolfsec --release
cargo build -p wolf_net --release
cargo build -p wolf_web --release
```

### Linting and Formatting
```bash
# Run clippy linter across workspace
cargo clippy --workspace

# Run clippy with warnings as errors
cargo clippy --workspace -- -D warnings

# Format code with rustfmt
cargo fmt

# Check formatting without changes
cargo fmt --check
```

### Testing Commands

#### Run All Tests
```bash
# Quick sanity check - all unit tests
cargo test

# Full system verification with all features
cargo test --workspace --all-features

# Run tests with verbose output
cargo test -- --nocapture
```

#### Run Specific Test Suites

**Dashboard Tests:**
```bash
# Basic dashboard functionality
cargo test --test dashboard_simple_test

# Comprehensive dashboard integration
cargo test --test dashboard_comprehensive_test
```

**Security Core Tests:**
```bash
# WolfSec comprehensive tests
cargo test -p wolfsec

# WolfSec with specific test features
cargo test -p wolfsec --features security_tests
```

**Networking Tests:**
```bash
# WolfNet discovery integration
cargo test -p wolf_net --test discovery_integration

# WolfNet library tests
cargo test -p wolf_net --lib
```

**Database Tests:**
```bash
# WolfDb vector tests
cargo test vector::tests -p wolf_db

# WolfDb large scale tests
cargo test --test large_scale_vector -- --nocapture
```

**Tercespot (Blind Command-Bus) Tests:**
```bash
# All Tercespot tests
cargo test --workspace

# Specific Tercespot components
cargo test -p ceremony
cargo test -p shared
cargo test -p sentinel
cargo test -p client
```

#### Run Single Tests
```bash
# Run specific test function
cargo test test_name

# Run test in specific package
cargo test -p wolfsec test_specific_function

# Run ignored tests
cargo test -- --ignored

# Run with single thread (for debugging)
cargo test -- --test-threads=1
```

#### Performance and Stress Testing
```bash
# System stress tests
cargo test --test system_stress_test -- --nocapture

# Benchmarks (requires criterion)
cargo bench -p wolf_den
cargo bench -p wolfsec
```

### Makefile Commands
```bash
# Build release
make build

# Run all tests
make test

# Run main application
make run

# Clean build artifacts
make clean

# System backup
make backup

# System restore (requires FILE=path)
make restore FILE=/path/to/backup.tar.gz

# Update dependencies
make patch

# Run health checks
make monitor
```

## Code Style Guidelines

### Import Conventions
- Group imports by standard library, external crates, then internal crates
- Use explicit imports instead of globs (`use std::collections::HashMap` not `use std::collections::*`)
- Group related imports together with blank lines between groups
- For long import lists, use multi-line format with each import on separate line

```rust
// Good - organized imports
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};

use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;

// Internal crates
use wolfsec::identity::User;
use wolf_net::node::NodeId;
```

### Formatting Standards
- Use `rustfmt` for all code formatting
- Maximum line length: 100 characters (default rustfmt)
- Use 4 spaces for indentation (default rustfmt)
- Function signatures should have parameters on separate lines if too long

### Type Annotations and Naming

**Variable Naming:**
- Use `snake_case` for variables and functions
- Use `PascalCase` for types, structs, enums, traits
- Use `SCREAMING_SNAKE_CASE` for constants
- Prefix private fields with underscore if unused: `_unused_field`

**Type Conventions:**
- Use explicit types for public APIs
- Prefer concrete types over generics when clarity is improved
- Use `Result<T, E>` with specific error types, not `anyhow::Result`
- Use `Arc<T>` for shared ownership in async contexts

### Error Handling
- Use `thiserror` for custom error types
- Prefer specific error types over generic `anyhow::Error`
- Use `?` operator for error propagation in fallible functions
- Log errors at appropriate levels (debug, info, warn, error)
- Avoid `unwrap()` and `expect()` in production code - use proper error handling

```rust
// Good - specific error handling
#[derive(thiserror::Error, Debug)]
pub enum WolfError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub fn connect_node() -> Result<NodeId, WolfError> {
    // Implementation with proper error handling
}
```

### Async Programming
- Use `tokio` as the async runtime
- Prefer `async fn` for async functions
- Use `Arc<T>` for shared state in async contexts
- Use `tokio::sync` primitives (Mutex, RwLock, etc.) instead of std
- Avoid blocking operations in async functions

### Security Best Practices
- Zeroize sensitive data after use
- Use constant-time operations for cryptographic comparisons
- Validate all inputs, especially from network sources
- Implement proper access controls and authentication
- Log security events appropriately
- Use post-quantum cryptography where applicable

### Documentation
- Use `///` for public API documentation
- Include examples in doc comments where helpful
- Document error conditions and panics
- Use `#![deny(missing_docs)]` for critical security modules
- Document thread-safety guarantees

### Testing Patterns
- Use descriptive test names: `test_function_name_behavior`
- Group related tests in modules
- Use `#[tokio::test]` for async tests
- Mock external dependencies appropriately
- Test error conditions, not just happy paths
- Use property-based testing where applicable

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_connection_success() {
        // Test implementation
    }

    #[tokio::test]
    async fn test_node_connection_failure() {
        // Test error handling
    }
}
```

### Code Organization
- Group related functionality in modules
- Keep functions focused on single responsibilities
- Use trait-based design for extensible components
- Prefer composition over inheritance
- Separate concerns: business logic, networking, storage, UI

### Performance Considerations
- Avoid unnecessary allocations in hot paths
- Use `Arc` for shared ownership instead of cloning large structures
- Profile before optimizing
- Use appropriate data structures for access patterns
- Consider memory layout and cache efficiency

### Workspace Structure
- Main application in root `src/`
- Shared crates in `crates/` directory
- Tests in `tests/` directory
- Integration tests use feature flags appropriately
- Documentation in `docs/` directory

## Pre-commit Hooks

The project includes pre-commit hooks for code quality:

```bash
# Install pre-commit hook
./scripts/install_pre_commit_hook.sh

# Run pre-commit checks manually
./scripts/pre-commit-hook.sh
```

Pre-commit checks include:
- Code formatting with rustfmt
- Linting with clippy
- Running tests
- Security scanning with gitLeaks

## Development Workflow

1. **Code Changes**: Make changes following style guidelines
2. **Testing**: Run relevant tests (`cargo test -p <package>`)
3. **Linting**: Run `cargo clippy --workspace`
4. **Formatting**: Run `cargo fmt`
5. **Commit**: Use conventional commit messages
6. **Pre-commit**: Hook runs automatically on commit

## Security Considerations for Agents

- **Never** commit secrets or sensitive data
- **Always** validate inputs from external sources
- **Use** proper error handling to avoid information leakage
- **Follow** principle of least privilege
- **Audit** code changes for security implications
- **Test** security features thoroughly

## Export Control Notice

This codebase contains cryptographic technology subject to US export control regulations. All contributors must be US persons and understand export control requirements as outlined in `EXPORT_CONTROL.md`.

---

*Built with Rust for Security, Performance, and Reliability* 🐺</content>
<parameter name="filePath">AGENTS.md