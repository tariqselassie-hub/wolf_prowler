# Contributing to Wolfsec

Thank you for your interest in contributing to Wolfsec! This document provides guidelines and best practices for contributing to the project.

## 🎯 Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow the Wolf Pack philosophy: work together, protect the pack

## 🏗️ Architecture Guidelines

### Follow Hexagonal Architecture

- **Domain Layer**: Pure business logic, no infrastructure dependencies
- **Infrastructure Layer**: Implementations of domain interfaces
- **Application Layer**: Use cases and orchestration

### Domain-Driven Design

- Use ubiquitous language from the security domain
- Define clear aggregates and boundaries
- Emit domain events for state changes
- Keep entities focused and cohesive

## 📝 Coding Standards

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting: `cargo fmt`
- Use `clippy` for linting: `cargo clippy -- -D warnings`
- Prefer explicit over implicit

### Naming Conventions

- **Modules**: `snake_case` (e.g., `threat_detection`)
- **Types**: `PascalCase` (e.g., `ThreatDetector`)
- **Functions**: `snake_case` (e.g., `detect_threat`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_RETRIES`)

### Error Handling

```rust
// Use thiserror for library errors
#[derive(Error, Debug)]
pub enum MyModuleError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Operation failed: {0}")]
    OperationFailed(#[from] std::io::Error),
}

// Use anyhow for application errors
use anyhow::{Context, Result};

fn my_function() -> Result<()> {
    do_something()
        .context("Failed to do something")?;
    Ok(())
}
```

### Async/Await

- Use `async fn` for I/O operations
- Avoid blocking operations in async code
- Use `tokio::spawn` for concurrent tasks
- Handle cancellation gracefully

## 🧪 Testing Requirements

### Unit Tests

- Test pure functions in the same file
- Use `#[cfg(test)]` module
- Aim for >80% coverage

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_function() {
        let result = my_function();
        assert!(result.is_ok());
    }
}
```

### Integration Tests

- Place in `tests/` directory
- Test module interactions
- Use realistic scenarios

### Benchmarks

- Add benchmarks for performance-critical code
- Use Criterion for benchmarking
- Track performance over time

## 📚 Documentation Requirements

### Module Documentation

```rust
//! Module Name
//!
//! Brief description of the module's purpose.
//!
//! # Features
//!
//! - Feature 1
//! - Feature 2
//!
//! # Example
//!
//! ```rust
//! use wolfsec::module::Type;
//!
//! let instance = Type::new();
//! ```
```

### Function Documentation

```rust
/// Brief description of what the function does.
///
/// # Arguments
///
/// * `param1` - Description of param1
/// * `param2` - Description of param2
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// Description of error conditions
///
/// # Example
///
/// ```rust
/// let result = my_function(arg1, arg2)?;
/// ```
pub fn my_function(param1: Type1, param2: Type2) -> Result<ReturnType> {
    // Implementation
}
```

### Safety Documentation

```rust
/// # Safety
///
/// This function is safe because:
/// - The pointer is guaranteed to be valid
/// - The lifetime ensures no use-after-free
/// - The operation is atomic
unsafe fn my_unsafe_function() {
    // Implementation
}
```

## 🔄 Pull Request Process

### Before Submitting

1. **Run tests**: `cargo test --all`
2. **Run clippy**: `cargo clippy --all -- -D warnings`
3. **Format code**: `cargo fmt --all`
4. **Update docs**: Ensure documentation is current
5. **Add examples**: If adding new features

### PR Description

Include:
- **What**: Brief description of changes
- **Why**: Motivation for the changes
- **How**: Implementation approach
- **Testing**: How you tested the changes

### Review Process

- Address all review comments
- Keep PRs focused and small
- Squash commits before merging
- Update CHANGELOG.md

## 🐺 Wolf Pack Philosophy

### Security First

- Validate all inputs
- Use constant-time operations for crypto
- Document security assumptions
- Follow principle of least privilege

### Performance Matters

- Profile before optimizing
- Use benchmarks to track performance
- Avoid premature optimization
- Document performance characteristics

### Maintainability

- Write self-documenting code
- Add comments for complex logic
- Keep functions small and focused
- Refactor when needed

## 🎓 Learning Resources

### Rust

- [The Rust Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Async Book](https://rust-lang.github.io/async-book/)

### Architecture

- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
- [Domain-Driven Design](https://www.domainlanguage.com/ddd/)
- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)

### Security

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)

## 📞 Getting Help

- Open an issue for bugs
- Start a discussion for questions
- Join our community chat
- Read the documentation

## 🙏 Thank You!

Your contributions make Wolfsec better for everyone. Thank you for being part of the Wolf Pack! 🐺
