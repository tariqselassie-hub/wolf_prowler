# Performance Guide

## Overview

This guide provides best practices and techniques for optimizing performance in Wolfsec. Performance is critical for security systems that need to process high volumes of events in real-time.

## Performance Targets

### Throughput
- **Threat Detection**: >10,000 events/second
- **Metrics Collection**: >50,000 metrics/second
- **Authentication**: >1,000 requests/second
- **Encryption/Decryption**: >100 MB/second

### Latency
- **Threat Detection**: <10ms p99
- **Authentication**: <50ms p99
- **Metrics Collection**: <1ms p99
- **Alert Generation**: <5ms p99

### Resource Usage
- **Memory**: <500MB baseline
- **CPU**: <20% idle load
- **Network**: <10MB/s baseline

## Profiling

### CPU Profiling

Use `cargo-flamegraph` for CPU profiling:

```bash
# Install
cargo install flamegraph

# Profile a benchmark
cargo flamegraph --bench crypto_bench

# Profile tests
cargo flamegraph --test integration_tests
```

### Memory Profiling

Use `valgrind` with `massif` for memory profiling:

```bash
# Install valgrind
sudo apt-get install valgrind

# Profile memory usage
valgrind --tool=massif --massif-out-file=massif.out \
    cargo test --release

# Visualize
ms_print massif.out
```

### Async Profiling

Use `tokio-console` for async profiling:

```bash
# Add to Cargo.toml
[dependencies]
console-subscriber = "0.1"

# Enable in code
console_subscriber::init();

# Run tokio-console
tokio-console
```

## Optimization Techniques

### 1. Avoid Allocations

**Bad**:
```rust
fn process_data(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();  // Allocation
    for &byte in data {
        result.push(byte * 2);
    }
    result
}
```

**Good**:
```rust
fn process_data(data: &[u8], output: &mut [u8]) {
    for (i, &byte) in data.iter().enumerate() {
        output[i] = byte * 2;  // No allocation
    }
}
```

### 2. Use Buffering

**Bad**:
```rust
for event in events {
    process_event(event).await;  // Many small I/O operations
}
```

**Good**:
```rust
let mut buffer = Vec::with_capacity(100);
for event in events {
    buffer.push(event);
    if buffer.len() >= 100 {
        process_batch(&buffer).await;  // Batched I/O
        buffer.clear();
    }
}
```

### 3. Cache Expensive Operations

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

struct ThreatDetector {
    reputation_cache: Arc<RwLock<HashMap<IpAddr, Reputation>>>,
}

impl ThreatDetector {
    async fn check_reputation(&self, ip: IpAddr) -> Reputation {
        // Check cache first
        {
            let cache = self.reputation_cache.read().await;
            if let Some(rep) = cache.get(&ip) {
                return rep.clone();
            }
        }
        
        // Expensive lookup
        let rep = self.lookup_reputation(ip).await;
        
        // Update cache
        {
            let mut cache = self.reputation_cache.write().await;
            cache.insert(ip, rep.clone());
        }
        
        rep
    }
}
```

### 4. Use Connection Pooling

```rust
use sqlx::PgPool;

// Create pool once
let pool = PgPool::connect(&database_url).await?;

// Reuse connections
async fn query_data(pool: &PgPool) -> Result<Vec<Row>> {
    sqlx::query("SELECT * FROM threats")
        .fetch_all(pool)  // Reuses connection from pool
        .await
}
```

### 5. Optimize Async/Await

**Bad**:
```rust
async fn process_all(items: Vec<Item>) {
    for item in items {
        process_item(item).await;  // Sequential
    }
}
```

**Good**:
```rust
async fn process_all(items: Vec<Item>) {
    let futures: Vec<_> = items
        .into_iter()
        .map(|item| process_item(item))
        .collect();
    
    futures::future::join_all(futures).await;  // Concurrent
}
```

### 6. Use `Arc` Instead of `Clone`

**Bad**:
```rust
async fn process(data: Vec<u8>) {
    tokio::spawn(async move {
        // data is moved, requires clone for each spawn
    });
}
```

**Good**:
```rust
async fn process(data: Arc<Vec<u8>>) {
    tokio::spawn(async move {
        // Arc is cheap to clone
        let data = data.clone();
    });
}
```

## Memory Management

### 1. Avoid Memory Leaks

```rust
// Use RAII for cleanup
struct Resource {
    handle: Handle,
}

impl Drop for Resource {
    fn drop(&mut self) {
        // Cleanup happens automatically
        self.handle.close();
    }
}
```

### 2. Use `Cow` for Conditional Ownership

```rust
use std::borrow::Cow;

fn process_string(input: &str) -> Cow<str> {
    if input.contains("bad") {
        Cow::Owned(input.replace("bad", "good"))  // Allocate only if needed
    } else {
        Cow::Borrowed(input)  // No allocation
    }
}
```

### 3. Preallocate Capacity

```rust
// Bad
let mut vec = Vec::new();
for i in 0..1000 {
    vec.push(i);  // May reallocate multiple times
}

// Good
let mut vec = Vec::with_capacity(1000);
for i in 0..1000 {
    vec.push(i);  // No reallocation
}
```

## Benchmarking

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench crypto_bench

# Save baseline
cargo bench -- --save-baseline main

# Compare to baseline
cargo bench -- --baseline main
```

### Interpreting Results

```
test bench_constant_time_eq ... bench:     125 ns/iter (+/- 10)
```

- **125 ns/iter**: Average time per iteration
- **(+/- 10)**: Standard deviation

### Performance Regression Tests

Add to CI/CD:

```yaml
- name: Run benchmarks
  run: cargo bench -- --save-baseline ci

- name: Check for regressions
  run: |
    cargo bench -- --baseline ci
    # Fail if performance degrades >10%
```

## Async Best Practices

### 1. Don't Block the Runtime

**Bad**:
```rust
async fn process() {
    std::thread::sleep(Duration::from_secs(1));  // Blocks runtime!
}
```

**Good**:
```rust
async fn process() {
    tokio::time::sleep(Duration::from_secs(1)).await;  // Non-blocking
}
```

### 2. Use `spawn_blocking` for CPU-Intensive Work

```rust
async fn hash_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        // CPU-intensive work
        bcrypt::hash(password, 12)
    })
    .await?
}
```

### 3. Limit Concurrency

```rust
use futures::stream::{self, StreamExt};

async fn process_all(items: Vec<Item>) {
    stream::iter(items)
        .map(|item| process_item(item))
        .buffer_unordered(10)  // Max 10 concurrent
        .collect::<Vec<_>>()
        .await;
}
```

## Caching Strategies

### 1. LRU Cache

```rust
use lru::LruCache;

struct ThreatCache {
    cache: LruCache<String, ThreatInfo>,
}

impl ThreatCache {
    fn new(capacity: usize) -> Self {
        Self {
            cache: LruCache::new(capacity),
        }
    }
    
    fn get(&mut self, key: &str) -> Option<&ThreatInfo> {
        self.cache.get(key)
    }
    
    fn put(&mut self, key: String, value: ThreatInfo) {
        self.cache.put(key, value);
    }
}
```

### 2. Time-Based Expiration

```rust
use std::time::{Duration, Instant};

struct CachedValue<T> {
    value: T,
    expires_at: Instant,
}

impl<T> CachedValue<T> {
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }
    
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}
```

## Performance Checklist

Before deploying to production:

- [ ] Run benchmarks and verify performance targets
- [ ] Profile CPU usage under load
- [ ] Profile memory usage and check for leaks
- [ ] Test with realistic data volumes
- [ ] Verify async tasks don't block the runtime
- [ ] Check connection pool sizes
- [ ] Review cache hit rates
- [ ] Test concurrent request handling
- [ ] Verify resource cleanup (Drop implementations)
- [ ] Check for unnecessary allocations
- [ ] Review database query performance
- [ ] Test with production-like network latency

## Monitoring Performance

### Metrics to Track

```rust
// Track operation latency
let start = Instant::now();
perform_operation().await?;
let duration = start.elapsed();
metrics.record_latency("operation_name", duration);

// Track throughput
metrics.increment_counter("operations_completed");

// Track resource usage
metrics.gauge("memory_usage_bytes", get_memory_usage());
metrics.gauge("active_connections", pool.size());
```

### Performance Dashboards

Monitor these metrics:
- Request latency (p50, p95, p99)
- Throughput (requests/second)
- Error rate
- CPU usage
- Memory usage
- Connection pool utilization
- Cache hit rate

## Common Performance Pitfalls

1. **Unnecessary Clones**: Use references or `Arc` instead
2. **Blocking in Async**: Use `spawn_blocking` for CPU work
3. **No Connection Pooling**: Reuse database connections
4. **Unbounded Concurrency**: Limit concurrent tasks
5. **No Caching**: Cache expensive operations
6. **Inefficient Serialization**: Use binary formats for large data
7. **Too Many Allocations**: Preallocate and reuse buffers
8. **Synchronous I/O**: Use async I/O everywhere

## Resources

- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [Tokio Performance Guide](https://tokio.rs/tokio/topics/performance)
- [Flamegraph](https://github.com/flamegraph-rs/flamegraph)
- [cargo-bench](https://doc.rust-lang.org/cargo/commands/cargo-bench.html)

---

For performance-critical code, always measure before and after optimization!
