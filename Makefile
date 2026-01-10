# Wolf Prowler Development Makefile
# Simplifies running tests, benchmarks, and common development tasks.

CARGO := cargo
DOCKER_COMPOSE := docker-compose

.PHONY: all build check test test-all test-security test-persistence test-validation bench clean run-server docker-build docker-up

# Default: Check and run all tests
all: check test-all

# --- Build & Check ---

build:
	$(CARGO) build --workspace --all-features

check:
	$(CARGO) check --workspace --all-features
	$(CARGO) clippy --workspace --all-features

# --- Testing ---

# Run all tests in the workspace
test-all:
	$(CARGO) test --workspace --all-features

# Run the comprehensive security test suite in wolfsec
test-security:
	$(CARGO) test -p wolfsec comprehensive_tests

# Run the WolfDb persistence integration test in wolfsec
test-persistence:
	$(CARGO) test -p wolfsec test_wolf_db_threat_repository_integration -- --nocapture

# Run the server-side security event persistence test
test-server-persistence:
	$(CARGO) test -p wolf_server --bin wolf_server wolfsec_integration::tests::test_security_event_persistence

# Run the discovery event validation test (Input Sanitization)
test-validation:
	$(CARGO) test -p wolf_server --bin wolf_server tests::test_discovery_event_validation_integration

# --- Benchmarking ---

# Run performance benchmark tests (currently implemented as unit tests in wolfsec)
bench:
	$(CARGO) test -p wolfsec test_performance_benchmarks -- --nocapture

# Run criterion benchmarks for accurate cryptographic measurements
bench-criterion:
	$(CARGO) bench -p wolfsec

# --- Execution ---

run-server:
	$(CARGO) run -p wolf_server

clean:
	$(CARGO) clean