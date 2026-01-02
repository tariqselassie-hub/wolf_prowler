# Use Rust official image as base for building
FROM rust:1.75-slim-bookworm as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Copy all workspace crates
COPY wolf_den ./wolf_den
COPY wolf_net ./wolf_net
COPY wolfsec ./wolfsec
COPY wolf_server ./wolf_server
COPY src ./src
COPY wolf_web ./wolf_web
COPY wolf_control ./wolf_control

# Build the primary server binary
# We use wolf_server as the base for both Hub and Agent
RUN cargo build --release -p wolf_server

# Runtime stage: minimal image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-privileged user
RUN useradd -r -s /bin/false wolf

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/wolf_server /app/wolf_prowler_server

# Copy static assets (needed if acting as a Hub)
COPY --from=builder /app/wolf_web /app/wolf_web

# Set up data and log persistence
RUN mkdir -p /app/data /app/logs && \
    chown -R wolf:wolf /app

USER wolf

# P2P and API Ports
EXPOSE 3030 3031

# The binary handles configuration via environment variables
CMD ["./wolf_prowler_server"]
