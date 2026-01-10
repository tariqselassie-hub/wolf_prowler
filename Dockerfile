FROM rust:1.70 as builder

WORKDIR /usr/src/wolf_prowler
COPY . .

# Build the server
RUN cargo build --release -p wolf_server

FROM debian:bookworm-slim

# Install OpenSSL (required for some dependencies) and ca-certificates
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/wolf_prowler/target/release/wolf_server /usr/local/bin/wolf_server

# Create directory for data
RUN mkdir -p /data/wolf_db /data/wolfsec_db /certs
VOLUME ["/data", "/certs"]

# Expose API port
EXPOSE 3030

CMD ["wolf_server"]