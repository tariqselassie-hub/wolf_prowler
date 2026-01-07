//! Utility functions for the wolf_net crate.

use libp2p::Multiaddr;
use std::net::{IpAddr, SocketAddr};

/// Placeholder for utility initialization.
pub fn init() {
    // Initialize utility subsystems if needed
    tracing::debug!("Wolf Net utilities initialized");
}

/// Sets up the logging system with a specific log level.
pub fn setup_logging(level: tracing::Level) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .try_init()
        .map_err(|e| anyhow::anyhow!("Failed to initialize logging: {}", e))
}

/// Converts a Multiaddr to a SocketAddr if possible.
pub fn multiaddr_to_socketaddr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter();
    let ip = match iter.next()? {
        libp2p::multiaddr::Protocol::Ip4(ip) => IpAddr::V4(ip),
        libp2p::multiaddr::Protocol::Ip6(ip) => IpAddr::V6(ip),
        _ => return None,
    };
    let port = match iter.next()? {
        libp2p::multiaddr::Protocol::Tcp(port) => port,
        libp2p::multiaddr::Protocol::Udp(port) => port,
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Converts a SocketAddr to a Multiaddr (TCP).
pub fn socketaddr_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    let mut ma = Multiaddr::empty();
    match addr.ip() {
        IpAddr::V4(ip) => ma.push(libp2p::multiaddr::Protocol::Ip4(ip)),
        IpAddr::V6(ip) => ma.push(libp2p::multiaddr::Protocol::Ip6(ip)),
    }
    ma.push(libp2p::multiaddr::Protocol::Tcp(addr.port()));
    ma
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_logging() {
        // Attempt to set up logging.
        // Note: This may fail if logging was already initialized by another test,
        // which is expected behavior for tracing_subscriber.
        let result = setup_logging(tracing::Level::DEBUG);
        if let Err(e) = result {
            assert!(e.to_string().contains("Failed to initialize logging"));
        }
    }

    #[test]
    fn test_address_conversion() {
        let socket_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let multiaddr = socketaddr_to_multiaddr(socket_addr);

        assert!(multiaddr.to_string().contains("/ip4/127.0.0.1/tcp/8080"));

        let converted_back = multiaddr_to_socketaddr(&multiaddr);
        assert_eq!(converted_back, Some(socket_addr));
    }
}
