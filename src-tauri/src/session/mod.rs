pub mod tcp;
pub mod udp;

use std::fmt;
use std::net::SocketAddr;

/// A captured TCP or UDP flow. Debug output is deliberately redacted so an
/// accidental diagnostic cannot disclose destination addresses.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl FlowKey {
    pub fn new(source: SocketAddr, destination: SocketAddr) -> Option<Self> {
        if source.port() == 0
            || destination.port() == 0
            || source.is_ipv4() != destination.is_ipv4()
        {
            return None;
        }
        Some(Self {
            source,
            destination,
        })
    }

    pub fn reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
        }
    }
}

impl fmt::Debug for FlowKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FlowKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_key_requires_one_address_family_and_redacts_debug() {
        let source: SocketAddr = "192.0.2.10:50000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let key = FlowKey::new(source, destination).unwrap();
        assert_eq!(key.reverse().source, destination);
        assert_eq!(format!("{key:?}"), "FlowKey([REDACTED])");
        assert!(FlowKey::new(source, "[2001:db8::1]:443".parse().unwrap()).is_none());
    }
}
