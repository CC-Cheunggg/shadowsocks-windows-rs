//! Deliberately unimplemented proxy boundary for this DIRECT-only slice.

use std::fmt;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    ProxyNotImplemented,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("proxy outbound is not implemented")
    }
}

impl std::error::Error for ProxyError {}

#[derive(Debug, Default)]
pub struct ProxyOutbound;

impl ProxyOutbound {
    /// Fails closed. Callers must never translate this into DIRECT.
    pub fn connect_tcp(&self, _destination: SocketAddr) -> Result<(), ProxyError> {
        Err(ProxyError::ProxyNotImplemented)
    }

    /// Fails closed. Callers must never translate this into DIRECT.
    pub fn associate_udp(&self, _destination: SocketAddr) -> Result<(), ProxyError> {
        Err(ProxyError::ProxyNotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_placeholder_always_fails_closed() {
        let proxy = ProxyOutbound;
        let destination = "192.0.2.1:443".parse().unwrap();
        assert_eq!(
            proxy.connect_tcp(destination),
            Err(ProxyError::ProxyNotImplemented)
        );
        assert_eq!(
            proxy.associate_udp(destination),
            Err(ProxyError::ProxyNotImplemented)
        );
    }
}
