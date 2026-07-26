use std::fmt;
use std::io;

/// Packet failures are intentionally structural. They never contain packet
/// bytes, addresses, host names, or other captured data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    TooShort,
    InvalidIpVersion,
    InvalidIpv4HeaderLength,
    InvalidIpv4TotalLength,
    InvalidIpv4HeaderChecksum,
    FragmentedIpv4,
    InvalidIpv6PayloadLength,
    FragmentedIpv6,
    UnsupportedIpv6Extension,
    InvalidTcpHeaderLength,
    InvalidUdpLength,
    InvalidTransportChecksum,
    PacketTooLarge,
}

impl fmt::Display for PacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooShort => "packet is shorter than the required header",
            Self::InvalidIpVersion => "packet has an unsupported IP version",
            Self::InvalidIpv4HeaderLength => "IPv4 header length is invalid",
            Self::InvalidIpv4TotalLength => "IPv4 total length is invalid",
            Self::InvalidIpv4HeaderChecksum => "IPv4 header checksum is invalid",
            Self::FragmentedIpv4 => "fragmented IPv4 packets are not supported",
            Self::InvalidIpv6PayloadLength => "IPv6 payload length is invalid",
            Self::FragmentedIpv6 => "fragmented IPv6 packets are not supported",
            Self::UnsupportedIpv6Extension => "IPv6 extension header is not supported",
            Self::InvalidTcpHeaderLength => "TCP header length is invalid",
            Self::InvalidUdpLength => "UDP datagram length is invalid",
            Self::InvalidTransportChecksum => "transport checksum is invalid",
            Self::PacketTooLarge => "packet exceeds the supported IP length",
        })
    }
}

impl std::error::Error for PacketError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    DirectTcpConnect,
    DirectTcpRead,
    DirectTcpWrite,
    DirectUdpBind,
    DirectUdpSend,
    DirectUdpReceive,
    DnsForward,
    TunReceive,
    TunSend,
    RouteUpdate,
}

impl IoOperation {
    const fn description(self) -> &'static str {
        match self {
            Self::DirectTcpConnect => "direct TCP connect",
            Self::DirectTcpRead => "direct TCP read",
            Self::DirectTcpWrite => "direct TCP write",
            Self::DirectUdpBind => "direct UDP bind",
            Self::DirectUdpSend => "direct UDP send",
            Self::DirectUdpReceive => "direct UDP receive",
            Self::DnsForward => "DNS forward",
            Self::TunReceive => "TUN receive",
            Self::TunSend => "TUN send",
            Self::RouteUpdate => "route update",
        }
    }
}

/// Errors exposed by the connection engine.
///
/// Dynamic OS messages and captured data are deliberately not retained. The
/// I/O kind is enough for diagnostics without leaking a destination, DNS
/// payload, path, credential, or authorization material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    Packet(PacketError),
    InvalidRule,
    InvalidDomain,
    InvalidCacheConfiguration,
    StateUnavailable,
    SessionCapacity,
    InvalidSessionState,
    UnsupportedProtocol,
    ProxyNotImplemented,
    Cancelled,
    TimedOut,
    Io {
        operation: IoOperation,
        kind: io::ErrorKind,
    },
}

impl EngineError {
    pub fn safe_io(operation: IoOperation, error: &io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}

impl From<PacketError> for EngineError {
    fn from(error: PacketError) -> Self {
        Self::Packet(error)
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(error) => write!(formatter, "{error}"),
            Self::InvalidRule => formatter.write_str("routing rule is invalid"),
            Self::InvalidDomain => formatter.write_str("domain name is invalid"),
            Self::InvalidCacheConfiguration => {
                formatter.write_str("DNS cache configuration is invalid")
            }
            Self::StateUnavailable => formatter.write_str("connection engine state is unavailable"),
            Self::SessionCapacity => formatter.write_str("session capacity was reached"),
            Self::InvalidSessionState => formatter.write_str("session state transition is invalid"),
            Self::UnsupportedProtocol => {
                formatter.write_str("captured protocol is not supported; traffic was blocked")
            }
            Self::ProxyNotImplemented => {
                formatter.write_str("proxy outbound is not implemented; traffic was blocked")
            }
            Self::Cancelled => formatter.write_str("connection operation was cancelled"),
            Self::TimedOut => formatter.write_str("connection operation timed out"),
            Self::Io { operation, kind } => {
                write!(formatter, "{} failed ({kind:?})", operation.description())
            }
        }
    }
}

impl std::error::Error for EngineError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_do_not_retain_sensitive_os_messages() {
        let secret = "secret.example/private/path?authorization=token";
        let source = io::Error::new(io::ErrorKind::PermissionDenied, secret);
        let error = EngineError::safe_io(IoOperation::DirectTcpConnect, &source);
        let display = error.to_string();
        let debug = format!("{error:?}");

        assert!(!display.contains(secret));
        assert!(!debug.contains(secret));
        assert_eq!(display, "direct TCP connect failed (PermissionDenied)");
    }

    #[test]
    fn proxy_failure_is_explicit_and_closed() {
        assert_eq!(
            EngineError::ProxyNotImplemented.to_string(),
            "proxy outbound is not implemented; traffic was blocked"
        );
    }
}
