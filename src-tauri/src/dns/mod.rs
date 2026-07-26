mod cache;
mod wire;

pub use cache::{DnsCache, DnsCacheConfig};
pub use wire::{
    DnsAnswer, DnsMessageError, DnsQuery, parse_query, parse_response_answers,
    parse_response_answers_for_query, response_correlates,
};

pub const DNS_PORT: u16 = 53;

/// UDP is required by this slice. TCP is represented explicitly so fallback
/// can be added by the direct DNS forwarder without changing cache semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}
