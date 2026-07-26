//! Outbound transports selected after capture and routing.

pub mod direct;
pub mod proxy;

pub use direct::{
    CancellationToken, DirectBinding, DirectError, DirectOutbound, DirectTcp, DirectUdp,
    FlowMetadata, LoopGuard, TransportProtocol,
};
pub use proxy::{ProxyError, ProxyOutbound};
