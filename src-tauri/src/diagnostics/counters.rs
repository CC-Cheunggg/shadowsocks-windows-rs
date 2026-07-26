use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    TunRxPackets,
    TunTxPackets,
    CapturedTcpSessions,
    CapturedUdpDatagrams,
    RouteDirect,
    RouteProxy,
    SystemProxyDetected,
    RouteDirectSystemProxy,
    DirectTcpConnections,
    DirectUdpAssociations,
    UnsupportedPackets,
    DroppedPackets,
    LoopPreventionDrops,
}

#[derive(Debug, Default)]
pub struct Diagnostics {
    tun_rx_packets: AtomicU64,
    tun_tx_packets: AtomicU64,
    captured_tcp_sessions: AtomicU64,
    captured_udp_datagrams: AtomicU64,
    route_direct: AtomicU64,
    route_proxy: AtomicU64,
    system_proxy_detected: AtomicU64,
    route_direct_system_proxy: AtomicU64,
    direct_tcp_connections: AtomicU64,
    direct_udp_associations: AtomicU64,
    unsupported_packets: AtomicU64,
    dropped_packets: AtomicU64,
    loop_prevention_drops: AtomicU64,
}

impl Diagnostics {
    pub fn increment(&self, counter: Counter) {
        self.add(counter, 1);
    }

    pub fn add(&self, counter: Counter, amount: u64) {
        saturating_add(self.atomic(counter), amount);
    }

    pub fn snapshot(&self) -> DiagnosticsSnapshot {
        DiagnosticsSnapshot {
            tun_rx_packets: self.load(Counter::TunRxPackets),
            tun_tx_packets: self.load(Counter::TunTxPackets),
            captured_tcp_sessions: self.load(Counter::CapturedTcpSessions),
            captured_udp_datagrams: self.load(Counter::CapturedUdpDatagrams),
            route_direct: self.load(Counter::RouteDirect),
            route_proxy: self.load(Counter::RouteProxy),
            system_proxy_detected: self.load(Counter::SystemProxyDetected),
            route_direct_system_proxy: self.load(Counter::RouteDirectSystemProxy),
            direct_tcp_connections: self.load(Counter::DirectTcpConnections),
            direct_udp_associations: self.load(Counter::DirectUdpAssociations),
            unsupported_packets: self.load(Counter::UnsupportedPackets),
            dropped_packets: self.load(Counter::DroppedPackets),
            loop_prevention_drops: self.load(Counter::LoopPreventionDrops),
        }
    }

    pub fn reset(&self) {
        for counter in [
            Counter::TunRxPackets,
            Counter::TunTxPackets,
            Counter::CapturedTcpSessions,
            Counter::CapturedUdpDatagrams,
            Counter::RouteDirect,
            Counter::RouteProxy,
            Counter::SystemProxyDetected,
            Counter::RouteDirectSystemProxy,
            Counter::DirectTcpConnections,
            Counter::DirectUdpAssociations,
            Counter::UnsupportedPackets,
            Counter::DroppedPackets,
            Counter::LoopPreventionDrops,
        ] {
            self.atomic(counter).store(0, Ordering::Relaxed);
        }
    }

    fn load(&self, counter: Counter) -> u64 {
        self.atomic(counter).load(Ordering::Relaxed)
    }

    fn atomic(&self, counter: Counter) -> &AtomicU64 {
        match counter {
            Counter::TunRxPackets => &self.tun_rx_packets,
            Counter::TunTxPackets => &self.tun_tx_packets,
            Counter::CapturedTcpSessions => &self.captured_tcp_sessions,
            Counter::CapturedUdpDatagrams => &self.captured_udp_datagrams,
            Counter::RouteDirect => &self.route_direct,
            Counter::RouteProxy => &self.route_proxy,
            Counter::SystemProxyDetected => &self.system_proxy_detected,
            Counter::RouteDirectSystemProxy => &self.route_direct_system_proxy,
            Counter::DirectTcpConnections => &self.direct_tcp_connections,
            Counter::DirectUdpAssociations => &self.direct_udp_associations,
            Counter::UnsupportedPackets => &self.unsupported_packets,
            Counter::DroppedPackets => &self.dropped_packets,
            Counter::LoopPreventionDrops => &self.loop_prevention_drops,
        }
    }
}

fn saturating_add(atomic: &AtomicU64, amount: u64) {
    let mut current = atomic.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(amount);
        match atomic.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiagnosticsSnapshot {
    pub tun_rx_packets: u64,
    pub tun_tx_packets: u64,
    pub captured_tcp_sessions: u64,
    pub captured_udp_datagrams: u64,
    pub route_direct: u64,
    pub route_proxy: u64,
    pub system_proxy_detected: u64,
    pub route_direct_system_proxy: u64,
    pub direct_tcp_connections: u64,
    pub direct_udp_associations: u64,
    pub unsupported_packets: u64,
    pub dropped_packets: u64,
    pub loop_prevention_drops: u64,
}

/// Opaque, process-local correlation identifier. It carries no destination or
/// payload data and is suitable for the optional
/// captured→decision→outbound→completed/failed diagnostic chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId(u64);

impl FlowId {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
pub struct FlowIdGenerator {
    next: AtomicU64,
}

impl Default for FlowIdGenerator {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }
}

impl FlowIdGenerator {
    pub fn next(&self) -> FlowId {
        let value = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(1))
            })
            .unwrap_or(u64::MAX);
        FlowId(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn snapshot_contains_only_named_safe_counts() {
        let diagnostics = Diagnostics::default();
        diagnostics.add(Counter::TunRxPackets, 3);
        diagnostics.increment(Counter::RouteDirect);
        diagnostics.increment(Counter::DroppedPackets);
        assert_eq!(
            diagnostics.snapshot(),
            DiagnosticsSnapshot {
                tun_rx_packets: 3,
                route_direct: 1,
                dropped_packets: 1,
                ..DiagnosticsSnapshot::default()
            }
        );
    }

    #[test]
    fn increments_are_thread_safe() {
        let diagnostics = Arc::new(Diagnostics::default());
        let mut threads = Vec::new();
        for _ in 0..8 {
            let diagnostics = Arc::clone(&diagnostics);
            threads.push(thread::spawn(move || {
                for _ in 0..10_000 {
                    diagnostics.increment(Counter::CapturedUdpDatagrams);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(diagnostics.snapshot().captured_udp_datagrams, 80_000);
    }

    #[test]
    fn reset_starts_a_new_runtime_counting_window() {
        let diagnostics = Diagnostics::default();
        diagnostics.add(Counter::TunRxPackets, 3);
        diagnostics.increment(Counter::RouteDirect);
        diagnostics.reset();
        assert_eq!(diagnostics.snapshot(), DiagnosticsSnapshot::default());
    }

    #[test]
    fn flow_ids_are_non_secret_and_monotonic() {
        let generator = FlowIdGenerator::default();
        assert_eq!(generator.next().get(), 1);
        assert_eq!(generator.next().get(), 2);
    }
}
