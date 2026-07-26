use super::FlowKey;
use crate::error::EngineError;
use crate::packet::IpPacket;
use crate::packet::tcp::{self, TcpPacket};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp::{Socket as SmolTcpSocket, SocketBuffer, State as SmolTcpState};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{
    HardwareAddress, IpAddress as SmolIpAddress, IpCidr as SmolIpCidr, IpListenEndpoint,
};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const STACK_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const STACK_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x7373, 0x7273, 0, 0, 0, 0, 1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSessionConfig {
    pub max_sessions: usize,
    pub receive_buffer_bytes: usize,
    pub transmit_buffer_bytes: usize,
    pub idle_timeout: Duration,
    pub mtu: usize,
}

impl Default for TcpSessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: 4096,
            receive_buffer_bytes: 64 * 1024,
            transmit_buffer_bytes: 64 * 1024,
            idle_timeout: Duration::from_secs(300),
            mtu: 1500,
        }
    }
}

impl TcpSessionConfig {
    fn validate(self) -> Result<Self, EngineError> {
        if self.max_sessions == 0
            || self.receive_buffer_bytes < 4096
            || self.transmit_buffer_bytes < 4096
            || self.idle_timeout.is_zero()
            || !(1280..=9000).contains(&self.mtu)
        {
            return Err(EngineError::InvalidSessionState);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpLifecycle {
    Handshaking,
    Established,
    ClientHalfClosed,
    Closing,
    Closed,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSessionNotice {
    Established(FlowKey),
    ClientHalfClosed(FlowKey),
    Closed(FlowKey),
    Reset(FlowKey),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpIngest {
    pub key: FlowKey,
    pub created: bool,
    pub notices: Vec<TcpSessionNotice>,
}

struct Session {
    handle: SocketHandle,
    lifecycle: TcpLifecycle,
    client_eof_reported: bool,
    last_activity: Instant,
}

/// Thin transparent-session adapter around smoltcp.
///
/// smoltcp owns sequence numbers, retransmission, windows, FIN/RST behavior,
/// and TCP timers. This adapter only creates an exact listener when a captured
/// SYN arrives and exposes bounded stream buffers to the DIRECT outbound.
pub struct TcpSessionEngine {
    config: TcpSessionConfig,
    started_at: Instant,
    interface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    sessions: HashMap<FlowKey, Session>,
}

impl TcpSessionEngine {
    pub fn new(config: TcpSessionConfig, now: Instant) -> Result<Self, EngineError> {
        let config = config.validate()?;
        let mut device = QueueDevice::new(config.mtu);
        let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        interface_config.random_seed = monotonic_seed(now);
        let mut interface =
            Interface::new(interface_config, &mut device, SmolInstant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(SmolIpCidr::new(SmolIpAddress::Ipv4(STACK_IPV4), 15))
                .expect("smoltcp IPv4 address capacity");
            addresses
                .push(SmolIpCidr::new(SmolIpAddress::Ipv6(STACK_IPV6), 64))
                .expect("smoltcp IPv6 address capacity");
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(STACK_IPV4)
            .expect("smoltcp IPv4 route capacity");
        interface
            .routes_mut()
            .add_default_ipv6_route(STACK_IPV6)
            .expect("smoltcp IPv6 route capacity");
        interface.set_any_ip(true);

        Ok(Self {
            config,
            started_at: now,
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            sessions: HashMap::new(),
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Validates and ingests one complete TCP/IP packet. A new exact listener
    /// is installed only for a first SYN; stray packets are left to smoltcp,
    /// which produces the standards-compliant reset when appropriate.
    pub fn ingest(&mut self, bytes: &[u8], now: Instant) -> Result<TcpIngest, EngineError> {
        let (key, flags, packet) = parse_tcp_flow(bytes)?;
        let mut created = false;
        if !self.sessions.contains_key(&key)
            && flags & tcp::flags::SYN != 0
            && flags & (tcp::flags::ACK | tcp::flags::RST) == 0
        {
            match self.add_listener(key, now) {
                Ok(()) => created = true,
                Err(EngineError::SessionCapacity) => {
                    // Give smoltcp the unmatched SYN so it can emit the
                    // standards-compliant reset. Capacity exhaustion belongs
                    // to this flow and must not poison the whole runtime.
                    self.device.rx.push_back(packet);
                    self.poll(now)?;
                    return Err(EngineError::SessionCapacity);
                }
                Err(error) => return Err(error),
            }
        }
        if let Some(session) = self.sessions.get_mut(&key) {
            session.last_activity = now;
        }
        self.device.rx.push_back(packet);
        let notices = self.poll(now)?;
        Ok(TcpIngest {
            key,
            created,
            notices,
        })
    }

    pub fn poll(&mut self, now: Instant) -> Result<Vec<TcpSessionNotice>, EngineError> {
        let timestamp = self.timestamp(now);
        self.interface
            .poll(timestamp, &mut self.device, &mut self.sockets);

        let mut notices = Vec::new();
        for (key, session) in &mut self.sessions {
            let socket = self.sockets.get::<SmolTcpSocket<'static>>(session.handle);
            let state = socket.state();
            let lifecycle = lifecycle(state, socket.may_recv());

            if lifecycle == TcpLifecycle::Established
                && session.lifecycle == TcpLifecycle::Handshaking
            {
                notices.push(TcpSessionNotice::Established(*key));
            }
            if !socket.may_recv()
                && !socket.can_recv()
                && !session.client_eof_reported
                && !matches!(
                    state,
                    SmolTcpState::Listen | SmolTcpState::SynReceived | SmolTcpState::Closed
                )
            {
                session.client_eof_reported = true;
                notices.push(TcpSessionNotice::ClientHalfClosed(*key));
            }
            if lifecycle != session.lifecycle {
                match lifecycle {
                    TcpLifecycle::Closed => notices.push(TcpSessionNotice::Closed(*key)),
                    TcpLifecycle::Reset => notices.push(TcpSessionNotice::Reset(*key)),
                    _ => {}
                }
                session.lifecycle = lifecycle;
            }
        }
        Ok(notices)
    }

    pub fn lifecycle(&self, key: &FlowKey) -> Option<TcpLifecycle> {
        self.sessions.get(key).map(|session| session.lifecycle)
    }

    /// Rejects an otherwise valid unmatched flow without allocating a session.
    /// smoltcp emits the appropriate reset for an initial SYN.
    pub fn reject(&mut self, bytes: &[u8], now: Instant) -> Result<(), EngineError> {
        let (_, _, packet) = parse_tcp_flow(bytes)?;
        self.device.rx.push_back(packet);
        self.poll(now)?;
        Ok(())
    }

    pub fn can_receive_from_client(&self, key: &FlowKey) -> bool {
        self.sessions.get(key).is_some_and(|session| {
            self.sockets
                .get::<SmolTcpSocket<'static>>(session.handle)
                .can_recv()
        })
    }

    /// Removes up to `buffer.len()` bytes from the client-facing TCP receive
    /// window. Calling code should reserve bounded outbound-channel capacity
    /// first; leaving bytes here naturally applies TCP backpressure.
    pub fn receive_from_client(
        &mut self,
        key: &FlowKey,
        buffer: &mut [u8],
        now: Instant,
    ) -> Result<usize, EngineError> {
        let session = self
            .sessions
            .get_mut(key)
            .ok_or(EngineError::InvalidSessionState)?;
        let socket = self
            .sockets
            .get_mut::<SmolTcpSocket<'static>>(session.handle);
        if !socket.can_recv() {
            return Ok(0);
        }
        let received = socket
            .recv_slice(buffer)
            .map_err(|_| EngineError::InvalidSessionState)?;
        if received > 0 {
            session.last_activity = now;
        }
        Ok(received)
    }

    /// Enqueues as much DIRECT response data as the bounded smoltcp transmit
    /// window can accept. The caller retains and retries the unaccepted suffix.
    pub fn send_to_client(
        &mut self,
        key: &FlowKey,
        data: &[u8],
        now: Instant,
    ) -> Result<usize, EngineError> {
        let session = self
            .sessions
            .get_mut(key)
            .ok_or(EngineError::InvalidSessionState)?;
        let socket = self
            .sockets
            .get_mut::<SmolTcpSocket<'static>>(session.handle);
        if !socket.may_send() {
            return Err(EngineError::InvalidSessionState);
        }
        let sent = socket
            .send_slice(data)
            .map_err(|_| EngineError::InvalidSessionState)?;
        if sent > 0 {
            session.last_activity = now;
        }
        Ok(sent)
    }

    /// DIRECT EOF maps to a graceful FIN after queued response bytes.
    pub fn close_direct_write(&mut self, key: &FlowKey, now: Instant) -> Result<(), EngineError> {
        let session = self
            .sessions
            .get_mut(key)
            .ok_or(EngineError::InvalidSessionState)?;
        self.sockets
            .get_mut::<SmolTcpSocket<'static>>(session.handle)
            .close();
        session.lifecycle = TcpLifecycle::Closing;
        self.poll(now)?;
        Ok(())
    }

    /// Connection refusal, cancellation, or an outbound error maps to TCP RST.
    pub fn abort(&mut self, key: &FlowKey, now: Instant) -> Result<(), EngineError> {
        let session = self
            .sessions
            .get_mut(key)
            .ok_or(EngineError::InvalidSessionState)?;
        self.sockets
            .get_mut::<SmolTcpSocket<'static>>(session.handle)
            .abort();
        session.lifecycle = TcpLifecycle::Reset;
        self.poll(now)?;
        Ok(())
    }

    /// Removes terminal sockets after their final packet has been emitted and
    /// also bounds stalled sessions independently of smoltcp's own TCP timer.
    pub fn reap(&mut self, now: Instant) -> Vec<FlowKey> {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(key, session)| {
                let socket = self.sockets.get::<SmolTcpSocket<'static>>(session.handle);
                let terminal = matches!(
                    socket.state(),
                    SmolTcpState::Closed | SmolTcpState::TimeWait
                );
                let idle = now.saturating_duration_since(session.last_activity)
                    >= self.config.idle_timeout;
                (terminal || idle).then_some(*key)
            })
            .collect::<Vec<_>>();

        for key in &expired {
            if let Some(session) = self.sessions.remove(key) {
                self.sockets.remove(session.handle);
            }
        }
        expired
    }

    pub fn take_transmit(&mut self) -> Vec<Vec<u8>> {
        self.device.tx.drain(..).collect()
    }

    fn add_listener(&mut self, key: FlowKey, now: Instant) -> Result<(), EngineError> {
        if self.sessions.len() >= self.config.max_sessions {
            return Err(EngineError::SessionCapacity);
        }
        let mut socket = SmolTcpSocket::new(
            SocketBuffer::new(vec![0; self.config.receive_buffer_bytes]),
            SocketBuffer::new(vec![0; self.config.transmit_buffer_bytes]),
        );
        socket.set_timeout(Some(SmolDuration::from_millis(duration_millis(
            self.config.idle_timeout,
        ))));
        socket.set_nagle_enabled(false);
        socket
            .listen(IpListenEndpoint {
                addr: Some(to_smoltcp_ip(key.destination.ip())),
                port: key.destination.port(),
            })
            .map_err(|_| EngineError::InvalidSessionState)?;
        let handle = self.sockets.add(socket);
        self.sessions.insert(
            key,
            Session {
                handle,
                lifecycle: TcpLifecycle::Handshaking,
                client_eof_reported: false,
                last_activity: now,
            },
        );
        Ok(())
    }

    fn timestamp(&self, now: Instant) -> SmolInstant {
        SmolInstant::from_millis(
            now.saturating_duration_since(self.started_at)
                .as_millis()
                .min(i64::MAX as u128) as i64,
        )
    }
}

pub fn inspect_tcp_flow(bytes: &[u8]) -> Result<(FlowKey, u16), EngineError> {
    let (key, flags, _) = parse_tcp_flow(bytes)?;
    Ok((key, flags))
}

fn lifecycle(state: SmolTcpState, may_recv: bool) -> TcpLifecycle {
    match state {
        SmolTcpState::Listen | SmolTcpState::SynSent | SmolTcpState::SynReceived => {
            TcpLifecycle::Handshaking
        }
        SmolTcpState::Established => TcpLifecycle::Established,
        SmolTcpState::CloseWait if !may_recv => TcpLifecycle::ClientHalfClosed,
        SmolTcpState::FinWait1
        | SmolTcpState::FinWait2
        | SmolTcpState::CloseWait
        | SmolTcpState::Closing
        | SmolTcpState::LastAck => TcpLifecycle::Closing,
        SmolTcpState::TimeWait => TcpLifecycle::Closed,
        SmolTcpState::Closed => TcpLifecycle::Reset,
    }
}

fn parse_tcp_flow(bytes: &[u8]) -> Result<(FlowKey, u16, Vec<u8>), EngineError> {
    match IpPacket::parse(bytes)? {
        IpPacket::V4(packet) if packet.protocol() == tcp::PROTOCOL_NUMBER => {
            let segment = TcpPacket::parse(packet.payload())?;
            segment.verify_ipv4_checksum(packet.source(), packet.destination())?;
            let key = FlowKey::new(
                SocketAddr::new(IpAddr::V4(packet.source()), segment.source_port()),
                SocketAddr::new(IpAddr::V4(packet.destination()), segment.destination_port()),
            )
            .ok_or(EngineError::InvalidSessionState)?;
            Ok((key, segment.flags(), packet.packet().to_vec()))
        }
        IpPacket::V6(packet) if packet.next_header() == tcp::PROTOCOL_NUMBER => {
            let segment = TcpPacket::parse(packet.payload())?;
            segment.verify_ipv6_checksum(packet.source(), packet.destination())?;
            let key = FlowKey::new(
                SocketAddr::new(IpAddr::V6(packet.source()), segment.source_port()),
                SocketAddr::new(IpAddr::V6(packet.destination()), segment.destination_port()),
            )
            .ok_or(EngineError::InvalidSessionState)?;
            Ok((key, segment.flags(), packet.packet().to_vec()))
        }
        _ => Err(EngineError::UnsupportedProtocol),
    }
}

fn to_smoltcp_ip(address: IpAddr) -> SmolIpAddress {
    match address {
        IpAddr::V4(address) => SmolIpAddress::Ipv4(address),
        IpAddr::V6(address) => SmolIpAddress::Ipv6(address),
    }
}

fn monotonic_seed(now: Instant) -> u64 {
    let address = &now as *const Instant as usize as u64;
    address.rotate_left(17) ^ std::process::id() as u64
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl QueueDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx.pop_front().map(|packet| {
            (
                QueueRxToken(packet),
                QueueTxToken {
                    queue: &mut self.tx,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken {
            queue: &mut self.tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

struct QueueRxToken(Vec<u8>);

impl smoltcp::phy::RxToken for QueueRxToken {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(&self.0)
    }
}

struct QueueTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl smoltcp::phy::TxToken for QueueTxToken<'_> {
    fn consume<R, F>(self, length: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; length];
        let result = function(&mut packet);
        self.queue.push_back(packet);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PacketError;
    use crate::packet::checksum::internet_checksum;

    fn tcp_ipv4(
        source: SocketAddr,
        destination: SocketAddr,
        sequence: u32,
        acknowledgment: u32,
        flags: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let source_ip = match source.ip() {
            IpAddr::V4(address) => address,
            _ => panic!("IPv4 test source"),
        };
        let destination_ip = match destination.ip() {
            IpAddr::V4(address) => address,
            _ => panic!("IPv4 test destination"),
        };
        let mut segment = vec![0; 20 + payload.len()];
        segment[0..2].copy_from_slice(&source.port().to_be_bytes());
        segment[2..4].copy_from_slice(&destination.port().to_be_bytes());
        segment[4..8].copy_from_slice(&sequence.to_be_bytes());
        segment[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
        segment[12] = 0x50 | ((flags >> 8) as u8 & 1);
        segment[13] = flags as u8;
        segment[14..16].copy_from_slice(&32_000_u16.to_be_bytes());
        segment[20..].copy_from_slice(payload);
        let checksum = tcp::checksum_ipv4(source_ip, destination_ip, &segment);
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());

        let mut packet = vec![0; 20 + segment.len()];
        let packet_length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = tcp::PROTOCOL_NUMBER;
        packet[12..16].copy_from_slice(&source_ip.octets());
        packet[16..20].copy_from_slice(&destination_ip.octets());
        packet[20..].copy_from_slice(&segment);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn parsed_tcp(packet: &[u8]) -> (Ipv4Addr, Ipv4Addr, TcpPacket<'_>) {
        let IpPacket::V4(ip) = IpPacket::parse(packet).unwrap() else {
            panic!("IPv4");
        };
        (
            ip.source(),
            ip.destination(),
            TcpPacket::parse(ip.payload()).unwrap(),
        )
    }

    fn handshake(
        engine: &mut TcpSessionEngine,
        now: Instant,
        client: SocketAddr,
        destination: SocketAddr,
    ) -> (FlowKey, u32) {
        let syn = tcp_ipv4(client, destination, 1000, 0, tcp::flags::SYN, &[]);
        let ingest = engine.ingest(&syn, now).unwrap();
        assert!(ingest.created);
        let packets = engine.take_transmit();
        assert_eq!(packets.len(), 1);
        let (_, _, syn_ack) = parsed_tcp(&packets[0]);
        assert_eq!(
            syn_ack.flags() & (tcp::flags::SYN | tcp::flags::ACK),
            tcp::flags::SYN | tcp::flags::ACK
        );
        let server_sequence = syn_ack.sequence_number();
        let ack = tcp_ipv4(
            client,
            destination,
            1001,
            server_sequence.wrapping_add(1),
            tcp::flags::ACK,
            &[],
        );
        engine.ingest(&ack, now + Duration::from_millis(1)).unwrap();
        assert_eq!(
            engine.lifecycle(&ingest.key),
            Some(TcpLifecycle::Established)
        );
        engine.take_transmit();
        (ingest.key, server_sequence)
    }

    #[test]
    fn smoltcp_terminates_handshake_and_reassembles_stream() {
        let now = Instant::now();
        let mut engine = TcpSessionEngine::new(TcpSessionConfig::default(), now).unwrap();
        let client = "198.18.0.2:50000".parse().unwrap();
        let destination = "203.0.113.8:443".parse().unwrap();
        let (key, server_sequence) = handshake(&mut engine, now, client, destination);

        let data = tcp_ipv4(
            client,
            destination,
            1001,
            server_sequence.wrapping_add(1),
            tcp::flags::ACK | tcp::flags::PSH,
            b"partial stream",
        );
        engine
            .ingest(&data, now + Duration::from_millis(2))
            .unwrap();
        let mut buffer = [0; 64];
        let count = engine
            .receive_from_client(&key, &mut buffer, now + Duration::from_millis(3))
            .unwrap();
        assert_eq!(&buffer[..count], b"partial stream");
    }

    #[test]
    fn bounded_send_window_applies_backpressure_and_abort_emits_reset() {
        let now = Instant::now();
        let config = TcpSessionConfig {
            transmit_buffer_bytes: 4096,
            ..TcpSessionConfig::default()
        };
        let mut engine = TcpSessionEngine::new(config, now).unwrap();
        let client = "198.18.0.2:50001".parse().unwrap();
        let destination = "203.0.113.8:80".parse().unwrap();
        let (key, _) = handshake(&mut engine, now, client, destination);

        let data = vec![0x5a; 8192];
        assert_eq!(
            engine
                .send_to_client(&key, &data, now + Duration::from_millis(2))
                .unwrap(),
            4096
        );
        assert_eq!(
            engine
                .send_to_client(&key, &data, now + Duration::from_millis(3))
                .unwrap(),
            0
        );
        engine.abort(&key, now + Duration::from_millis(4)).unwrap();
        let packets = engine.take_transmit();
        assert!(
            packets
                .iter()
                .map(|packet| parsed_tcp(packet).2.flags())
                .any(|flags| flags & tcp::flags::RST != 0)
        );
    }

    #[test]
    fn unmatched_flow_can_be_rejected_without_allocating_a_session() {
        let now = Instant::now();
        let mut engine = TcpSessionEngine::new(TcpSessionConfig::default(), now).unwrap();
        let syn = tcp_ipv4(
            "198.18.0.2:50010".parse().unwrap(),
            "203.0.113.8:443".parse().unwrap(),
            1,
            0,
            tcp::flags::SYN,
            &[],
        );
        engine.reject(&syn, now).unwrap();
        assert_eq!(engine.session_count(), 0);
        assert!(
            engine
                .take_transmit()
                .iter()
                .map(|packet| parsed_tcp(packet).2.flags())
                .any(|flags| flags & tcp::flags::RST != 0)
        );
    }

    #[test]
    fn client_fin_is_reported_as_half_close_and_sessions_expire() {
        let now = Instant::now();
        let config = TcpSessionConfig {
            idle_timeout: Duration::from_secs(5),
            ..TcpSessionConfig::default()
        };
        let mut engine = TcpSessionEngine::new(config, now).unwrap();
        let client = "198.18.0.2:50002".parse().unwrap();
        let destination = "203.0.113.8:53".parse().unwrap();
        let (key, server_sequence) = handshake(&mut engine, now, client, destination);
        let fin = tcp_ipv4(
            client,
            destination,
            1001,
            server_sequence.wrapping_add(1),
            tcp::flags::ACK | tcp::flags::FIN,
            &[],
        );
        let notices = engine
            .ingest(&fin, now + Duration::from_millis(2))
            .unwrap()
            .notices;
        assert!(
            notices
                .iter()
                .any(|notice| *notice == TcpSessionNotice::ClientHalfClosed(key))
        );
        assert_eq!(engine.reap(now + Duration::from_secs(6)), vec![key]);
    }

    #[test]
    fn cancellation_and_capacity_fail_closed() {
        let now = Instant::now();
        let config = TcpSessionConfig {
            max_sessions: 1,
            ..TcpSessionConfig::default()
        };
        let mut engine = TcpSessionEngine::new(config, now).unwrap();
        let first = tcp_ipv4(
            "198.18.0.2:51000".parse().unwrap(),
            "203.0.113.8:443".parse().unwrap(),
            1,
            0,
            tcp::flags::SYN,
            &[],
        );
        engine.ingest(&first, now).unwrap();
        engine.take_transmit();
        let second = tcp_ipv4(
            "198.18.0.2:51001".parse().unwrap(),
            "203.0.113.9:443".parse().unwrap(),
            1,
            0,
            tcp::flags::SYN,
            &[],
        );
        assert_eq!(
            engine.ingest(&second, now).unwrap_err(),
            EngineError::SessionCapacity
        );
        assert!(
            engine
                .take_transmit()
                .iter()
                .map(|packet| parsed_tcp(packet).2.flags())
                .any(|flags| flags & tcp::flags::RST != 0)
        );
    }

    #[test]
    fn rejects_bad_checksum_before_the_stack() {
        let now = Instant::now();
        let mut engine = TcpSessionEngine::new(TcpSessionConfig::default(), now).unwrap();
        let mut syn = tcp_ipv4(
            "198.18.0.2:50000".parse().unwrap(),
            "203.0.113.8:443".parse().unwrap(),
            1,
            0,
            tcp::flags::SYN,
            &[],
        );
        syn[36] ^= 1;
        assert_eq!(
            engine.ingest(&syn, now).unwrap_err(),
            EngineError::Packet(PacketError::InvalidTransportChecksum)
        );
    }
}
