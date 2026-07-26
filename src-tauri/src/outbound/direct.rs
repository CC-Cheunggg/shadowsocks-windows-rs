//! DIRECT outbound constrained to the original physical interface.
//!
//! Binding `IP_UNICAST_IF` (network-byte-order interface index) or
//! `IPV6_UNICAST_IF` (host-byte-order interface index), together with binding
//! the discovered physical source address, keeps these sockets on the original
//! adapter even while Wintun owns split-default capture routes.

use crate::tun::network_change::NetworkEpochToken;
use crate::tun::routes::PhysicalInterface;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, SocketAddrV6, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(windows)]
const IO_POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectError {
    UnsupportedPlatform,
    InvalidBinding(&'static str),
    AddressFamilyUnavailable,
    NetworkChanged,
    Cancelled,
    Timeout,
    Socket {
        operation: &'static str,
        code: Option<i32>,
    },
}

impl DirectError {
    fn socket(operation: &'static str, error: &io::Error) -> Self {
        Self::Socket {
            operation,
            code: error.raw_os_error(),
        }
    }
}

impl fmt::Display for DirectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("DIRECT physical-interface binding is Windows-only")
            }
            Self::InvalidBinding(message) => write!(formatter, "invalid DIRECT binding: {message}"),
            Self::AddressFamilyUnavailable => {
                formatter.write_str("physical interface has no source address for destination")
            }
            Self::NetworkChanged => {
                formatter.write_str("the physical network changed during a DIRECT operation")
            }
            Self::Cancelled => formatter.write_str("DIRECT operation was cancelled"),
            Self::Timeout => formatter.write_str("DIRECT operation timed out"),
            Self::Socket { operation, code } => match code {
                Some(code) => write!(formatter, "DIRECT {operation} failed (OS error {code})"),
                None => write!(formatter, "DIRECT {operation} failed"),
            },
        }
    }
}

impl std::error::Error for DirectError {}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn check(&self) -> Result<(), DirectError> {
        if self.is_cancelled() {
            Err(DirectError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectBinding {
    pub interface_index: u32,
    pub ipv4_source: Option<IpAddr>,
    pub ipv6_source: Option<IpAddr>,
}

impl TryFrom<&PhysicalInterface> for DirectBinding {
    type Error = DirectError;

    fn try_from(interface: &PhysicalInterface) -> Result<Self, Self::Error> {
        if interface.identity.interface_index == 0 {
            return Err(DirectError::InvalidBinding("interface index is zero"));
        }
        let binding = Self {
            interface_index: interface.identity.interface_index,
            ipv4_source: interface.ipv4_source.map(IpAddr::V4),
            ipv6_source: interface.ipv6_source.map(IpAddr::V6),
        };
        binding.validate()?;
        Ok(binding)
    }
}

impl DirectBinding {
    pub fn validate(&self) -> Result<(), DirectError> {
        if self.interface_index == 0 {
            return Err(DirectError::InvalidBinding("interface index is zero"));
        }
        if self.ipv4_source.is_some_and(|address| !address.is_ipv4()) {
            return Err(DirectError::InvalidBinding("IPv4 source has wrong family"));
        }
        if self.ipv6_source.is_some_and(|address| !address.is_ipv6()) {
            return Err(DirectError::InvalidBinding("IPv6 source has wrong family"));
        }
        if self.ipv4_source.is_none() && self.ipv6_source.is_none() {
            return Err(DirectError::InvalidBinding(
                "physical source addresses are unavailable",
            ));
        }
        Ok(())
    }

    fn source_for(&self, destination: SocketAddr) -> Result<IpAddr, DirectError> {
        if destination.ip().is_loopback() {
            return Ok(destination.ip());
        }
        match destination {
            SocketAddr::V4(_) => self.ipv4_source,
            SocketAddr::V6(_) => self.ipv6_source,
        }
        .ok_or(DirectError::AddressFamilyUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowMetadata {
    pub flow_id: u64,
    pub physical_interface_index: u32,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub transport: TransportProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LoopKey {
    transport: TransportProtocol,
    source: SocketAddr,
    destination: SocketAddr,
}

fn normalize_loop_endpoint(endpoint: SocketAddr) -> SocketAddr {
    match endpoint {
        SocketAddr::V4(_) => endpoint,
        SocketAddr::V6(endpoint) => {
            SocketAddr::V6(SocketAddrV6::new(*endpoint.ip(), endpoint.port(), 0, 0))
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct LoopGuard {
    inner: Arc<Mutex<HashMap<LoopKey, usize>>>,
}

impl LoopGuard {
    /// A captured packet whose source endpoint matches an active DIRECT socket
    /// is an outbound-recursion candidate and must be dropped, never routed
    /// through DIRECT a second time.
    pub fn is_direct_socket_source(&self, source: SocketAddr) -> bool {
        let source = normalize_loop_endpoint(source);
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .any(|key| key.source == source)
    }

    /// Exact recursion check used by the packet driver. Protocol and both
    /// endpoints are part of the identity so an unrelated flow that happens
    /// to reuse one local endpoint is not misclassified.
    pub fn is_direct_flow(
        &self,
        transport: TransportProtocol,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> bool {
        let source = normalize_loop_endpoint(source);
        let destination = normalize_loop_endpoint(destination);
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&LoopKey {
                transport,
                source,
                destination,
            })
    }

    pub fn active_endpoints(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    fn register(
        &self,
        transport: TransportProtocol,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> LoopRegistration {
        let key = LoopKey {
            transport,
            source: normalize_loop_endpoint(source),
            destination: normalize_loop_endpoint(destination),
        };
        let mut entries = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *entries.entry(key).or_insert(0) += 1;
        LoopRegistration {
            guard: self.clone(),
            key,
        }
    }
}

#[derive(Debug)]
struct LoopRegistration {
    guard: LoopGuard,
    key: LoopKey,
}

impl Drop for LoopRegistration {
    fn drop(&mut self) {
        let mut entries = self
            .guard
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = entries.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                entries.remove(&self.key);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirectOutbound {
    binding: DirectBinding,
    endpoint_bindings: Arc<HashMap<SocketAddr, DirectBinding>>,
    loop_guard: LoopGuard,
    network_epoch: NetworkEpochToken,
}

impl DirectOutbound {
    pub fn new(binding: DirectBinding, loop_guard: LoopGuard) -> Result<Self, DirectError> {
        binding.validate()?;
        Ok(Self {
            binding,
            endpoint_bindings: Arc::new(HashMap::new()),
            loop_guard,
            network_epoch: NetworkEpochToken::new(),
        })
    }

    pub fn binding(&self) -> &DirectBinding {
        &self.binding
    }

    pub fn loop_guard(&self) -> &LoopGuard {
        &self.loop_guard
    }

    pub fn with_network_epoch(mut self, network_epoch: NetworkEpochToken) -> Self {
        self.network_epoch = network_epoch;
        self
    }

    /// Installs exact endpoint-specific bindings selected from the pre-capture
    /// `GetBestRoute2` result. This is used for a confirmed intranet system
    /// proxy that may live on a different physical adapter than the ordinary
    /// default route.
    pub fn with_endpoint_bindings(
        mut self,
        bindings: impl IntoIterator<Item = (SocketAddr, DirectBinding)>,
    ) -> Result<Self, DirectError> {
        let mut checked = HashMap::new();
        for (endpoint, binding) in bindings {
            binding.validate()?;
            binding.source_for(endpoint)?;
            checked.insert(endpoint, binding);
        }
        self.endpoint_bindings = Arc::new(checked);
        Ok(self)
    }

    fn binding_for(&self, destination: SocketAddr) -> &DirectBinding {
        self.endpoint_bindings
            .get(&destination)
            .unwrap_or(&self.binding)
    }

    pub fn connect_tcp(
        &self,
        flow_id: u64,
        destination: SocketAddr,
        timeout: Duration,
        cancellation: &CancellationToken,
    ) -> Result<DirectTcp, DirectError> {
        cancellation.check()?;
        check_network_epoch(&self.network_epoch)?;
        if timeout.is_zero() {
            return Err(DirectError::Timeout);
        }
        let binding = self.binding_for(destination).clone();
        let guard = self.loop_guard.clone();
        let (stream, local_addr, registration) = platform::connect_tcp(
            &binding,
            destination,
            timeout,
            cancellation,
            &self.network_epoch,
            move |local_addr| guard.register(TransportProtocol::Tcp, local_addr, destination),
        )?;
        Ok(DirectTcp {
            stream,
            metadata: FlowMetadata {
                flow_id,
                physical_interface_index: binding.interface_index,
                local_addr,
                remote_addr: destination,
                transport: TransportProtocol::Tcp,
            },
            network_epoch: self.network_epoch.clone(),
            _registration: registration,
        })
    }

    pub fn associate_udp(
        &self,
        flow_id: u64,
        destination: SocketAddr,
        cancellation: &CancellationToken,
    ) -> Result<DirectUdp, DirectError> {
        cancellation.check()?;
        check_network_epoch(&self.network_epoch)?;
        let binding = self.binding_for(destination).clone();
        let guard = self.loop_guard.clone();
        let (socket, local_addr, registration) = platform::connect_udp(
            &binding,
            destination,
            &self.network_epoch,
            move |local_addr| guard.register(TransportProtocol::Udp, local_addr, destination),
        )?;
        Ok(DirectUdp {
            socket,
            metadata: FlowMetadata {
                flow_id,
                physical_interface_index: binding.interface_index,
                local_addr,
                remote_addr: destination,
                transport: TransportProtocol::Udp,
            },
            network_epoch: self.network_epoch.clone(),
            _registration: registration,
        })
    }
}

fn check_network_epoch(network_epoch: &NetworkEpochToken) -> Result<(), DirectError> {
    if network_epoch.is_invalid() {
        Err(DirectError::NetworkChanged)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub struct DirectTcp {
    stream: TcpStream,
    metadata: FlowMetadata,
    network_epoch: NetworkEpochToken,
    _registration: LoopRegistration,
}

impl DirectTcp {
    pub fn metadata(&self) -> &FlowMetadata {
        &self.metadata
    }

    pub fn read_cancellable(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<usize, DirectError> {
        loop {
            cancellation.check()?;
            check_network_epoch(&self.network_epoch)?;
            if Instant::now() >= deadline {
                return Err(DirectError::Timeout);
            }
            match self.stream.read(buffer) {
                Ok(size) => return Ok(size),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(DirectError::socket("TCP read", &error)),
            }
        }
    }

    pub fn write_all_cancellable(
        &mut self,
        mut buffer: &[u8],
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(), DirectError> {
        while !buffer.is_empty() {
            cancellation.check()?;
            check_network_epoch(&self.network_epoch)?;
            if Instant::now() >= deadline {
                return Err(DirectError::Timeout);
            }
            match self.stream.write(buffer) {
                Ok(0) => {
                    return Err(DirectError::Socket {
                        operation: "TCP write returned EOF",
                        code: None,
                    });
                }
                Ok(written) => buffer = &buffer[written..],
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(DirectError::socket("TCP write", &error)),
            }
        }
        Ok(())
    }

    pub fn shutdown(&self, direction: Shutdown) -> Result<(), DirectError> {
        self.stream
            .shutdown(direction)
            .map_err(|error| DirectError::socket("TCP shutdown", &error))
    }
}

#[derive(Debug)]
pub struct DirectUdp {
    socket: UdpSocket,
    metadata: FlowMetadata,
    network_epoch: NetworkEpochToken,
    _registration: LoopRegistration,
}

impl DirectUdp {
    pub fn metadata(&self) -> &FlowMetadata {
        &self.metadata
    }

    pub fn send_cancellable(
        &self,
        payload: &[u8],
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<usize, DirectError> {
        loop {
            cancellation.check()?;
            check_network_epoch(&self.network_epoch)?;
            if Instant::now() >= deadline {
                return Err(DirectError::Timeout);
            }
            match self.socket.send(payload) {
                Ok(size) => return Ok(size),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(DirectError::socket("UDP send", &error)),
            }
        }
    }

    pub fn recv_cancellable(
        &self,
        payload: &mut [u8],
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<usize, DirectError> {
        loop {
            cancellation.check()?;
            check_network_epoch(&self.network_epoch)?;
            if Instant::now() >= deadline {
                return Err(DirectError::Timeout);
            }
            match self.socket.recv(payload) {
                Ok(size) => return Ok(size),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(DirectError::socket("UDP receive", &error)),
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{
        CancellationToken, DirectBinding, DirectError, IO_POLL_INTERVAL, NetworkEpochToken,
        SocketAddr, TcpStream, UdpSocket, check_network_epoch,
    };
    use std::ffi::c_char;
    use std::mem::{self, MaybeUninit};
    use std::net::{SocketAddrV4, SocketAddrV6};
    use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Networking::WinSock::WSADATA;

    type Socket = usize;
    const INVALID_SOCKET: Socket = !0;
    const SOCKET_ERROR: i32 = -1;
    const AF_INET: i32 = 2;
    const AF_INET6: i32 = 23;
    const SOCK_STREAM: i32 = 1;
    const IPPROTO_IP: i32 = 0;
    const IPPROTO_TCP: i32 = 6;
    const IPPROTO_IPV6: i32 = 41;
    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;
    const SOL_SOCKET: i32 = 0xffff;
    const SO_ERROR: i32 = 0x1007;
    const FIONBIO: i32 = 0x8004_667e_u32 as i32;
    const WSAEWOULDBLOCK: i32 = 10035;
    const WSAEINPROGRESS: i32 = 10036;
    const WSAEALREADY: i32 = 10037;
    const POLLERR: i16 = 0x0001;
    const POLLHUP: i16 = 0x0002;
    const POLLWRNORM: i16 = 0x0010;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockAddr {
        family: u16,
        data: [u8; 14],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockAddrIn {
        family: u16,
        port: u16,
        address: u32,
        zero: [u8; 8],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockAddrIn6 {
        family: u16,
        port: u16,
        flow_info: u32,
        address: [u8; 16],
        scope_id: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union SockAddrStorage {
        ipv4: SockAddrIn,
        ipv6: SockAddrIn6,
        alignment: [u64; 16],
    }

    #[repr(C)]
    struct WsaPollFd {
        socket: Socket,
        events: i16,
        returned_events: i16,
    }

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAStartup(version: u16, data: *mut WSADATA) -> i32;
        fn WSAGetLastError() -> i32;
        fn socket(address_family: i32, socket_type: i32, protocol: i32) -> Socket;
        fn closesocket(socket: Socket) -> i32;
        fn bind(socket: Socket, address: *const SockAddr, address_length: i32) -> i32;
        fn connect(socket: Socket, address: *const SockAddr, address_length: i32) -> i32;
        fn getsockname(socket: Socket, address: *mut SockAddr, address_length: *mut i32) -> i32;
        fn setsockopt(
            socket: Socket,
            level: i32,
            option_name: i32,
            option_value: *const c_char,
            option_length: i32,
        ) -> i32;
        fn getsockopt(
            socket: Socket,
            level: i32,
            option_name: i32,
            option_value: *mut c_char,
            option_length: *mut i32,
        ) -> i32;
        fn ioctlsocket(socket: Socket, command: i32, argument: *mut u32) -> i32;
        fn WSAPoll(descriptors: *mut WsaPollFd, count: u32, timeout_ms: i32) -> i32;
    }

    static WINSOCK: OnceLock<Result<(), i32>> = OnceLock::new();

    pub(super) fn connect_tcp<R>(
        binding: &DirectBinding,
        destination: SocketAddr,
        timeout: Duration,
        cancellation: &CancellationToken,
        network_epoch: &NetworkEpochToken,
        on_bound: impl FnOnce(SocketAddr) -> R,
    ) -> Result<(TcpStream, SocketAddr, R), DirectError> {
        initialize_winsock()?;
        check_network_epoch(network_epoch)?;
        let source = binding.source_for(destination)?;
        let family = if destination.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        // SAFETY: WSAStartup succeeded and parameters are valid constants.
        let raw = unsafe { socket(family, SOCK_STREAM, IPPROTO_TCP) };
        if raw == INVALID_SOCKET {
            return Err(last_socket_error("TCP socket creation"));
        }
        let mut owned = RawSocketGuard(Some(raw));

        if !destination.ip().is_loopback() {
            bind_interface(raw, binding.interface_index, destination.is_ipv6())?;
        }
        let source = SocketAddr::new(source, 0);
        call_sockaddr(source, binding.interface_index, |address, length| {
            // SAFETY: socket is live and address points to the matching
            // sockaddr representation for `length`.
            let result = unsafe { bind(raw, address, length) };
            if result == SOCKET_ERROR {
                Err(last_socket_error("TCP source bind"))
            } else {
                Ok(())
            }
        })?;
        // Port zero is resolved by bind. Register the complete tuple before
        // connect can emit the first SYN.
        let local_addr = query_local_addr(raw)?;
        let registration = on_bound(local_addr);
        check_network_epoch(network_epoch)?;

        set_nonblocking(raw, true)?;
        let connect_result =
            call_sockaddr(destination, binding.interface_index, |address, length| {
                // SAFETY: socket is live and address representation is valid.
                let result = unsafe { connect(raw, address, length) };
                if result == 0 {
                    Ok(true)
                } else {
                    // SAFETY: WSAGetLastError has no preconditions.
                    let code = unsafe { WSAGetLastError() };
                    if matches!(code, WSAEWOULDBLOCK | WSAEINPROGRESS | WSAEALREADY) {
                        Ok(false)
                    } else {
                        Err(DirectError::Socket {
                            operation: "TCP connect",
                            code: Some(code),
                        })
                    }
                }
            })?;

        if !connect_result {
            wait_for_connect(raw, timeout, cancellation, network_epoch)?;
        }
        set_nonblocking(raw, false)?;
        let raw = owned.0.take().expect("raw socket guard lost ownership");
        // SAFETY: ownership is transferred exactly once from RawSocketGuard.
        let stream = unsafe { TcpStream::from_raw_socket(raw as RawSocket) };
        stream
            .set_read_timeout(Some(IO_POLL_INTERVAL))
            .map_err(|error| DirectError::socket("TCP read-timeout setup", &error))?;
        stream
            .set_write_timeout(Some(IO_POLL_INTERVAL))
            .map_err(|error| DirectError::socket("TCP write-timeout setup", &error))?;
        Ok((stream, local_addr, registration))
    }

    pub(super) fn connect_udp<R>(
        binding: &DirectBinding,
        destination: SocketAddr,
        network_epoch: &NetworkEpochToken,
        on_bound: impl FnOnce(SocketAddr) -> R,
    ) -> Result<(UdpSocket, SocketAddr, R), DirectError> {
        check_network_epoch(network_epoch)?;
        let source = binding.source_for(destination)?;
        let socket = UdpSocket::bind(SocketAddr::new(source, 0))
            .map_err(|error| DirectError::socket("UDP source bind", &error))?;
        if !destination.ip().is_loopback() {
            bind_interface(
                socket.as_raw_socket() as Socket,
                binding.interface_index,
                destination.is_ipv6(),
            )?;
        }
        let local_addr = socket
            .local_addr()
            .map_err(|error| DirectError::socket("UDP local address query", &error))?;
        let registration = on_bound(local_addr);
        check_network_epoch(network_epoch)?;
        socket
            .connect(destination)
            .map_err(|error| DirectError::socket("UDP connect", &error))?;
        socket
            .set_read_timeout(Some(IO_POLL_INTERVAL))
            .map_err(|error| DirectError::socket("UDP read-timeout setup", &error))?;
        socket
            .set_write_timeout(Some(IO_POLL_INTERVAL))
            .map_err(|error| DirectError::socket("UDP write-timeout setup", &error))?;
        Ok((socket, local_addr, registration))
    }

    fn initialize_winsock() -> Result<(), DirectError> {
        let result = WINSOCK.get_or_init(|| {
            let mut data = MaybeUninit::<WSADATA>::zeroed();
            // MAKEWORD(2, 2) == 0x0202.
            // SAFETY: data points to writable WSADATA storage.
            let code = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
            if code == 0 { Ok(()) } else { Err(code) }
        });
        result.map_err(|code| DirectError::Socket {
            operation: "Winsock initialization",
            code: Some(code),
        })
    }

    fn bind_interface(socket: Socket, interface_index: u32, ipv6: bool) -> Result<(), DirectError> {
        // Windows documents IP_UNICAST_IF as a network-byte-order ULONG. Its
        // IPv6 counterpart takes a host-byte-order interface index.
        let option_value = if ipv6 {
            interface_index
        } else {
            interface_index.to_be()
        };
        let (level, option) = if ipv6 {
            (IPPROTO_IPV6, IPV6_UNICAST_IF)
        } else {
            (IPPROTO_IP, IP_UNICAST_IF)
        };
        // SAFETY: option_value points to a u32 of the documented size.
        let result = unsafe {
            setsockopt(
                socket,
                level,
                option,
                (&option_value as *const u32).cast::<c_char>(),
                mem::size_of::<u32>() as i32,
            )
        };
        if result == SOCKET_ERROR {
            Err(last_socket_error("physical interface binding"))
        } else {
            Ok(())
        }
    }

    fn query_local_addr(socket: Socket) -> Result<SocketAddr, DirectError> {
        let mut storage = MaybeUninit::<SockAddrStorage>::zeroed();
        let mut length = mem::size_of::<SockAddrStorage>() as i32;
        // SAFETY: storage is large and aligned enough for either Windows
        // sockaddr representation and `length` is a valid writable value.
        if unsafe { getsockname(socket, storage.as_mut_ptr().cast::<SockAddr>(), &mut length) }
            == SOCKET_ERROR
        {
            return Err(last_socket_error("local address query"));
        }
        // SAFETY: getsockname initialized a sockaddr and both variants begin
        // with the same family field.
        let storage = unsafe { storage.assume_init() };
        // SAFETY: reading the common first field is valid for either variant.
        let family = unsafe { storage.ipv4.family };
        match i32::from(family) {
            AF_INET if length as usize >= mem::size_of::<SockAddrIn>() => {
                // SAFETY: the reported family and length select this variant.
                let address = unsafe { storage.ipv4 };
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    address.address.to_ne_bytes().into(),
                    u16::from_be(address.port),
                )))
            }
            AF_INET6 if length as usize >= mem::size_of::<SockAddrIn6>() => {
                // SAFETY: the reported family and length select this variant.
                let address = unsafe { storage.ipv6 };
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    address.address.into(),
                    u16::from_be(address.port),
                    address.flow_info,
                    address.scope_id,
                )))
            }
            _ => Err(DirectError::Socket {
                operation: "local address query",
                code: None,
            }),
        }
    }

    fn set_nonblocking(socket: Socket, enabled: bool) -> Result<(), DirectError> {
        let mut value = u32::from(enabled);
        // SAFETY: socket is live and value is writable.
        if unsafe { ioctlsocket(socket, FIONBIO, &mut value) } == SOCKET_ERROR {
            Err(last_socket_error("nonblocking mode change"))
        } else {
            Ok(())
        }
    }

    fn wait_for_connect(
        socket: Socket,
        timeout: Duration,
        cancellation: &CancellationToken,
        network_epoch: &NetworkEpochToken,
    ) -> Result<(), DirectError> {
        let deadline = Instant::now() + timeout;
        loop {
            cancellation.check()?;
            check_network_epoch(network_epoch)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(DirectError::Timeout);
            }
            let wait = remaining.min(Duration::from_millis(100));
            let mut descriptor = WsaPollFd {
                socket,
                events: POLLWRNORM,
                returned_events: 0,
            };
            // SAFETY: descriptor points to one writable WSAPOLLFD.
            let result = unsafe {
                WSAPoll(
                    &mut descriptor,
                    1,
                    i32::try_from(wait.as_millis()).unwrap_or(100),
                )
            };
            if result == SOCKET_ERROR {
                return Err(last_socket_error("TCP connect poll"));
            }
            if result == 0 {
                continue;
            }
            if descriptor.returned_events & (POLLWRNORM | POLLERR | POLLHUP) != 0 {
                let mut socket_error = 0_i32;
                let mut length = mem::size_of::<i32>() as i32;
                // SAFETY: output pointers describe a writable i32.
                if unsafe {
                    getsockopt(
                        socket,
                        SOL_SOCKET,
                        SO_ERROR,
                        (&mut socket_error as *mut i32).cast::<c_char>(),
                        &mut length,
                    )
                } == SOCKET_ERROR
                {
                    return Err(last_socket_error("TCP connect result"));
                }
                return if socket_error == 0 {
                    Ok(())
                } else {
                    Err(DirectError::Socket {
                        operation: "TCP connect",
                        code: Some(socket_error),
                    })
                };
            }
        }
    }

    fn call_sockaddr<T>(
        address: SocketAddr,
        interface_index: u32,
        call: impl FnOnce(*const SockAddr, i32) -> Result<T, DirectError>,
    ) -> Result<T, DirectError> {
        match address {
            SocketAddr::V4(address) => {
                let storage = sockaddr_v4(address);
                call(
                    (&storage as *const SockAddrIn).cast::<SockAddr>(),
                    mem::size_of::<SockAddrIn>() as i32,
                )
            }
            SocketAddr::V6(address) => {
                let storage = sockaddr_v6(address, interface_index);
                call(
                    (&storage as *const SockAddrIn6).cast::<SockAddr>(),
                    mem::size_of::<SockAddrIn6>() as i32,
                )
            }
        }
    }

    fn sockaddr_v4(address: SocketAddrV4) -> SockAddrIn {
        SockAddrIn {
            family: AF_INET as u16,
            port: address.port().to_be(),
            // Native integer whose memory representation is the address octets.
            address: u32::from_ne_bytes(address.ip().octets()),
            zero: [0; 8],
        }
    }

    fn sockaddr_v6(address: SocketAddrV6, interface_index: u32) -> SockAddrIn6 {
        let scope_id = if address.scope_id() != 0 {
            address.scope_id()
        } else if address.ip().is_unicast_link_local() {
            interface_index
        } else {
            0
        };
        SockAddrIn6 {
            family: AF_INET6 as u16,
            port: address.port().to_be(),
            flow_info: address.flowinfo(),
            address: address.ip().octets(),
            scope_id,
        }
    }

    fn last_socket_error(operation: &'static str) -> DirectError {
        DirectError::Socket {
            operation,
            // SAFETY: WSAGetLastError has no preconditions.
            code: Some(unsafe { WSAGetLastError() }),
        }
    }

    struct RawSocketGuard(Option<Socket>);

    impl Drop for RawSocketGuard {
        fn drop(&mut self) {
            if let Some(socket) = self.0.take() {
                // SAFETY: guard owns the still-live socket.
                unsafe {
                    closesocket(socket);
                }
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{
        CancellationToken, DirectBinding, DirectError, NetworkEpochToken, SocketAddr, TcpStream,
        UdpSocket,
    };
    use std::time::Duration;

    pub(super) fn connect_tcp<R>(
        _binding: &DirectBinding,
        _destination: SocketAddr,
        _timeout: Duration,
        _cancellation: &CancellationToken,
        _network_epoch: &NetworkEpochToken,
        _on_bound: impl FnOnce(SocketAddr) -> R,
    ) -> Result<(TcpStream, SocketAddr, R), DirectError> {
        Err(DirectError::UnsupportedPlatform)
    }

    pub(super) fn connect_udp<R>(
        _binding: &DirectBinding,
        _destination: SocketAddr,
        _network_epoch: &NetworkEpochToken,
        _on_bound: impl FnOnce(SocketAddr) -> R,
    ) -> Result<(UdpSocket, SocketAddr, R), DirectError> {
        Err(DirectError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> DirectBinding {
        DirectBinding {
            interface_index: 7,
            ipv4_source: Some("192.0.2.10".parse().unwrap()),
            ipv6_source: Some("2001:db8::10".parse().unwrap()),
        }
    }

    #[test]
    fn binding_requires_matching_source_families() {
        assert!(binding().validate().is_ok());
        assert_eq!(
            binding().source_for("127.0.0.1:8080".parse().unwrap()),
            Ok("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            binding().source_for("[::1]:8080".parse().unwrap()),
            Ok("::1".parse().unwrap())
        );
        let mut invalid = binding();
        invalid.ipv4_source = Some("2001:db8::1".parse().unwrap());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn exact_endpoint_can_use_a_different_physical_binding() {
        let endpoint = "10.0.0.20:8080".parse().unwrap();
        let override_binding = DirectBinding {
            interface_index: 9,
            ipv4_source: Some("10.0.0.10".parse().unwrap()),
            ipv6_source: None,
        };
        let outbound = DirectOutbound::new(binding(), LoopGuard::default())
            .unwrap()
            .with_endpoint_bindings([(endpoint, override_binding.clone())])
            .unwrap();
        assert_eq!(outbound.binding_for(endpoint), &override_binding);
        assert_eq!(
            outbound.binding_for("10.0.0.20:8443".parse().unwrap()),
            outbound.binding()
        );
    }

    #[test]
    fn cancellation_is_sticky_and_safe_to_clone() {
        let token = CancellationToken::default();
        let clone = token.clone();
        assert!(!clone.is_cancelled());
        token.cancel();
        assert!(clone.is_cancelled());
        assert_eq!(clone.check(), Err(DirectError::Cancelled));
    }

    #[test]
    fn invalid_network_epoch_rejects_new_direct_sockets_before_platform_io() {
        let epoch = NetworkEpochToken::new();
        let outbound = DirectOutbound::new(binding(), LoopGuard::default())
            .unwrap()
            .with_network_epoch(epoch.clone());
        assert!(epoch.invalidate());
        assert_eq!(
            outbound
                .connect_tcp(
                    1,
                    "192.0.2.20:443".parse().unwrap(),
                    Duration::from_secs(1),
                    &CancellationToken::default(),
                )
                .unwrap_err(),
            DirectError::NetworkChanged
        );
        assert_eq!(
            outbound
                .associate_udp(
                    2,
                    "192.0.2.20:53".parse().unwrap(),
                    &CancellationToken::default(),
                )
                .unwrap_err(),
            DirectError::NetworkChanged
        );
    }

    #[test]
    fn loop_guard_registers_and_releases_endpoints() {
        let guard = LoopGuard::default();
        let source = "192.0.2.10:49152".parse().unwrap();
        let destination = "198.51.100.20:443".parse().unwrap();
        let first = guard.register(TransportProtocol::Tcp, source, destination);
        let second = guard.register(TransportProtocol::Tcp, source, destination);
        assert!(guard.is_direct_socket_source(source));
        assert!(guard.is_direct_flow(TransportProtocol::Tcp, source, destination));
        assert!(!guard.is_direct_flow(TransportProtocol::Udp, source, destination));
        assert!(!guard.is_direct_flow(
            TransportProtocol::Tcp,
            source,
            "198.51.100.21:443".parse().unwrap()
        ));
        assert_eq!(guard.active_endpoints(), 1);
        drop(first);
        assert!(guard.is_direct_socket_source(source));
        drop(second);
        assert!(!guard.is_direct_socket_source(source));
    }

    #[test]
    fn loop_guard_ignores_ipv6_scope_and_flowinfo_from_getsockname() {
        let guard = LoopGuard::default();
        let registered_source = SocketAddr::V6(SocketAddrV6::new(
            "fe80::10".parse().unwrap(),
            49_152,
            123,
            7,
        ));
        let registered_destination =
            SocketAddr::V6(SocketAddrV6::new("fe80::20".parse().unwrap(), 443, 456, 7));
        let packet_source = "[fe80::10]:49152".parse().unwrap();
        let packet_destination = "[fe80::20]:443".parse().unwrap();
        let _registration = guard.register(
            TransportProtocol::Tcp,
            registered_source,
            registered_destination,
        );

        assert!(guard.is_direct_socket_source(packet_source));
        assert!(guard.is_direct_flow(TransportProtocol::Tcp, packet_source, packet_destination));
        assert_eq!(guard.active_endpoints(), 1);
    }

    #[test]
    fn direct_errors_do_not_expose_destination_or_payload() {
        let error = DirectError::Socket {
            operation: "TCP connect",
            code: Some(10061),
        }
        .to_string();
        assert_eq!(error, "DIRECT TCP connect failed (OS error 10061)");
        assert!(!error.contains("192.0.2.1"));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_transport_fails_closed() {
        let outbound = DirectOutbound::new(binding(), LoopGuard::default()).unwrap();
        let error = outbound
            .connect_tcp(
                1,
                "192.0.2.20:443".parse().unwrap(),
                Duration::from_secs(1),
                &CancellationToken::default(),
            )
            .unwrap_err();
        assert_eq!(error, DirectError::UnsupportedPlatform);
    }
}
