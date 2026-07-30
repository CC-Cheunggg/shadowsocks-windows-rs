//! Privileged Windows-only Wintun ring smoke test.
//!
//! This executable owns only two RFC 5737 `/32` routes and a TEST-NET source
//! address. It never installs a default route or changes DNS.

#[cfg(not(windows))]
fn main() {
    eprintln!("wintun_smoke is supported only on Windows");
}

#[cfg(windows)]
mod windows_smoke {
    use shadowsocks_windows_rs_lib::packet::IpPacket;
    use shadowsocks_windows_rs_lib::packet::builder::udp_packet;
    use shadowsocks_windows_rs_lib::packet::checksum::internet_checksum;
    use shadowsocks_windows_rs_lib::packet::tcp::{self, TcpPacket, flags};
    use shadowsocks_windows_rs_lib::packet::udp::UdpPacket;
    use shadowsocks_windows_rs_lib::tun::routes::{
        InterfaceAddress, InterfaceIdentity, OwnedRoute, RouteTransaction, SystemNetworkSnapshot,
        find_interface_by_alias, resolve_interface_identity, restore_isolated,
    };
    use shadowsocks_windows_rs_lib::tun::wintun::{Adapter, MIN_RING_CAPACITY, Session, Wintun};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    const TUN_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const UDP_DESTINATION: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
    const TCP_DESTINATION: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 3);
    const UDP_PORT: u16 = 39_001;
    const TCP_PORT: u16 = 39_002;
    const UDP_PROBE: &[u8] = b"sswr-wintun-udp-probe";
    const UDP_RESPONSE: &[u8] = b"sswr-wintun-udp-response";
    const CAPTURE_TIMEOUT: Duration = Duration::from_secs(8);

    type SmokeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    pub fn run() -> SmokeResult<()> {
        let adapter_name = adapter_name()?;
        if std::env::args().any(|argument| argument == "--cleanup-only") {
            cleanup_by_name(&adapter_name)?;
            println!("Wintun smoke cleanup completed for {adapter_name}");
            return Ok(());
        }

        let snapshot_before = SystemNetworkSnapshot::capture()?;
        let defaults_before = snapshot_before.default_route_fingerprint()?;
        println!(
            "Captured pre-test network snapshot at {}",
            snapshot_before.captured_unix_ms
        );

        let wintun = Wintun::load()?;
        let adapter = wintun.create_adapter_with_type(&adapter_name, "SSWR Smoke")?;
        let interface_index = adapter.interface_index()?;
        let interface = resolve_interface_identity(interface_index)?;
        println!("Created temporary adapter {adapter_name} (ifIndex {interface_index})");
        let session = adapter.start_session(MIN_RING_CAPACITY)?;

        let mut network = IsolatedNetwork::new();
        if let Err(error) = network.install(interface) {
            cleanup_network(network, session, adapter)?;
            return Err(error);
        }
        let smoke_result = run_packet_checks(&session);

        cleanup_network(network, session, adapter)?;

        let snapshot_after = SystemNetworkSnapshot::capture()?;
        let defaults_after = snapshot_after.default_route_fingerprint()?;
        if defaults_before != defaults_after {
            return Err("default-route set changed during isolated Wintun smoke test".into());
        }
        println!(
            "Captured post-test network snapshot at {}; default routes unchanged",
            snapshot_after.captured_unix_ms
        );

        smoke_result?;
        println!("Wintun receive/send ring UDP and TCP smoke checks passed");
        Ok(())
    }

    fn run_packet_checks(session: &Session) -> SmokeResult<()> {
        udp_round_trip(session)?;
        tcp_handshake(session)?;
        Ok(())
    }

    fn udp_round_trip(session: &Session) -> SmokeResult<()> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_read_timeout(Some(CAPTURE_TIMEOUT))?;
        socket.send_to(UDP_PROBE, (UDP_DESTINATION, UDP_PORT))?;

        let captured = capture_matching(session, CAPTURE_TIMEOUT, |bytes| {
            let Ok(IpPacket::V4(ip)) = IpPacket::parse(bytes) else {
                return false;
            };
            if ip.destination() != UDP_DESTINATION || ip.protocol() != 17 {
                return false;
            }
            let Ok(udp) = UdpPacket::parse(ip.payload()) else {
                return false;
            };
            udp.destination_port() == UDP_PORT && udp.payload() == UDP_PROBE
        })?;
        let IpPacket::V4(ip) = IpPacket::parse(&captured)? else {
            return Err("captured UDP probe was not IPv4".into());
        };
        let udp = UdpPacket::parse(ip.payload())?;
        udp.verify_ipv4_checksum(ip.source(), ip.destination())?;
        if ip.source() != TUN_ADDRESS {
            return Err(format!("UDP probe used unexpected source {}", ip.source()).into());
        }

        let response = udp_packet(
            SocketAddr::from((UDP_DESTINATION, UDP_PORT)),
            SocketAddr::from((ip.source(), udp.source_port())),
            UDP_RESPONSE,
            0x5353,
        )?;
        session.send(&response)?;

        let mut payload = [0_u8; 128];
        let (length, source) = socket.recv_from(&mut payload)?;
        if source != SocketAddr::from((UDP_DESTINATION, UDP_PORT))
            || &payload[..length] != UDP_RESPONSE
        {
            return Err("injected UDP response did not reach the originating socket".into());
        }
        println!("UDP probe captured and injected response reached the local socket");
        Ok(())
    }

    fn tcp_handshake(session: &Session) -> SmokeResult<()> {
        let destination = SocketAddr::from((TCP_DESTINATION, TCP_PORT));
        let (connection_tx, connection_rx) = mpsc::sync_channel(1);
        let connector = std::thread::spawn(move || {
            let result = TcpStream::connect_timeout(&destination, CAPTURE_TIMEOUT);
            let _ = connection_tx.send(result);
        });
        let mut connector = ConnectorGuard(Some(connector));

        let captured_syn = capture_matching(session, CAPTURE_TIMEOUT, |bytes| {
            let Ok(IpPacket::V4(ip)) = IpPacket::parse(bytes) else {
                return false;
            };
            if ip.destination() != TCP_DESTINATION || ip.protocol() != 6 {
                return false;
            }
            let Ok(tcp) = TcpPacket::parse(ip.payload()) else {
                return false;
            };
            tcp.destination_port() == TCP_PORT
                && tcp.flags() & flags::SYN != 0
                && tcp.flags() & flags::ACK == 0
        })?;
        let IpPacket::V4(ip) = IpPacket::parse(&captured_syn)? else {
            return Err("captured TCP SYN was not IPv4".into());
        };
        let syn = TcpPacket::parse(ip.payload())?;
        syn.verify_ipv4_checksum(ip.source(), ip.destination())?;
        if ip.source() != TUN_ADDRESS {
            return Err(format!("TCP SYN used unexpected source {}", ip.source()).into());
        }

        let server_sequence = 0x5353_0001;
        let syn_ack = tcp_ipv4_packet(
            TCP_DESTINATION,
            ip.source(),
            TCP_PORT,
            syn.source_port(),
            server_sequence,
            syn.sequence_number().wrapping_add(1),
            flags::SYN | flags::ACK,
        );
        session.send(&syn_ack)?;

        let captured_ack = capture_matching(session, CAPTURE_TIMEOUT, |bytes| {
            let Ok(IpPacket::V4(ip)) = IpPacket::parse(bytes) else {
                return false;
            };
            if ip.source() != TUN_ADDRESS
                || ip.destination() != TCP_DESTINATION
                || ip.protocol() != 6
            {
                return false;
            }
            let Ok(tcp) = TcpPacket::parse(ip.payload()) else {
                return false;
            };
            tcp.destination_port() == TCP_PORT
                && tcp.source_port() == syn.source_port()
                && tcp.flags() & flags::ACK != 0
                && tcp.flags() & flags::SYN == 0
                && tcp.acknowledgment_number() == server_sequence.wrapping_add(1)
        })?;
        let IpPacket::V4(ack_ip) = IpPacket::parse(&captured_ack)? else {
            return Err("captured TCP ACK was not IPv4".into());
        };
        TcpPacket::parse(ack_ip.payload())?
            .verify_ipv4_checksum(ack_ip.source(), ack_ip.destination())?;

        let stream_result = connection_rx
            .recv_timeout(CAPTURE_TIMEOUT)
            .map_err(|_| "TCP connect did not complete after SYN-ACK injection")?;
        let stream = stream_result?;
        drop(stream);
        connector
            .0
            .take()
            .expect("connector handle is present")
            .join()
            .map_err(|_| "TCP connector thread panicked")?;
        println!("TCP SYN captured, SYN-ACK injected, and client ACK captured");
        Ok(())
    }

    fn capture_matching(
        session: &Session,
        timeout: Duration,
        predicate: impl Fn(&[u8]) -> bool,
    ) -> SmokeResult<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            while let Some(packet) = session.receive()? {
                if predicate(packet.as_ref()) {
                    return Ok(packet.as_ref().to_vec());
                }
            }

            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err("timed out waiting for matching Wintun packet".into());
            };
            if !session.wait_for_read(remaining)? {
                return Err("timed out waiting for Wintun receive ring".into());
            }
        }
    }

    fn tcp_ipv4_packet(
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgment: u32,
        tcp_flags: u16,
    ) -> Vec<u8> {
        let mut segment = vec![0_u8; 20];
        segment[0..2].copy_from_slice(&source_port.to_be_bytes());
        segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
        segment[4..8].copy_from_slice(&sequence.to_be_bytes());
        segment[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
        segment[12] = 5 << 4;
        segment[13] = tcp_flags as u8;
        segment[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        let transport_checksum = tcp::checksum_ipv4(source_ip, destination_ip, &segment);
        segment[16..18].copy_from_slice(&transport_checksum.to_be_bytes());

        let total_length = 20 + segment.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x5354_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source_ip.octets());
        packet[16..20].copy_from_slice(&destination_ip.octets());
        packet[20..].copy_from_slice(&segment);
        let header_checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    struct IsolatedNetwork {
        transaction: Option<RouteTransaction>,
    }

    struct ConnectorGuard(Option<JoinHandle<()>>);

    impl Drop for ConnectorGuard {
        fn drop(&mut self) {
            if let Some(handle) = self.0.take() {
                let _ = handle.join();
            }
        }
    }

    impl IsolatedNetwork {
        fn new() -> Self {
            Self { transaction: None }
        }

        fn install(&mut self, interface: InterfaceIdentity) -> SmokeResult<()> {
            let transaction = RouteTransaction::install_isolated(
                interface.clone(),
                vec![isolated_address()],
                isolated_routes(&interface)?,
                &mut self.transaction,
            )?;
            self.transaction = Some(transaction);
            Ok(())
        }

        fn withdraw_capture_routes(&mut self) -> SmokeResult<()> {
            if let Some(transaction) = self.transaction.as_mut() {
                transaction.withdraw_capture_routes()?;
            }
            Ok(())
        }

        fn restore_interface_state_after_session(&mut self) -> SmokeResult<()> {
            if let Some(transaction) = self.transaction.as_mut() {
                transaction.restore_interface_state_after_session()?;
            }
            Ok(())
        }

        fn finish_ordered_cleanup(&mut self) -> SmokeResult<()> {
            if let Some(transaction) = self.transaction.take() {
                transaction.finish_ordered_cleanup()?;
            }
            Ok(())
        }
    }

    fn cleanup_network(
        mut network: IsolatedNetwork,
        session: Session,
        adapter: Adapter,
    ) -> SmokeResult<()> {
        if let Err(error) = network.withdraw_capture_routes() {
            // Do not let unwinding end the session or remove the adapter after
            // route withdrawal failed. Retain every downstream resource for
            // the rest of this process, matching the production fallback.
            std::mem::forget(network);
            std::mem::forget(session);
            std::mem::forget(adapter);
            return Err(error);
        }

        drop(session);

        if let Err(error) = network.restore_interface_state_after_session() {
            // The session has ended, but adapter removal could implicitly
            // discard interface state that was not restored successfully.
            std::mem::forget(network);
            std::mem::forget(adapter);
            return Err(error);
        }

        network.finish_ordered_cleanup()?;
        adapter.remove_owned()?;
        Ok(())
    }

    fn isolated_address() -> InterfaceAddress {
        InterfaceAddress {
            address: IpAddr::V4(TUN_ADDRESS),
            prefix_length: 32,
        }
    }

    fn isolated_routes(interface: &InterfaceIdentity) -> SmokeResult<Vec<OwnedRoute>> {
        [UDP_DESTINATION, TCP_DESTINATION]
            .into_iter()
            .map(|destination| {
                OwnedRoute::on_link_host(IpAddr::V4(destination), interface.clone(), 1)
                    .map_err(Into::into)
            })
            .collect()
    }

    fn cleanup_by_name(adapter_name: &str) -> SmokeResult<()> {
        if let Some(interface) = find_interface_by_alias(adapter_name)? {
            // An alias is user-controlled and can be reused by a non-Wintun
            // interface. Prove that the application-local Wintun DLL can open
            // this adapter and that the opened LUID/index/full identity still
            // match before removing even the isolated TEST-NET objects.
            let wintun = Wintun::load()?;
            let adapter = wintun.open_adapter(adapter_name)?;
            let opened_index = adapter.interface_index()?;
            let opened_identity = resolve_interface_identity(opened_index)?;
            if adapter.luid() != interface.interface_luid || opened_identity != interface {
                return Err(
                    "refusing isolated cleanup because Wintun adapter identity changed".into(),
                );
            }
            restore_isolated(
                &interface,
                &[isolated_address()],
                &isolated_routes(&interface)?,
            )?;
            adapter.close();
            if find_interface_by_alias(adapter_name)?.is_some() {
                return Err(
                    "isolated routes/address were restored, but the residual adapter cannot be \
                     removed through a reopened Wintun 0.14.1 handle"
                        .into(),
                );
            }
        }
        Ok(())
    }

    fn adapter_name() -> SmokeResult<String> {
        let name = std::env::var("SSWR_WINTUN_SMOKE_NAME").unwrap_or_else(|_| {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            format!("SSWR-Smoke-{}-{nonce}", std::process::id())
        });
        if name.is_empty()
            || name.encode_utf16().count() >= 128
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
        {
            return Err(
                "SSWR_WINTUN_SMOKE_NAME must contain only ASCII letters, digits, or '-'".into(),
            );
        }
        Ok(name)
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_smoke::run() {
        eprintln!("Wintun smoke test failed: {error}");
        std::process::exit(1);
    }
}
