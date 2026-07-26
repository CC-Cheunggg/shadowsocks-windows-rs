use crate::error::PacketError;
use crate::packet::checksum::internet_checksum;
use crate::packet::udp;
use std::net::{IpAddr, SocketAddr};

/// Builds an unfragmented UDP/IP packet for injection into Wintun.
pub fn udp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    ipv4_identification: u16,
) -> Result<Vec<u8>, PacketError> {
    udp_packet_with_mtu(
        source,
        destination,
        payload,
        ipv4_identification,
        u16::MAX as usize,
    )
}

/// Builds an unfragmented UDP/IP packet and rejects packets that exceed the
/// configured Wintun interface MTU. Callers must drop rather than fragment an
/// oversized response because this slice does not implement IP fragmentation.
pub fn udp_packet_with_mtu(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    ipv4_identification: u16,
    mtu: usize,
) -> Result<Vec<u8>, PacketError> {
    if source.port() == 0 || destination.port() == 0 || source.is_ipv4() != destination.is_ipv4() {
        return Err(PacketError::InvalidUdpLength);
    }
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or(PacketError::PacketTooLarge)?;
    let udp_len_u16 = u16::try_from(udp_len).map_err(|_| PacketError::PacketTooLarge)?;
    let mut datagram = vec![0; udp_len];
    datagram[0..2].copy_from_slice(&source.port().to_be_bytes());
    datagram[2..4].copy_from_slice(&destination.port().to_be_bytes());
    datagram[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    datagram[8..].copy_from_slice(payload);

    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            let checksum = udp::checksum_ipv4(source_ip, destination_ip, &datagram);
            datagram[6..8].copy_from_slice(&checksum.to_be_bytes());
            let total_len = 20_usize
                .checked_add(udp_len)
                .ok_or(PacketError::PacketTooLarge)?;
            if total_len > mtu {
                return Err(PacketError::PacketTooLarge);
            }
            let total_len_u16 =
                u16::try_from(total_len).map_err(|_| PacketError::PacketTooLarge)?;
            let mut packet = vec![0; total_len];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
            packet[4..6].copy_from_slice(&ipv4_identification.to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = udp::PROTOCOL_NUMBER;
            packet[12..16].copy_from_slice(&source_ip.octets());
            packet[16..20].copy_from_slice(&destination_ip.octets());
            packet[20..].copy_from_slice(&datagram);
            let header_checksum = internet_checksum(&packet[..20]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            Ok(packet)
        }
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            let total_len = 40_usize
                .checked_add(udp_len)
                .ok_or(PacketError::PacketTooLarge)?;
            if total_len > mtu {
                return Err(PacketError::PacketTooLarge);
            }
            let checksum = udp::checksum_ipv6(source_ip, destination_ip, &datagram);
            datagram[6..8].copy_from_slice(&checksum.to_be_bytes());
            let mut packet = vec![0; total_len];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
            packet[6] = udp::PROTOCOL_NUMBER;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source_ip.octets());
            packet[24..40].copy_from_slice(&destination_ip.octets());
            packet[40..].copy_from_slice(&datagram);
            Ok(packet)
        }
        _ => Err(PacketError::InvalidIpVersion),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{IpPacket, udp::UdpPacket};

    #[test]
    fn builds_valid_ipv4_and_ipv6_udp_responses() {
        let v4 = udp_packet(
            "198.51.100.53:53".parse().unwrap(),
            "198.18.0.2:53000".parse().unwrap(),
            b"dns-v4",
            7,
        )
        .unwrap();
        let IpPacket::V4(ipv4) = IpPacket::parse(&v4).unwrap() else {
            panic!("IPv4");
        };
        UdpPacket::parse(ipv4.payload())
            .unwrap()
            .verify_ipv4_checksum(ipv4.source(), ipv4.destination())
            .unwrap();

        let v6 = udp_packet(
            "[2001:db8::53]:53".parse().unwrap(),
            "[fd00:7373:7273::2]:53000".parse().unwrap(),
            b"dns-v6",
            0,
        )
        .unwrap();
        let IpPacket::V6(ipv6) = IpPacket::parse(&v6).unwrap() else {
            panic!("IPv6");
        };
        UdpPacket::parse(ipv6.payload())
            .unwrap()
            .verify_ipv6_checksum(ipv6.source(), ipv6.destination())
            .unwrap();
    }

    #[test]
    fn rejects_mixed_families_and_oversized_payloads() {
        assert_eq!(
            udp_packet(
                "198.51.100.53:53".parse().unwrap(),
                "[2001:db8::1]:53000".parse().unwrap(),
                b"x",
                0,
            )
            .unwrap_err(),
            PacketError::InvalidUdpLength
        );
        assert_eq!(
            udp_packet(
                "198.51.100.53:53".parse().unwrap(),
                "198.18.0.2:53000".parse().unwrap(),
                &vec![0; 65_508],
                0,
            )
            .unwrap_err(),
            PacketError::PacketTooLarge
        );
    }

    #[test]
    fn configured_mtu_is_enforced_without_fragmenting() {
        let source_v4 = "198.51.100.53:53".parse().unwrap();
        let destination_v4 = "198.18.0.2:53000".parse().unwrap();
        assert_eq!(
            udp_packet_with_mtu(source_v4, destination_v4, &vec![0; 1473], 0, 1500).unwrap_err(),
            PacketError::PacketTooLarge
        );
        assert_eq!(
            udp_packet_with_mtu(source_v4, destination_v4, &vec![0; 1472], 0, 1500)
                .unwrap()
                .len(),
            1500
        );

        let source_v6 = "[2001:db8::53]:53".parse().unwrap();
        let destination_v6 = "[fd00:7373:7273::2]:53000".parse().unwrap();
        assert_eq!(
            udp_packet_with_mtu(source_v6, destination_v6, &vec![0; 1453], 0, 1500).unwrap_err(),
            PacketError::PacketTooLarge
        );
        assert_eq!(
            udp_packet_with_mtu(source_v6, destination_v6, &vec![0; 1452], 0, 1500)
                .unwrap()
                .len(),
            1500
        );
    }
}
