use crate::error::PacketError;
use crate::packet::checksum::{ipv4_transport_checksum, ipv6_transport_checksum};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const PROTOCOL_NUMBER: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacket<'a> {
    bytes: &'a [u8],
}

impl<'a> UdpPacket<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < 8 {
            return Err(PacketError::TooShort);
        }
        let datagram_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if datagram_len < 8 || datagram_len > bytes.len() {
            return Err(PacketError::InvalidUdpLength);
        }
        Ok(Self {
            bytes: &bytes[..datagram_len],
        })
    }

    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[6], self.bytes[7]])
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[8..]
    }

    pub fn datagram(&self) -> &'a [u8] {
        self.bytes
    }

    /// IPv4 permits a zero UDP checksum. Non-zero checksums are validated.
    pub fn verify_ipv4_checksum(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Result<(), PacketError> {
        if self.checksum() == 0
            || ipv4_transport_checksum(source, destination, PROTOCOL_NUMBER, self.bytes) == 0
        {
            Ok(())
        } else {
            Err(PacketError::InvalidTransportChecksum)
        }
    }

    /// IPv6 requires a UDP checksum, so zero is rejected.
    pub fn verify_ipv6_checksum(
        &self,
        source: Ipv6Addr,
        destination: Ipv6Addr,
    ) -> Result<(), PacketError> {
        if self.checksum() != 0
            && ipv6_transport_checksum(source, destination, PROTOCOL_NUMBER, self.bytes) == 0
        {
            Ok(())
        } else {
            Err(PacketError::InvalidTransportChecksum)
        }
    }
}

/// Calculates and normalizes the checksum for a UDP datagram whose checksum
/// bytes are zero. RFC 768 transmits a calculated zero as all ones.
pub fn checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, datagram: &[u8]) -> u16 {
    normalize(ipv4_transport_checksum(
        source,
        destination,
        PROTOCOL_NUMBER,
        datagram,
    ))
}

pub fn checksum_ipv6(source: Ipv6Addr, destination: Ipv6Addr, datagram: &[u8]) -> u16 {
    normalize(ipv6_transport_checksum(
        source,
        destination,
        PROTOCOL_NUMBER,
        datagram,
    ))
}

fn normalize(checksum: u16) -> u16 {
    if checksum == 0 { 0xffff } else { checksum }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram() -> Vec<u8> {
        let mut bytes = vec![0_u8; 11];
        bytes[0..2].copy_from_slice(&53_000_u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&53_u16.to_be_bytes());
        bytes[4..6].copy_from_slice(&11_u16.to_be_bytes());
        bytes[8..].copy_from_slice(b"dns");
        bytes
    }

    #[test]
    fn parses_fields_and_respects_declared_length() {
        let mut bytes = datagram();
        bytes.extend_from_slice(b"ignored trailing IP bytes");
        let packet = UdpPacket::parse(&bytes).unwrap();
        assert_eq!(packet.source_port(), 53_000);
        assert_eq!(packet.destination_port(), 53);
        assert_eq!(packet.payload(), b"dns");
        assert_eq!(packet.datagram().len(), 11);
    }

    #[test]
    fn validates_ipv4_and_ipv6_checksums() {
        let source_v4 = Ipv4Addr::new(192, 0, 2, 1);
        let destination_v4 = Ipv4Addr::new(198, 51, 100, 2);
        let mut bytes_v4 = datagram();
        let checksum = checksum_ipv4(source_v4, destination_v4, &bytes_v4);
        bytes_v4[6..8].copy_from_slice(&checksum.to_be_bytes());
        UdpPacket::parse(&bytes_v4)
            .unwrap()
            .verify_ipv4_checksum(source_v4, destination_v4)
            .unwrap();

        let source_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut bytes_v6 = datagram();
        let checksum = checksum_ipv6(source_v6, destination_v6, &bytes_v6);
        bytes_v6[6..8].copy_from_slice(&checksum.to_be_bytes());
        UdpPacket::parse(&bytes_v6)
            .unwrap()
            .verify_ipv6_checksum(source_v6, destination_v6)
            .unwrap();
    }

    #[test]
    fn treats_zero_checksum_as_ipv4_only() {
        let bytes = datagram();
        let packet = UdpPacket::parse(&bytes).unwrap();
        packet
            .verify_ipv4_checksum(Ipv4Addr::LOCALHOST, Ipv4Addr::BROADCAST)
            .unwrap();
        assert_eq!(
            packet
                .verify_ipv6_checksum(Ipv6Addr::LOCALHOST, Ipv6Addr::UNSPECIFIED)
                .unwrap_err(),
            PacketError::InvalidTransportChecksum
        );
    }

    #[test]
    fn rejects_invalid_lengths() {
        let mut bytes = datagram();
        bytes[4..6].copy_from_slice(&7_u16.to_be_bytes());
        assert_eq!(
            UdpPacket::parse(&bytes).unwrap_err(),
            PacketError::InvalidUdpLength
        );
    }
}
