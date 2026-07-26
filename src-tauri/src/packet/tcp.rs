use crate::error::PacketError;
use crate::packet::checksum::{ipv4_transport_checksum, ipv6_transport_checksum};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const PROTOCOL_NUMBER: u8 = 6;

pub mod flags {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    pub const NS: u16 = 0x100;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpPacket<'a> {
    bytes: &'a [u8],
    header_len: usize,
}

impl<'a> TcpPacket<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < 20 {
            return Err(PacketError::TooShort);
        }
        let header_len = usize::from(bytes[12] >> 4) * 4;
        if header_len < 20 || header_len > bytes.len() {
            return Err(PacketError::InvalidTcpHeaderLength);
        }
        Ok(Self { bytes, header_len })
    }

    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    pub fn sequence_number(&self) -> u32 {
        u32::from_be_bytes(self.bytes[4..8].try_into().expect("fixed TCP sequence"))
    }

    pub fn acknowledgment_number(&self) -> u32 {
        u32::from_be_bytes(
            self.bytes[8..12]
                .try_into()
                .expect("fixed TCP acknowledgment"),
        )
    }

    pub fn flags(&self) -> u16 {
        u16::from_be_bytes([self.bytes[12], self.bytes[13]]) & 0x01ff
    }

    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes([self.bytes[14], self.bytes[15]])
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.bytes[16], self.bytes[17]])
    }

    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.bytes[18], self.bytes[19]])
    }

    pub fn options(&self) -> &'a [u8] {
        &self.bytes[20..self.header_len]
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }

    pub fn segment(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn verify_ipv4_checksum(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Result<(), PacketError> {
        if ipv4_transport_checksum(source, destination, PROTOCOL_NUMBER, self.bytes) == 0 {
            Ok(())
        } else {
            Err(PacketError::InvalidTransportChecksum)
        }
    }

    pub fn verify_ipv6_checksum(
        &self,
        source: Ipv6Addr,
        destination: Ipv6Addr,
    ) -> Result<(), PacketError> {
        if ipv6_transport_checksum(source, destination, PROTOCOL_NUMBER, self.bytes) == 0 {
            Ok(())
        } else {
            Err(PacketError::InvalidTransportChecksum)
        }
    }
}

/// Calculates the checksum for a TCP segment whose checksum bytes are zero.
pub fn checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, segment: &[u8]) -> u16 {
    ipv4_transport_checksum(source, destination, PROTOCOL_NUMBER, segment)
}

/// Calculates the checksum for a TCP segment whose checksum bytes are zero.
pub fn checksum_ipv6(source: Ipv6Addr, destination: Ipv6Addr, segment: &[u8]) -> u16 {
    ipv6_transport_checksum(source, destination, PROTOCOL_NUMBER, segment)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_segment() -> Vec<u8> {
        let mut segment = vec![0_u8; 24];
        segment[0..2].copy_from_slice(&12_345_u16.to_be_bytes());
        segment[2..4].copy_from_slice(&443_u16.to_be_bytes());
        segment[4..8].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        segment[8..12].copy_from_slice(&0x0506_0708_u32.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = (flags::ACK | flags::PSH) as u8;
        segment[14..16].copy_from_slice(&4096_u16.to_be_bytes());
        segment[20..].copy_from_slice(b"test");
        segment
    }

    #[test]
    fn parses_fields_and_payload() {
        let segment = tcp_segment();
        let packet = TcpPacket::parse(&segment).unwrap();
        assert_eq!(packet.source_port(), 12_345);
        assert_eq!(packet.destination_port(), 443);
        assert_eq!(packet.sequence_number(), 0x0102_0304);
        assert_eq!(packet.acknowledgment_number(), 0x0506_0708);
        assert_eq!(packet.flags(), flags::ACK | flags::PSH);
        assert_eq!(packet.payload(), b"test");
    }

    #[test]
    fn validates_ipv4_and_ipv6_checksums() {
        let source_v4 = Ipv4Addr::new(192, 0, 2, 1);
        let destination_v4 = Ipv4Addr::new(198, 51, 100, 2);
        let mut segment_v4 = tcp_segment();
        let checksum = checksum_ipv4(source_v4, destination_v4, &segment_v4);
        segment_v4[16..18].copy_from_slice(&checksum.to_be_bytes());
        TcpPacket::parse(&segment_v4)
            .unwrap()
            .verify_ipv4_checksum(source_v4, destination_v4)
            .unwrap();
        segment_v4[20] ^= 1;
        assert_eq!(
            TcpPacket::parse(&segment_v4)
                .unwrap()
                .verify_ipv4_checksum(source_v4, destination_v4)
                .unwrap_err(),
            PacketError::InvalidTransportChecksum
        );

        let source_v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination_v6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut segment_v6 = tcp_segment();
        let checksum = checksum_ipv6(source_v6, destination_v6, &segment_v6);
        segment_v6[16..18].copy_from_slice(&checksum.to_be_bytes());
        TcpPacket::parse(&segment_v6)
            .unwrap()
            .verify_ipv6_checksum(source_v6, destination_v6)
            .unwrap();
    }

    #[test]
    fn rejects_invalid_data_offset() {
        let mut segment = tcp_segment();
        segment[12] = 0x40;
        assert_eq!(
            TcpPacket::parse(&segment).unwrap_err(),
            PacketError::InvalidTcpHeaderLength
        );
    }
}
