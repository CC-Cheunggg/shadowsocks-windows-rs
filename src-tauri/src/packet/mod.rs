pub mod builder;
pub mod checksum;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

use crate::error::PacketError;
use ipv4::Ipv4Packet;
use ipv6::Ipv6Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        let version = bytes.first().ok_or(PacketError::TooShort)? >> 4;
        match version {
            4 => Ipv4Packet::parse(bytes).map(Self::V4),
            6 => Ipv6Packet::parse(bytes).map(Self::V6),
            _ => Err(PacketError::InvalidIpVersion),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatches_by_ip_version() {
        let mut ipv4 = [0_u8; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20_u16.to_be_bytes());
        ipv4[8] = 64;
        let header_checksum = checksum::internet_checksum(&ipv4);
        ipv4[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        assert!(matches!(IpPacket::parse(&ipv4), Ok(IpPacket::V4(_))));

        let mut ipv6 = [0_u8; 40];
        ipv6[0] = 0x60;
        ipv6[6] = 59;
        assert!(matches!(IpPacket::parse(&ipv6), Ok(IpPacket::V6(_))));

        assert_eq!(
            IpPacket::parse(&[0x70]).unwrap_err(),
            PacketError::InvalidIpVersion
        );
    }
}
