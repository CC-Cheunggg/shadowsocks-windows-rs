use crate::error::PacketError;
use crate::packet::checksum::internet_checksum;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
    header_len: usize,
}

impl<'a> Ipv4Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < 20 {
            return Err(PacketError::TooShort);
        }
        if bytes[0] >> 4 != 4 {
            return Err(PacketError::InvalidIpVersion);
        }

        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len < 20 || header_len > bytes.len() {
            return Err(PacketError::InvalidIpv4HeaderLength);
        }
        let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total_len < header_len || total_len > bytes.len() {
            return Err(PacketError::InvalidIpv4TotalLength);
        }
        if internet_checksum(&bytes[..header_len]) != 0 {
            return Err(PacketError::InvalidIpv4HeaderChecksum);
        }

        let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
        let more_fragments = fragment & 0x2000 != 0;
        let fragment_offset = fragment & 0x1fff;
        if more_fragments || fragment_offset != 0 {
            return Err(PacketError::FragmentedIpv4);
        }

        Ok(Self {
            bytes: &bytes[..total_len],
            header_len,
        })
    }

    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.bytes[12],
            self.bytes[13],
            self.bytes[14],
            self.bytes[15],
        )
    }

    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.bytes[16],
            self.bytes[17],
            self.bytes[18],
            self.bytes[19],
        )
    }

    pub fn protocol(&self) -> u8 {
        self.bytes[9]
    }

    pub fn ttl(&self) -> u8 {
        self.bytes[8]
    }

    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..self.header_len]
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }

    pub fn packet(&self) -> &'a [u8] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(flags_and_offset: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 20 + payload.len()];
        bytes[0] = 0x45;
        let total_len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
        bytes[6..8].copy_from_slice(&flags_and_offset.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
        bytes[20..].copy_from_slice(payload);
        let checksum = internet_checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_complete_unfragmented_packet() {
        let bytes = packet(0x4000, b"abc");
        let parsed = Ipv4Packet::parse(&bytes).unwrap();
        assert_eq!(parsed.source(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(parsed.destination(), Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(parsed.protocol(), 17);
        assert_eq!(parsed.payload(), b"abc");
    }

    #[test]
    fn rejects_fragments_instead_of_leaking_them() {
        for fragment_bits in [0x2000, 0x0001] {
            let bytes = packet(fragment_bits, b"");
            assert_eq!(
                Ipv4Packet::parse(&bytes).unwrap_err(),
                PacketError::FragmentedIpv4
            );
        }
    }

    #[test]
    fn rejects_bad_length_and_checksum() {
        let mut bytes = packet(0, b"");
        bytes[2..4].copy_from_slice(&19_u16.to_be_bytes());
        assert_eq!(
            Ipv4Packet::parse(&bytes).unwrap_err(),
            PacketError::InvalidIpv4TotalLength
        );

        let mut bytes = packet(0, b"");
        bytes[8] ^= 1;
        assert_eq!(
            Ipv4Packet::parse(&bytes).unwrap_err(),
            PacketError::InvalidIpv4HeaderChecksum
        );
    }
}
