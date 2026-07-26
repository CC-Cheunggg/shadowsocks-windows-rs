use crate::error::PacketError;
use std::net::Ipv6Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Packet<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv6Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < 40 {
            return Err(PacketError::TooShort);
        }
        if bytes[0] >> 4 != 6 {
            return Err(PacketError::InvalidIpVersion);
        }

        let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        let total_len = 40_usize
            .checked_add(payload_len)
            .ok_or(PacketError::InvalidIpv6PayloadLength)?;
        if total_len > bytes.len() {
            return Err(PacketError::InvalidIpv6PayloadLength);
        }

        match bytes[6] {
            // Fragment has its own error so diagnostics can distinguish it.
            44 => return Err(PacketError::FragmentedIpv6),
            // Hop-by-Hop, Routing, ESP, AH, Destination Options, Mobility,
            // HIP, Shim6, and experimentation values are fail-closed in this
            // slice. No attempt is made to skip an extension chain.
            0 | 43 | 50 | 51 | 60 | 135 | 139 | 140 | 253 | 254 => {
                return Err(PacketError::UnsupportedIpv6Extension);
            }
            _ => {}
        }

        Ok(Self {
            bytes: &bytes[..total_len],
        })
    }

    pub fn source(&self) -> Ipv6Addr {
        let octets: [u8; 16] = self.bytes[8..24].try_into().expect("fixed IPv6 source");
        Ipv6Addr::from(octets)
    }

    pub fn destination(&self) -> Ipv6Addr {
        let octets: [u8; 16] = self.bytes[24..40]
            .try_into()
            .expect("fixed IPv6 destination");
        Ipv6Addr::from(octets)
    }

    pub fn next_header(&self) -> u8 {
        self.bytes[6]
    }

    pub fn hop_limit(&self) -> u8 {
        self.bytes[7]
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[40..]
    }

    pub fn packet(&self) -> &'a [u8] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 40 + payload.len()];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes[6] = next_header;
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        bytes[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        bytes[40..].copy_from_slice(payload);
        bytes
    }

    #[test]
    fn parses_base_header_without_extensions() {
        let bytes = packet(17, b"dns");
        let parsed = Ipv6Packet::parse(&bytes).unwrap();
        assert_eq!(parsed.source(), Ipv6Addr::LOCALHOST);
        assert_eq!(
            parsed.destination(),
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(parsed.payload(), b"dns");
    }

    #[test]
    fn distinguishes_fragment_and_other_extensions() {
        assert_eq!(
            Ipv6Packet::parse(&packet(44, &[0; 8])).unwrap_err(),
            PacketError::FragmentedIpv6
        );
        for next_header in [0, 43, 50, 51, 60, 135, 139, 140, 253, 254] {
            assert_eq!(
                Ipv6Packet::parse(&packet(next_header, &[])).unwrap_err(),
                PacketError::UnsupportedIpv6Extension
            );
        }
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut bytes = packet(6, &[]);
        bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            Ipv6Packet::parse(&bytes).unwrap_err(),
            PacketError::InvalidIpv6PayloadLength
        );
    }
}
