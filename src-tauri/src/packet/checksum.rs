use std::net::{Ipv4Addr, Ipv6Addr};

/// Computes the RFC 1071 one's-complement checksum.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    finalize(sum_words(0, bytes))
}

pub fn ipv4_transport_checksum(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let mut sum = sum_words(0, &source.octets());
    sum = sum_words(sum, &destination.octets());
    sum += u32::from(protocol);
    sum += segment.len() as u32;
    finalize(sum_words(sum, segment))
}

pub fn ipv6_transport_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    segment: &[u8],
) -> u16 {
    let mut sum = sum_words(0, &source.octets());
    sum = sum_words(sum, &destination.octets());
    let length = (segment.len() as u32).to_be_bytes();
    sum = sum_words(sum, &length);
    sum += u32::from(next_header);
    finalize(sum_words(sum, segment))
}

fn sum_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    fold(sum)
}

fn finalize(sum: u32) -> u16 {
    !fold(sum) as u16
}

fn fold(mut sum: u32) -> u32 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_rfc_1071_example() {
        let bytes = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x00, 0x00];
        assert_eq!(internet_checksum(&bytes), 0x220d);
    }

    #[test]
    fn odd_length_is_padded_on_the_right() {
        assert_eq!(internet_checksum(&[0x01, 0x02, 0x03]), 0xfbfd);
    }

    #[test]
    fn a_packet_containing_its_checksum_verifies_to_zero() {
        let mut bytes = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let checksum = internet_checksum(&bytes);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(internet_checksum(&bytes), 0);
    }
}
