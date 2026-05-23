use std::net::Ipv4Addr;

use crate::error::VpnError;

pub const IPV4_MIN_HEADER_LEN: usize = 20;

pub fn is_ipv4(packet: &[u8]) -> bool {
    packet.first().is_some_and(|first| first >> 4 == 4)
}

pub fn validate(packet: &[u8], max_len: usize) -> Result<(), VpnError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(VpnError::InvalidIpv4Packet(
            "packet shorter than IPv4 header",
        ));
    }

    if packet.len() > max_len {
        return Err(VpnError::InvalidIpv4Packet("packet exceeds configured MTU"));
    }

    if !is_ipv4(packet) {
        return Err(VpnError::InvalidIpv4Packet("packet is not IPv4"));
    }

    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HEADER_LEN {
        return Err(VpnError::InvalidIpv4Packet("IPv4 IHL is too small"));
    }

    if ihl > packet.len() {
        return Err(VpnError::InvalidIpv4Packet(
            "IPv4 IHL exceeds packet length",
        ));
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < ihl {
        return Err(VpnError::InvalidIpv4Packet(
            "IPv4 total length is smaller than header",
        ));
    }

    if total_len != packet.len() {
        return Err(VpnError::InvalidIpv4Packet(
            "IPv4 total length does not match packet length",
        ));
    }

    Ok(())
}

pub fn source_addr(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < IPV4_MIN_HEADER_LEN || !is_ipv4(packet) {
        return None;
    }

    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

pub fn destination_addr(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < IPV4_MIN_HEADER_LEN || !is_ipv4(packet) {
        return None;
    }

    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_packet() -> Vec<u8> {
        let mut packet = vec![0u8; IPV4_MIN_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(IPV4_MIN_HEADER_LEN as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 8, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 8, 0, 1]);
        packet
    }

    #[test]
    fn accepts_valid_ipv4_packet() {
        assert!(validate(&valid_packet(), 1300).is_ok());
    }

    #[test]
    fn rejects_non_ipv4_packet() {
        let mut packet = valid_packet();
        packet[0] = 0x65;

        assert!(matches!(
            validate(&packet, 1300),
            Err(VpnError::InvalidIpv4Packet("packet is not IPv4"))
        ));
    }

    #[test]
    fn rejects_total_length_mismatch() {
        let mut packet = valid_packet();
        packet[2..4].copy_from_slice(&21u16.to_be_bytes());

        assert!(matches!(
            validate(&packet, 1300),
            Err(VpnError::InvalidIpv4Packet(
                "IPv4 total length does not match packet length"
            ))
        ));
    }

    #[test]
    fn extracts_source_and_destination() {
        let packet = valid_packet();

        assert_eq!(source_addr(&packet), Some(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(destination_addr(&packet), Some(Ipv4Addr::new(10, 8, 0, 1)));
    }
}
