use std::net::Ipv4Addr;

pub fn is_ipv4(packet: &[u8]) -> bool {
    packet.first().is_some_and(|first| first >> 4 == 4)
}

pub fn source_addr(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || !is_ipv4(packet) {
        return None;
    }

    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

pub fn destination_addr(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || !is_ipv4(packet) {
        return None;
    }

    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}
