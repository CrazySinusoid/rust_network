use crate::protocol::PacketType;

pub const MAGIC: [u8; 4] = *b"RVPN";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 24;
pub const FLAG_ENCRYPTED_PAYLOAD: u8 = 0b0000_0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub packet_type: PacketType,
    pub flags: u8,
    pub session_id: u64,
    pub sequence_number: u64,
}

impl FrameHeader {
    pub fn new(packet_type: PacketType, flags: u8, session_id: u64, sequence_number: u64) -> Self {
        Self {
            packet_type,
            flags,
            session_id,
            sequence_number,
        }
    }

    pub fn encrypted(packet_type: PacketType, session_id: u64, sequence_number: u64) -> Self {
        Self::new(
            packet_type,
            FLAG_ENCRYPTED_PAYLOAD,
            session_id,
            sequence_number,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(header: FrameHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }
}
