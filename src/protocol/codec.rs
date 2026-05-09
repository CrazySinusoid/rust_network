use bytes::{Buf, BufMut, BytesMut};

use crate::error::VpnError;
use crate::protocol::{Frame, FrameHeader, PacketType, HEADER_LEN, MAGIC, VERSION};

pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(HEADER_LEN + frame.payload.len());

    buf.put_slice(&encode_header(&frame.header));
    buf.put_slice(&frame.payload);

    buf.to_vec()
}

pub fn encode_header(header: &FrameHeader) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(HEADER_LEN);

    buf.put_slice(&MAGIC);
    buf.put_u8(VERSION);
    buf.put_u8(header.packet_type.into());
    buf.put_u8(header.flags);
    buf.put_u8(HEADER_LEN as u8);
    buf.put_u64(header.session_id);
    buf.put_u64(header.sequence_number);

    buf.to_vec()
}

pub fn decode_frame(input: &[u8]) -> Result<Frame, VpnError> {
    if input.len() < HEADER_LEN {
        return Err(VpnError::InvalidFrame("frame shorter than header"));
    }

    if input[0..4] != MAGIC {
        return Err(VpnError::InvalidFrame("bad magic"));
    }

    let version = input[4];
    if version != VERSION {
        return Err(VpnError::UnsupportedVersion(version));
    }

    let header_len = input[7] as usize;
    if header_len != HEADER_LEN {
        return Err(VpnError::InvalidFrame("unsupported header length"));
    }

    let packet_type = PacketType::try_from(input[5])?;
    let flags = input[6];

    let mut numeric = &input[8..HEADER_LEN];
    let session_id = numeric.get_u64();
    let sequence_number = numeric.get_u64();

    Ok(Frame {
        header: FrameHeader {
            packet_type,
            flags,
            session_id,
            sequence_number,
        },
        payload: input[HEADER_LEN..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::frame::FLAG_ENCRYPTED_PAYLOAD;

    #[test]
    fn frame_round_trips() {
        let frame = Frame::new(
            FrameHeader::new(PacketType::Data, FLAG_ENCRYPTED_PAYLOAD, 42, 7),
            b"hello".to_vec(),
        );

        let encoded = encode_frame(&frame);
        let decoded = decode_frame(&encoded).expect("valid frame");

        assert_eq!(decoded, frame);
        assert_eq!(encoded.len(), HEADER_LEN + 5);
    }

    #[test]
    fn encoded_header_is_frame_prefix() {
        let frame = Frame::new(
            FrameHeader::new(PacketType::Data, FLAG_ENCRYPTED_PAYLOAD, 42, 7),
            b"hello".to_vec(),
        );

        let header = encode_header(&frame.header);
        let encoded = encode_frame(&frame);

        assert_eq!(header.len(), HEADER_LEN);
        assert_eq!(&encoded[..HEADER_LEN], header.as_slice());
    }

    #[test]
    fn rejects_bad_magic() {
        let frame = Frame::new(
            FrameHeader::new(PacketType::ClientHello, 0, 0, 0),
            Vec::new(),
        );
        let mut encoded = encode_frame(&frame);
        encoded[0] = b'X';

        assert!(matches!(
            decode_frame(&encoded),
            Err(VpnError::InvalidFrame("bad magic"))
        ));
    }

    #[test]
    fn rejects_unknown_packet_type() {
        let frame = Frame::new(
            FrameHeader::new(PacketType::ClientHello, 0, 0, 0),
            Vec::new(),
        );
        let mut encoded = encode_frame(&frame);
        encoded[5] = 99;

        assert!(matches!(
            decode_frame(&encoded),
            Err(VpnError::UnknownPacketType(99))
        ));
    }
}
