use crate::crypto::aead::{decrypt_payload_with_sequence, encrypt_payload_with_sequence};
use crate::crypto::keys::AeadKeyBytes;
use crate::crypto::nonce::NoncePrefix;
use crate::error::VpnError;
use crate::protocol::codec::encode_header;
use crate::protocol::frame::FLAG_ENCRYPTED_PAYLOAD;
use crate::protocol::handshake::{decode_auth_confirm, encode_auth_confirm, AuthConfirm};
use crate::protocol::{Frame, FrameHeader, PacketType};

pub const KEEPALIVE_LEN: usize = 8;

pub fn encrypt_auth_confirm_frame(
    auth: &AuthConfirm,
    key: &AeadKeyBytes,
    nonce_prefix: NoncePrefix,
    sequence_number: u64,
) -> Result<Frame, VpnError> {
    let header = FrameHeader::encrypted(PacketType::AuthConfirm, auth.session_id, sequence_number);
    let aad = encode_header(&header);
    let plaintext = encode_auth_confirm(auth);
    let payload =
        encrypt_payload_with_sequence(key, nonce_prefix, sequence_number, &aad, &plaintext)?;

    Ok(Frame { header, payload })
}

pub fn decrypt_auth_confirm_frame(
    frame: &Frame,
    key: &AeadKeyBytes,
    nonce_prefix: NoncePrefix,
) -> Result<AuthConfirm, VpnError> {
    validate_encrypted_packet(frame, PacketType::AuthConfirm)?;

    let aad = encode_header(&frame.header);
    let plaintext = decrypt_payload_with_sequence(
        key,
        nonce_prefix,
        frame.header.sequence_number,
        &aad,
        &frame.payload,
    )?;

    decode_auth_confirm(&plaintext)
}

pub fn encrypt_data_frame(
    session_id: u64,
    sequence_number: u64,
    key: &AeadKeyBytes,
    nonce_prefix: NoncePrefix,
    ip_packet: &[u8],
) -> Result<Frame, VpnError> {
    let header = FrameHeader::encrypted(PacketType::Data, session_id, sequence_number);
    let aad = encode_header(&header);
    let payload =
        encrypt_payload_with_sequence(key, nonce_prefix, sequence_number, &aad, ip_packet)?;

    Ok(Frame { header, payload })
}

pub fn decrypt_data_frame(
    frame: &Frame,
    key: &AeadKeyBytes,
    nonce_prefix: NoncePrefix,
) -> Result<Vec<u8>, VpnError> {
    validate_encrypted_packet(frame, PacketType::Data)?;

    let aad = encode_header(&frame.header);
    decrypt_payload_with_sequence(
        key,
        nonce_prefix,
        frame.header.sequence_number,
        &aad,
        &frame.payload,
    )
}

pub fn encrypt_keepalive_frame(
    session_id: u64,
    sequence_number: u64,
    key: &AeadKeyBytes,
    nonce_prefix: NoncePrefix,
    unix_time_ms: u64,
) -> Result<Frame, VpnError> {
    let header = FrameHeader::encrypted(PacketType::Keepalive, session_id, sequence_number);
    let aad = encode_header(&header);
    let plaintext = encode_keepalive(unix_time_ms);
    let payload =
        encrypt_payload_with_sequence(key, nonce_prefix, sequence_number, &aad, &plaintext)?;

    Ok(Frame { header, payload })
}

pub fn decrypt_keepalive_frame(
    frame: &Frame,
    key: &AeadKeyBytes,
    nonce_prefix: NoncePrefix,
) -> Result<u64, VpnError> {
    validate_encrypted_packet(frame, PacketType::Keepalive)?;

    let aad = encode_header(&frame.header);
    let plaintext = decrypt_payload_with_sequence(
        key,
        nonce_prefix,
        frame.header.sequence_number,
        &aad,
        &frame.payload,
    )?;

    decode_keepalive(&plaintext)
}

fn encode_keepalive(unix_time_ms: u64) -> Vec<u8> {
    unix_time_ms.to_be_bytes().to_vec()
}

fn decode_keepalive(input: &[u8]) -> Result<u64, VpnError> {
    if input.len() != KEEPALIVE_LEN {
        return Err(VpnError::InvalidFrame("invalid keepalive length"));
    }

    let mut bytes = [0u8; KEEPALIVE_LEN];
    bytes.copy_from_slice(input);
    Ok(u64::from_be_bytes(bytes))
}

fn validate_encrypted_packet(frame: &Frame, expected_type: PacketType) -> Result<(), VpnError> {
    if frame.header.packet_type != expected_type {
        return Err(VpnError::InvalidFrame("unexpected encrypted packet type"));
    }

    if frame.header.flags & FLAG_ENCRYPTED_PAYLOAD == 0 {
        return Err(VpnError::InvalidFrame("encrypted payload flag is missing"));
    }

    if frame.header.sequence_number == 0 {
        return Err(VpnError::InvalidFrame("encrypted packet sequence is zero"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::handshake::{CLIENT_RANDOM_LEN, SERVER_RANDOM_LEN};

    fn key() -> AeadKeyBytes {
        [0x11; 32]
    }

    fn nonce_prefix() -> NoncePrefix {
        [1, 2, 3, 4]
    }

    fn auth_confirm() -> AuthConfirm {
        AuthConfirm {
            client_instance_id: 0x0102_0304_0506_0708,
            session_id: 0x1112_1314_1516_1718,
            client_random: [0x11; CLIENT_RANDOM_LEN],
            server_random: [0x22; SERVER_RANDOM_LEN],
        }
    }

    #[test]
    fn auth_confirm_frame_round_trips() {
        let auth = auth_confirm();
        let frame = encrypt_auth_confirm_frame(&auth, &key(), nonce_prefix(), 1).unwrap();
        let decoded = decrypt_auth_confirm_frame(&frame, &key(), nonce_prefix()).unwrap();

        assert_eq!(decoded, auth);
        assert_eq!(frame.header.packet_type, PacketType::AuthConfirm);
        assert_eq!(frame.header.session_id, auth.session_id);
    }

    #[test]
    fn data_frame_round_trips() {
        let ip_packet = b"fake ipv4 packet bytes";
        let frame = encrypt_data_frame(42, 7, &key(), nonce_prefix(), ip_packet).unwrap();
        let decrypted = decrypt_data_frame(&frame, &key(), nonce_prefix()).unwrap();

        assert_eq!(decrypted, ip_packet);
        assert_eq!(frame.header.packet_type, PacketType::Data);
        assert_eq!(frame.header.session_id, 42);
        assert_eq!(frame.header.sequence_number, 7);
    }

    #[test]
    fn keepalive_frame_round_trips() {
        let frame =
            encrypt_keepalive_frame(42, 9, &key(), nonce_prefix(), 1_714_000_000_123).unwrap();
        let unix_time_ms = decrypt_keepalive_frame(&frame, &key(), nonce_prefix()).unwrap();

        assert_eq!(unix_time_ms, 1_714_000_000_123);
        assert_eq!(frame.header.packet_type, PacketType::Keepalive);
        assert_eq!(frame.header.session_id, 42);
        assert_eq!(frame.header.sequence_number, 9);
    }

    #[test]
    fn changed_header_breaks_aad() {
        let ip_packet = b"fake ipv4 packet bytes";
        let mut frame = encrypt_data_frame(42, 7, &key(), nonce_prefix(), ip_packet).unwrap();
        frame.header.session_id ^= 1;

        assert!(matches!(
            decrypt_data_frame(&frame, &key(), nonce_prefix()),
            Err(VpnError::DecryptionFailed)
        ));
    }

    #[test]
    fn rejects_plaintext_flag_for_secure_packet() {
        let ip_packet = b"fake ipv4 packet bytes";
        let mut frame = encrypt_data_frame(42, 7, &key(), nonce_prefix(), ip_packet).unwrap();
        frame.header.flags = 0;

        assert!(matches!(
            decrypt_data_frame(&frame, &key(), nonce_prefix()),
            Err(VpnError::InvalidFrame("encrypted payload flag is missing"))
        ));
    }

    #[test]
    fn rejects_zero_sequence_for_secure_packet() {
        let frame = Frame {
            header: FrameHeader::encrypted(PacketType::Data, 42, 0),
            payload: Vec::new(),
        };

        assert!(matches!(
            decrypt_data_frame(&frame, &key(), nonce_prefix()),
            Err(VpnError::InvalidFrame("encrypted packet sequence is zero"))
        ));
    }

    #[test]
    fn rejects_bad_keepalive_plaintext_length() {
        let header = FrameHeader::encrypted(PacketType::Keepalive, 42, 9);
        let aad = encode_header(&header);
        let payload =
            encrypt_payload_with_sequence(&key(), nonce_prefix(), 9, &aad, b"bad").unwrap();
        let frame = Frame { header, payload };

        assert!(matches!(
            decrypt_keepalive_frame(&frame, &key(), nonce_prefix()),
            Err(VpnError::InvalidFrame("invalid keepalive length"))
        ));
    }
}
