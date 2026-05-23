use rust_network::crypto::keys::AeadKeyBytes;
use rust_network::crypto::nonce::NoncePrefix;
use rust_network::error::VpnError;
use rust_network::packet::ipv4;
use rust_network::protocol::{
    decode_frame, decrypt_disconnect_frame, encrypt_disconnect_frame, DisconnectReason,
    FrameHeader, PacketType, ReplayDecision, ReplayWindow, MAX_FRAME_LEN,
};

fn key() -> AeadKeyBytes {
    [0x44; 32]
}

fn nonce_prefix() -> NoncePrefix {
    [4, 3, 2, 1]
}

fn valid_ipv4_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[10, 8, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 8, 0, 1]);
    packet
}

#[test]
fn oversized_frames_are_rejected_before_decode() {
    let oversized = vec![0u8; MAX_FRAME_LEN + 1];

    assert!(matches!(
        decode_frame(&oversized),
        Err(VpnError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN
        }) if len == MAX_FRAME_LEN + 1
    ));
}

#[test]
fn replay_window_allows_single_out_of_order_packet() {
    let mut window = ReplayWindow::new();

    assert_eq!(window.accept(100), ReplayDecision::Fresh);
    assert_eq!(window.accept(98), ReplayDecision::Fresh);
    assert_eq!(window.accept(98), ReplayDecision::Replay);
}

#[test]
fn ipv4_validator_rejects_payload_length_mismatch() {
    let mut packet = valid_ipv4_packet();
    packet[2..4].copy_from_slice(&24u16.to_be_bytes());

    assert!(matches!(
        ipv4::validate(&packet, 1300),
        Err(VpnError::InvalidIpv4Packet(
            "IPv4 total length does not match packet length"
        ))
    ));
}

#[test]
fn encrypted_disconnect_round_trips() {
    let frame = encrypt_disconnect_frame(
        7,
        1,
        &key(),
        nonce_prefix(),
        DisconnectReason::NormalShutdown,
    )
    .unwrap();

    assert_eq!(frame.header.packet_type, PacketType::Disconnect);
    assert_eq!(
        decrypt_disconnect_frame(&frame, &key(), nonce_prefix()).unwrap(),
        DisconnectReason::NormalShutdown
    );
}

#[test]
fn plaintext_disconnect_is_not_accepted_as_encrypted_control() {
    let frame = rust_network::protocol::Frame {
        header: FrameHeader::new(PacketType::Disconnect, 0, 7, 1),
        payload: vec![u8::from(DisconnectReason::NormalShutdown)],
    };

    assert!(matches!(
        decrypt_disconnect_frame(&frame, &key(), nonce_prefix()),
        Err(VpnError::InvalidFrame("encrypted payload flag is missing"))
    ));
}
