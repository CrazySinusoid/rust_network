use std::net::SocketAddr;

use anyhow::Result;

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::keys::{AeadKeyBytes, SessionKeys};
use crate::crypto::nonce::NoncePrefix;
use crate::protocol::{
    decode_frame, decrypt_data_frame, encode_frame, encrypt_data_frame, PacketType, HEADER_LEN,
};
use crate::transport::udp::UdpTransport;
use crate::tun::linux::TunDevice;

const EXTRA_FRAME_SPACE: usize = 64;

pub struct TunnelSession {
    pub session_id: u64,
    pub peer_addr: SocketAddr,
    pub send_seq: u64,
    pub recv_highest_seq: u64,
    pub send_key: AeadKeyBytes,
    pub recv_key: AeadKeyBytes,
    pub send_nonce_prefix: NoncePrefix,
    pub recv_nonce_prefix: NoncePrefix,
    pub selected_mtu: u16,
}

impl TunnelSession {
    pub fn client(
        session_id: u64,
        peer_addr: SocketAddr,
        keys: SessionKeys,
        selected_mtu: u16,
    ) -> Self {
        Self {
            session_id,
            peer_addr,
            send_seq: 0,
            recv_highest_seq: 0,
            send_key: keys.client_to_server_key,
            recv_key: keys.server_to_client_key,
            send_nonce_prefix: keys.client_to_server_nonce_prefix,
            recv_nonce_prefix: keys.server_to_client_nonce_prefix,
            selected_mtu,
        }
    }

    pub fn server(
        session_id: u64,
        peer_addr: SocketAddr,
        keys: SessionKeys,
        selected_mtu: u16,
    ) -> Self {
        Self {
            session_id,
            peer_addr,
            send_seq: 0,
            recv_highest_seq: 0,
            send_key: keys.server_to_client_key,
            recv_key: keys.client_to_server_key,
            send_nonce_prefix: keys.server_to_client_nonce_prefix,
            recv_nonce_prefix: keys.client_to_server_nonce_prefix,
            selected_mtu,
        }
    }

    fn next_send_sequence(&mut self) -> u64 {
        self.send_seq += 1;
        self.send_seq
    }

    fn is_fresh_recv_sequence(&self, sequence_number: u64) -> bool {
        sequence_number != 0 && sequence_number > self.recv_highest_seq
    }

    fn commit_recv_sequence(&mut self, sequence_number: u64) {
        self.recv_highest_seq = sequence_number;
    }
}

pub async fn run(
    mut tun: TunDevice,
    transport: UdpTransport,
    mut session: TunnelSession,
) -> Result<()> {
    let mut tun_buf = vec![0u8; session.selected_mtu as usize];
    let mut udp_buf =
        vec![0u8; session.selected_mtu as usize + HEADER_LEN + AEAD_TAG_LEN + EXTRA_FRAME_SPACE];

    tracing::info!(
        tun = tun.name(),
        peer = %session.peer_addr,
        session_id = session.session_id,
        mtu = session.selected_mtu,
        "encrypted tunnel loop started"
    );

    loop {
        tokio::select! {
            tun_result = tun.read_packet(&mut tun_buf) => {
                let n = tun_result?;
                if n == 0 {
                    continue;
                }

                let sequence_number = session.next_send_sequence();
                let frame = encrypt_data_frame(
                    session.session_id,
                    sequence_number,
                    &session.send_key,
                    session.send_nonce_prefix,
                    &tun_buf[..n],
                )?;
                let encoded = encode_frame(&frame);
                transport.send_to(&encoded, session.peer_addr).await?;

                tracing::debug!(
                    bytes = n,
                    sequence_number,
                    "sent encrypted data frame"
                );
            }
            udp_result = transport.recv_from(&mut udp_buf) => {
                let (n, peer) = udp_result?;
                if peer != session.peer_addr {
                    tracing::warn!(%peer, expected = %session.peer_addr, "dropping packet from unexpected peer");
                    continue;
                }

                let frame = match decode_frame(&udp_buf[..n]) {
                    Ok(frame) => frame,
                    Err(err) => {
                        tracing::warn!(error = %err, "dropping invalid frame");
                        continue;
                    }
                };

                if frame.header.packet_type != PacketType::Data {
                    tracing::debug!(packet_type = ?frame.header.packet_type, "ignoring non-data frame");
                    continue;
                }

                if frame.header.session_id != session.session_id {
                    tracing::warn!(
                        got = frame.header.session_id,
                        expected = session.session_id,
                        "dropping frame for wrong session"
                    );
                    continue;
                }

                if !session.is_fresh_recv_sequence(frame.header.sequence_number) {
                    tracing::warn!(
                        sequence_number = frame.header.sequence_number,
                        highest = session.recv_highest_seq,
                        "dropping replayed or out-of-order frame"
                    );
                    continue;
                }

                let packet = match decrypt_data_frame(&frame, &session.recv_key, session.recv_nonce_prefix) {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::warn!(error = %err, "dropping undecryptable data frame");
                        continue;
                    }
                };

                session.commit_recv_sequence(frame.header.sequence_number);
                tun.write_packet(&packet).await?;

                tracing::debug!(
                    bytes = packet.len(),
                    sequence_number = frame.header.sequence_number,
                    "wrote decrypted packet to TUN"
                );
            }
        }
    }
}
