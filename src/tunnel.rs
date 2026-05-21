use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::time::{interval_at, Instant as TokioInstant, MissedTickBehavior};

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::keys::{AeadKeyBytes, SessionKeys};
use crate::crypto::nonce::NoncePrefix;
use crate::error::VpnError;
use crate::protocol::{
    decode_frame, decrypt_data_frame, decrypt_keepalive_frame, encode_frame, encrypt_data_frame,
    encrypt_keepalive_frame, PacketType, HEADER_LEN,
};
use crate::transport::udp::UdpTransport;
use crate::tun::linux::TunDevice;

const EXTRA_FRAME_SPACE: usize = 64;
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

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
    pub last_seen: Instant,
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
            last_seen: Instant::now(),
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
            last_seen: Instant::now(),
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

    fn mark_seen(&mut self) {
        self.last_seen = Instant::now();
    }

    fn is_timed_out(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() >= timeout
    }
}

pub async fn run(
    tun: &mut TunDevice,
    transport: &UdpTransport,
    mut session: TunnelSession,
) -> Result<()> {
    let mut tun_buf = vec![0u8; session.selected_mtu as usize];
    let mut udp_buf =
        vec![0u8; session.selected_mtu as usize + HEADER_LEN + AEAD_TAG_LEN + EXTRA_FRAME_SPACE];
    let mut keepalive = interval_at(TokioInstant::now() + KEEPALIVE_INTERVAL, KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);

    tracing::info!(
        tun = tun.name(),
        peer = %session.peer_addr,
        session_id = session.session_id,
        mtu = session.selected_mtu,
        "encrypted tunnel loop started"
    );

    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                if session.is_timed_out(SESSION_TIMEOUT) {
                    return Err(VpnError::SessionTimeout {
                        session_id: session.session_id,
                        timeout_secs: SESSION_TIMEOUT.as_secs(),
                    }.into());
                }

                let sequence_number = session.next_send_sequence();
                let frame = encrypt_keepalive_frame(
                    session.session_id,
                    sequence_number,
                    &session.send_key,
                    session.send_nonce_prefix,
                    crate::util::time::unix_time_ms(),
                )?;
                let encoded = encode_frame(&frame);
                transport.send_to(&encoded, session.peer_addr).await?;

                tracing::debug!(
                    sequence_number,
                    "sent encrypted keepalive frame"
                );
            }
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

                if frame.header.packet_type != PacketType::Data && frame.header.packet_type != PacketType::Keepalive {
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

                match frame.header.packet_type {
                    PacketType::Data => {
                        let packet = match decrypt_data_frame(&frame, &session.recv_key, session.recv_nonce_prefix) {
                            Ok(packet) => packet,
                            Err(err) => {
                                tracing::warn!(error = %err, "dropping undecryptable data frame");
                                continue;
                            }
                        };

                        session.commit_recv_sequence(frame.header.sequence_number);
                        session.mark_seen();
                        tun.write_packet(&packet).await?;

                        tracing::debug!(
                            bytes = packet.len(),
                            sequence_number = frame.header.sequence_number,
                            "wrote decrypted packet to TUN"
                        );
                    }
                    PacketType::Keepalive => {
                        let peer_time_ms = match decrypt_keepalive_frame(&frame, &session.recv_key, session.recv_nonce_prefix) {
                            Ok(peer_time_ms) => peer_time_ms,
                            Err(err) => {
                                tracing::warn!(error = %err, "dropping undecryptable keepalive frame");
                                continue;
                            }
                        };

                        session.commit_recv_sequence(frame.header.sequence_number);
                        session.mark_seen();

                        tracing::debug!(
                            sequence_number = frame.header.sequence_number,
                            peer_time_ms,
                            "received encrypted keepalive frame"
                        );
                    }
                    _ => unreachable!("packet type was filtered before decrypt"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> SessionKeys {
        SessionKeys {
            handshake_key: [0x01; 32],
            client_to_server_key: [0x02; 32],
            server_to_client_key: [0x03; 32],
            handshake_nonce_prefix: [1, 1, 1, 1],
            client_to_server_nonce_prefix: [2, 2, 2, 2],
            server_to_client_nonce_prefix: [3, 3, 3, 3],
        }
    }

    #[test]
    fn session_sequence_increments() {
        let mut session =
            TunnelSession::client(42, "127.0.0.1:7000".parse().unwrap(), keys(), 1300);

        assert_eq!(session.next_send_sequence(), 1);
        assert_eq!(session.next_send_sequence(), 2);
    }

    #[test]
    fn session_timeout_uses_last_seen() {
        let mut session =
            TunnelSession::client(42, "127.0.0.1:7000".parse().unwrap(), keys(), 1300);
        session.last_seen = Instant::now() - SESSION_TIMEOUT - Duration::from_secs(1);

        assert!(session.is_timed_out(SESSION_TIMEOUT));

        session.mark_seen();
        assert!(!session.is_timed_out(SESSION_TIMEOUT));
    }
}
