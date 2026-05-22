use std::time::Duration;

use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::time::timeout;

use crate::config::ServerConfig;
use crate::crypto::keys::derive_session_keys;
use crate::crypto::psk::load_psk;
use crate::error::VpnError;
use crate::protocol::handshake::MIN_MTU;
use crate::protocol::{
    decode_client_hello, decode_frame, decrypt_auth_confirm_frame, encode_frame,
    encode_server_hello, Frame, FrameHeader, PacketType, ServerHello, AUTH_METHOD_PSK,
};
use crate::transport::udp::UdpTransport;
use crate::tun::linux;
use crate::tunnel::{self, TunnelSession};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_UDP_FRAME_LEN: usize = 2048;

pub async fn run(config: ServerConfig) -> Result<()> {
    let tun_config = config.tun.clone();
    let transport = UdpTransport::bind(config.listen).await?;
    let mut tun = None;

    tracing::info!(
        mode = "server",
        listen = %transport.local_addr()?,
        psk_file = %config.psk_file.display(),
        tun_name = %config.tun.name,
        tun_ip = %config.tun.ip_cidr,
        peer_ip = %config.peer_ip,
        mtu = config.tun.mtu,
        out_iface = %config.out_iface,
        "server is listening"
    );

    loop {
        let session = establish_session_with_transport(&config, &transport).await?;

        if tun.is_none() {
            tracing::info!(
                tun = %tun_config.name,
                ip = %tun_config.ip_cidr,
                mtu = session.selected_mtu,
                "creating server TUN device"
            );
            tun = Some(
                linux::create(&tun_config.name, &tun_config.ip_cidr, session.selected_mtu).await?,
            );
        }

        let result = tunnel::run(
            tun.as_mut().expect("TUN is initialized"),
            &transport,
            session,
        )
        .await;
        if is_session_timeout(&result) {
            tracing::warn!("server session timed out; waiting for a new ClientHello");
            continue;
        }

        return result;
    }
}

pub(crate) async fn establish_session_with_transport(
    config: &ServerConfig,
    transport: &UdpTransport,
) -> Result<TunnelSession> {
    let psk = load_psk(&config.psk_file)?;

    let mut buf = [0u8; MAX_UDP_FRAME_LEN];
    let (client_frame, peer) = recv_frame(&transport, &mut buf).await?;

    if client_frame.header.packet_type != PacketType::ClientHello {
        bail!(
            "expected ClientHello, got {:?}",
            client_frame.header.packet_type
        );
    }

    if client_frame.header.session_id != 0 || client_frame.header.sequence_number != 0 {
        bail!("ClientHello must use zero session id and sequence");
    }

    let client_hello = decode_client_hello(&client_frame.payload)?;
    let mut server_random = [0u8; 32];
    OsRng.fill_bytes(&mut server_random);

    let session_id = new_session_id();
    let selected_mtu = config.tun.mtu.min(client_hello.proposed_mtu);
    if selected_mtu < MIN_MTU {
        bail!("selected MTU is too small: {selected_mtu}");
    }

    let server_hello = ServerHello {
        server_random,
        server_time_unix_ms: crate::util::time::unix_time_ms(),
        selected_mtu,
        auth_method: AUTH_METHOD_PSK,
    };

    let server_frame = Frame::new(
        FrameHeader::new(PacketType::ServerHello, 0, session_id, 0),
        encode_server_hello(&server_hello),
    );

    transport
        .send_to(&encode_frame(&server_frame), peer)
        .await?;
    tracing::info!(%peer, session_id, "ServerHello sent");

    let keys = derive_session_keys(&psk, &client_hello.client_random, &server_random)?;
    let (auth_frame, auth_peer) = recv_frame(&transport, &mut buf).await?;

    if auth_peer != peer {
        bail!("received AuthConfirm from unexpected peer: {auth_peer}");
    }

    let auth = decrypt_auth_confirm_frame(
        &auth_frame,
        &keys.handshake_key,
        keys.handshake_nonce_prefix,
    )?;

    if auth.session_id != session_id {
        bail!("AuthConfirm session id mismatch");
    }

    if auth.client_instance_id != client_hello.client_instance_id {
        bail!("AuthConfirm client instance id mismatch");
    }

    if auth.client_random != client_hello.client_random {
        bail!("AuthConfirm client random mismatch");
    }

    if auth.server_random != server_random {
        bail!("AuthConfirm server random mismatch");
    }

    tracing::info!(%peer, session_id, selected_mtu, "client authenticated");

    let session = TunnelSession::server(session_id, peer, keys, selected_mtu);

    Ok(session)
}

fn new_session_id() -> u64 {
    loop {
        let session_id = OsRng.next_u64();
        if session_id != 0 {
            return session_id;
        }
    }
}

fn is_session_timeout(result: &Result<()>) -> bool {
    result
        .as_ref()
        .err()
        .and_then(|err| err.downcast_ref::<VpnError>())
        .is_some_and(|err| matches!(err, VpnError::SessionTimeout { .. }))
}

async fn recv_frame(
    transport: &UdpTransport,
    buf: &mut [u8],
) -> Result<(Frame, std::net::SocketAddr)> {
    let (n, peer) = timeout(HANDSHAKE_TIMEOUT, transport.recv_from(buf))
        .await
        .context("handshake timed out")??;
    let frame = decode_frame(&buf[..n])?;

    Ok((frame, peer))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::config::{ClientConfig, TunConfig};

    #[tokio::test]
    async fn udp_handshake_completes() {
        let psk_path = std::env::temp_dir().join(format!(
            "rust_network_psk_{}_{}.txt",
            std::process::id(),
            crate::util::time::unix_time_ms()
        ));
        fs::write(&psk_path, b"shared test psk").unwrap();

        let server_transport = UdpTransport::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let server_addr = server_transport.local_addr().unwrap();

        let server_config = ServerConfig {
            listen: server_addr,
            psk_file: psk_path.clone(),
            tun: TunConfig {
                name: "tun-test-server".to_owned(),
                ip_cidr: "10.8.0.1/24".to_owned(),
                mtu: 1300,
            },
            peer_ip: "10.8.0.2".to_owned(),
            out_iface: "eth0".to_owned(),
        };

        let client_config = ClientConfig {
            server: server_addr,
            psk_file: psk_path.clone(),
            tun: TunConfig {
                name: "tun-test-client".to_owned(),
                ip_cidr: "10.8.0.2/24".to_owned(),
                mtu: 1300,
            },
            server_tun_ip: "10.8.0.1".to_owned(),
        };

        let server_task = tokio::spawn(async move {
            establish_session_with_transport(&server_config, &server_transport).await
        });
        let client_result = crate::client::establish_session(&client_config).await;
        let server_result = server_task.await.unwrap();

        let _ = fs::remove_file(psk_path);

        let (_client_transport, client_session) = client_result.unwrap();
        let server_session = server_result.unwrap();

        assert_eq!(client_session.session_id, server_session.session_id);
        assert_eq!(client_session.peer_addr, server_addr);
        assert_eq!(server_session.selected_mtu, 1300);
    }
}
