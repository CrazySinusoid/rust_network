use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::time::timeout;

use crate::config::ClientConfig;
use crate::crypto::keys::derive_session_keys;
use crate::crypto::psk::load_psk;
use crate::protocol::{
    decode_frame, decode_server_hello, encode_client_hello, encode_frame,
    encrypt_auth_confirm_frame, AuthConfirm, ClientHello, Frame, FrameHeader, PacketType,
    AUTH_METHOD_PSK,
};
use crate::transport::udp::UdpTransport;
use crate::tun::linux;
use crate::tunnel::{self, TunnelSession};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_UDP_FRAME_LEN: usize = 2048;

pub async fn run(config: ClientConfig) -> Result<()> {
    let tun_config = config.tun.clone();
    let (transport, session) = establish_session(config).await?;

    tracing::info!(
        tun = %tun_config.name,
        ip = %tun_config.ip_cidr,
        mtu = session.selected_mtu,
        "creating client TUN device"
    );
    let tun = linux::create(&tun_config.name, &tun_config.ip_cidr, session.selected_mtu).await?;

    tunnel::run(tun, transport, session).await
}

pub(crate) async fn establish_session(
    config: ClientConfig,
) -> Result<(UdpTransport, TunnelSession)> {
    let psk = load_psk(&config.psk_file)?;
    let bind_addr = client_bind_addr(config.server);
    let transport = UdpTransport::bind(bind_addr).await?;

    tracing::info!(
        local = %transport.local_addr()?,
        server = %config.server,
        "client UDP socket is ready"
    );

    let client_hello = build_client_hello(config.tun.mtu);
    let client_frame = Frame::new(
        FrameHeader::new(PacketType::ClientHello, 0, 0, 0),
        encode_client_hello(&client_hello),
    );

    transport
        .send_to(&encode_frame(&client_frame), config.server)
        .await?;
    tracing::info!("ClientHello sent");

    let mut buf = [0u8; MAX_UDP_FRAME_LEN];
    let (server_frame, peer) = recv_frame(&transport, &mut buf).await?;

    if peer != config.server {
        bail!("received ServerHello from unexpected peer: {peer}");
    }

    if server_frame.header.packet_type != PacketType::ServerHello {
        bail!(
            "expected ServerHello, got {:?}",
            server_frame.header.packet_type
        );
    }

    if server_frame.header.session_id == 0 {
        bail!("server returned zero session id");
    }

    let server_hello = decode_server_hello(&server_frame.payload)?;
    let keys = derive_session_keys(
        &psk,
        &client_hello.client_random,
        &server_hello.server_random,
    )?;

    let auth = AuthConfirm {
        client_instance_id: client_hello.client_instance_id,
        session_id: server_frame.header.session_id,
        client_random: client_hello.client_random,
        server_random: server_hello.server_random,
    };

    let auth_frame =
        encrypt_auth_confirm_frame(&auth, &keys.handshake_key, keys.handshake_nonce_prefix, 1)?;

    transport
        .send_to(&encode_frame(&auth_frame), config.server)
        .await?;

    tracing::info!(
        session_id = server_frame.header.session_id,
        selected_mtu = server_hello.selected_mtu,
        "handshake completed"
    );

    let session = TunnelSession::client(
        server_frame.header.session_id,
        config.server,
        keys,
        server_hello.selected_mtu,
    );

    Ok((transport, session))
}

fn client_bind_addr(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

fn build_client_hello(proposed_mtu: u16) -> ClientHello {
    let mut client_random = [0u8; 32];
    OsRng.fill_bytes(&mut client_random);

    ClientHello {
        client_random,
        client_time_unix_ms: crate::util::time::unix_time_ms(),
        client_instance_id: OsRng.next_u64(),
        proposed_mtu,
        auth_method: AUTH_METHOD_PSK,
    }
}

async fn recv_frame(transport: &UdpTransport, buf: &mut [u8]) -> Result<(Frame, SocketAddr)> {
    let (n, peer) = timeout(HANDSHAKE_TIMEOUT, transport.recv_from(buf))
        .await
        .context("handshake timed out")??;
    let frame = decode_frame(&buf[..n])?;

    Ok((frame, peer))
}
