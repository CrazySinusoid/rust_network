use std::net::SocketAddr;

use anyhow::Result;
use tokio::net::UdpSocket;

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(addr).await?,
        })
    }

    pub async fn send_to(&self, frame: &[u8], peer: SocketAddr) -> Result<usize> {
        Ok(self.socket.send_to(frame, peer).await?)
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Ok(self.socket.recv_from(buf).await?)
    }
}
