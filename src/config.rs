use std::net::SocketAddr;
use std::path::PathBuf;

use crate::cli::{ClientArgs, ServerArgs};

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub ip_cidr: String,
    pub mtu: u16,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub psk_file: PathBuf,
    pub tun: TunConfig,
    pub peer_ip: String,
    pub out_iface: String,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server: SocketAddr,
    pub psk_file: PathBuf,
    pub tun: TunConfig,
    pub server_tun_ip: String,
}

impl From<ServerArgs> for ServerConfig {
    fn from(args: ServerArgs) -> Self {
        Self {
            listen: args.listen,
            psk_file: args.psk_file,
            tun: TunConfig {
                name: args.tun_name,
                ip_cidr: args.tun_ip,
                mtu: args.mtu,
            },
            peer_ip: args.peer_ip,
            out_iface: args.out_iface,
        }
    }
}

impl From<ClientArgs> for ClientConfig {
    fn from(args: ClientArgs) -> Self {
        Self {
            server: args.server,
            psk_file: args.psk_file,
            tun: TunConfig {
                name: args.tun_name,
                ip_cidr: args.tun_ip,
                mtu: args.mtu,
            },
            server_tun_ip: args.server_tun_ip,
        }
    }
}
