use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "rust_network")]
#[command(about = "Educational PSK-authenticated VPN over UDP")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Server(ServerArgs),
    Client(ClientArgs),
}

#[derive(Debug, Args)]
pub struct ServerArgs {
    #[arg(long, default_value = "0.0.0.0:7000")]
    pub listen: SocketAddr,

    #[arg(long)]
    pub psk_file: PathBuf,

    #[arg(long, default_value = "tun0")]
    pub tun_name: String,

    #[arg(long, default_value = "10.8.0.1/24")]
    pub tun_ip: String,

    #[arg(long, default_value = "10.8.0.2")]
    pub peer_ip: String,

    #[arg(long, default_value = "1300")]
    pub mtu: u16,

    #[arg(long, default_value = "eth0")]
    pub out_iface: String,
}

#[derive(Debug, Args)]
pub struct ClientArgs {
    #[arg(long)]
    pub server: SocketAddr,

    #[arg(long)]
    pub psk_file: PathBuf,

    #[arg(long, default_value = "tun0")]
    pub tun_name: String,

    #[arg(long, default_value = "10.8.0.2/24")]
    pub tun_ip: String,

    #[arg(long, default_value = "10.8.0.1")]
    pub server_tun_ip: String,

    #[arg(long, default_value = "1300")]
    pub mtu: u16,
}
