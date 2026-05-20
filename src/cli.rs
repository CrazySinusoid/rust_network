use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::routing::linux::{DEFAULT_TUN_NAME, DEFAULT_VPN_SUBNET};

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
    Routes(RoutesArgs),
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

#[derive(Debug, Args)]
pub struct RoutesArgs {
    #[command(subcommand)]
    pub command: RoutesCommand,
}

#[derive(Debug, Subcommand)]
pub enum RoutesCommand {
    Server(ServerRoutesArgs),
    Client(ClientRoutesArgs),
}

#[derive(Debug, Args)]
pub struct ServerRoutesArgs {
    #[arg(long, default_value = DEFAULT_VPN_SUBNET)]
    pub vpn_subnet: String,

    #[arg(long, default_value = DEFAULT_TUN_NAME)]
    pub tun_name: String,

    #[arg(long)]
    pub out_iface: String,

    #[arg(long)]
    pub rollback: bool,
}

#[derive(Debug, Args)]
pub struct ClientRoutesArgs {
    #[arg(long)]
    pub server_ip: String,

    #[arg(long, required_unless_present = "rollback")]
    pub old_gateway: Option<String>,

    #[arg(long, default_value = DEFAULT_TUN_NAME)]
    pub tun_name: String,

    #[arg(long)]
    pub rollback: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_routes_command() {
        let cli = Cli::parse_from(["rust_network", "routes", "server", "--out-iface", "eth0"]);

        match cli.command {
            Command::Routes(RoutesArgs {
                command: RoutesCommand::Server(args),
            }) => {
                assert_eq!(args.vpn_subnet, "10.8.0.0/24");
                assert_eq!(args.tun_name, "tun0");
                assert_eq!(args.out_iface, "eth0");
                assert!(!args.rollback);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_client_routes_rollback_command() {
        let cli = Cli::parse_from([
            "rust_network",
            "routes",
            "client",
            "--server-ip",
            "203.0.113.10",
            "--rollback",
        ]);

        match cli.command {
            Command::Routes(RoutesArgs {
                command: RoutesCommand::Client(args),
            }) => {
                assert_eq!(args.server_ip, "203.0.113.10");
                assert_eq!(args.old_gateway, None);
                assert_eq!(args.tun_name, "tun0");
                assert!(args.rollback);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
