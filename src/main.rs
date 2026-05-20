#![allow(dead_code, unused_imports)]

mod cli;
mod client;
mod config;
mod crypto;
mod error;
mod packet;
mod protocol;
mod routing;
mod server;
mod transport;
mod tun;
mod tunnel;
mod util;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command, RoutesCommand};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    match Cli::parse().command {
        Command::Server(args) => server::run(args.into()).await,
        Command::Client(args) => client::run(args.into()).await,
        Command::Routes(args) => {
            print_routes(args.command);
            Ok(())
        }
    }
}

fn print_routes(command: RoutesCommand) {
    let commands = match command {
        RoutesCommand::Server(args) => {
            if args.rollback {
                routing::commands::server_gateway_rollback_commands(
                    &args.vpn_subnet,
                    &args.tun_name,
                    &args.out_iface,
                )
            } else {
                routing::commands::server_gateway_commands(
                    &args.vpn_subnet,
                    &args.tun_name,
                    &args.out_iface,
                )
            }
        }
        RoutesCommand::Client(args) => {
            if args.rollback {
                routing::commands::client_full_tunnel_rollback_commands(
                    &args.server_ip,
                    &args.tun_name,
                )
            } else {
                let old_gateway = args
                    .old_gateway
                    .expect("clap requires --old-gateway unless --rollback is set");
                routing::commands::client_full_tunnel_commands(
                    &args.server_ip,
                    &old_gateway,
                    &args.tun_name,
                )
            }
        }
    };

    for command in commands {
        println!("{command}");
    }
}
