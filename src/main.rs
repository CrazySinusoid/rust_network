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

use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    match Cli::parse().command {
        Command::Server(args) => server::run(args.into()).await,
        Command::Client(args) => client::run(args.into()).await,
    }
}
