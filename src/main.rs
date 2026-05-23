use anyhow::Result;
use clap::Parser;
use rust_network::cli::{Cli, Command};
use rust_network::{client, routes, server};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match cli.command {
        Command::Server(args) => server::run(args.into()).await,
        Command::Client(args) => client::run(args.into()).await,
        Command::Routes(args) => routes::print(args.command),
    }
}

fn init_logging(verbosity: u8) {
    let filter = if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::from_default_env()
    } else {
        match verbosity {
            0 => EnvFilter::new("warn,rust_network=info"),
            1 => EnvFilter::new("warn,rust_network=debug"),
            _ => EnvFilter::new("warn,rust_network=trace"),
        }
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();
}
