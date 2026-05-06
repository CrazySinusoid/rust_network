use anyhow::Result;

use crate::config::ServerConfig;

pub async fn run(config: ServerConfig) -> Result<()> {
    tracing::info!(listen = %config.listen, "server mode is scaffolded");
    Ok(())
}
