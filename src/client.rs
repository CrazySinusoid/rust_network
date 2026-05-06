use anyhow::Result;

use crate::config::ClientConfig;

pub async fn run(config: ClientConfig) -> Result<()> {
    tracing::info!(server = %config.server, "client mode is scaffolded");
    Ok(())
}
