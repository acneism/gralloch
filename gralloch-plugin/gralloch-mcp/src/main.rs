mod capa;
mod casedir;
mod deobf;
mod dynamic;
mod hashes;
mod report;
mod server;
mod triage;
mod verify;
mod yara;

use anyhow::Result;
use rmcp::{transport::stdio, ServiceExt};

use crate::server::Gralloch;

#[tokio::main]
async fn main() -> Result<()> {

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("gralloch-mcp {} starting (stdio)", env!("CARGO_PKG_VERSION"));

    let service = Gralloch::new().serve(stdio()).await.inspect_err(|e| {
        tracing::error!("failed to start MCP service: {e:?}");
    })?;
    service.waiting().await?;
    Ok(())
}
