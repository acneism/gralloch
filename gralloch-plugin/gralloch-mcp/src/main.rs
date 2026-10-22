//! gralloch-mcp: native MCP server for the gralloch reverse-engineering pipeline.
//!
//! Tools exposed over stdio:
//!   - case_new : hash a sample, store it read-only without an executable
//!                extension, write case.json + notes.md. Never executes it.
//!   - triage   : parse the stored PE (format, arch, sections+entropy, imports,
//!                overlay, heuristic packer check) and write artifacts/triage.json.
//!
//! Isolation note: this server only ever READS the sample bytes. It contains no
//! code path that launches a process from the sample (see tz-re-pipeline.md 4).

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
    // Logs go to STDERR. stdout carries the MCP protocol and must stay clean.
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
