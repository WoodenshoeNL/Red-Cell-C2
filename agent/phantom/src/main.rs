//! Phantom Linux agent entry point.

use anyhow::Result;
use phantom::{PhantomAgent, PhantomConfig};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|argument| matches!(argument.as_str(), "-h" | "--help")) {
        println!("{}", PhantomConfig::usage());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = PhantomConfig::from_sources(std::env::args_os(), std::env::vars_os())?;
    info!("phantom agent starting");
    let mut agent = PhantomAgent::new(config)?;
    agent.run().await?;
    Ok(())
}
