//! Phantom Linux agent entry point.

use anyhow::Result;
use phantom::{PhantomAgent, PhantomConfig};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("phantom agent starting");
    let mut agent = PhantomAgent::new(PhantomConfig::default())?;
    agent.run().await?;
    Ok(())
}
