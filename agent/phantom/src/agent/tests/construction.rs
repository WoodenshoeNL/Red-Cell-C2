use std::error::Error;

use super::super::PhantomAgent;
use crate::config::PhantomConfig;

#[test]
fn agent_creation_succeeds() -> Result<(), Box<dyn Error>> {
    let agent = PhantomAgent::new(PhantomConfig::default())?;
    assert_ne!(agent.agent_id(), 0);
    Ok(())
}

#[test]
fn callback_seq_starts_at_one() -> Result<(), Box<dyn Error>> {
    let agent = PhantomAgent::new(PhantomConfig::default())?;
    assert_eq!(agent.callback_seq(), 1);
    Ok(())
}
