//! Background liveness monitoring for agent inactivity timeouts.

mod config;
mod monitor;
mod sweep;

pub use monitor::{AgentLivenessMonitor, spawn_agent_liveness_monitor};

#[cfg(test)]
mod tests;
