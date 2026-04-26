mod agent_id;
mod backoff;
mod bootstrap;
mod cli;
mod client;
mod commands;
mod config;
mod defaults;
mod dispatch;
mod error;
mod output;
mod tls;
mod util;

pub(crate) use agent_id::AgentId;
pub(crate) use cli::{
    AgentCommands, AuditCommands, ExportFormat, ListenerCommands, LootCommands, OperatorCommands,
    PayloadCommands,
};

fn main() {
    bootstrap::run();
}

#[cfg(test)]
mod tests;
